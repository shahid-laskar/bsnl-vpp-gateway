"""SubscriberBinding history from DHCP leases (plan section 5.3, P5-T4/T6).

    SubscriberBinding = (TenantContext, private_ipv4, mac, lease, valid_from, valid_to)

Rows in the ``bindings`` table are append-only history: a binding is opened
when a lease for (tenant, IP, MAC) is first seen and closed (``valid_to`` set)
when the lease is released, expires, or the IP moves to another MAC. Renewals
only move ``lease_expire`` forward. Bindings are never deleted, so an IP can
be attributed "as of" any past time (IPDR enrichment, Phase 7).

A lease maps to a tenant through its Kea subnet id (``kea_subnet_id``), and
the address must lie in that tenant's subnet. Times are integer epoch seconds.
"""
from __future__ import annotations

import ipaddress
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from .host_services import HostServiceValidationError, kea_subnet_id
from .leases import Lease, LeaseSourceError
from .store import DesiredStateStore, StoreTransaction

LOG = logging.getLogger("bsnl_vpp.bindings")
ACTOR = "kea-lease-sync"

BINDING_COLUMNS = ("id", "tenant_key", "private_ipv4", "mac", "client_id", "hostname", "kea_subnet_id",
                   "valid_from", "valid_to", "lease_expire", "close_reason", "source")


def iso(epoch: int | None) -> str | None:
    return None if epoch is None else datetime.fromtimestamp(epoch, timezone.utc).isoformat()


def binding_view(row: dict[str, Any]) -> dict[str, Any]:
    """API representation (RFC 3339 times)."""
    return {
        "tenant_key": row["tenant_key"],
        "private_ipv4": row["private_ipv4"],
        "mac": row["mac"],
        "client_id": row["client_id"] or None,
        "hostname": row["hostname"] or None,
        "valid_from": iso(row["valid_from"]),
        "valid_to": iso(row["valid_to"]),
        "lease_expire": iso(row["lease_expire"]),
        "close_reason": row["close_reason"],
        "source": row["source"],
    }


def subnet_tenants(state: dict[str, Any]) -> dict[int, dict[str, Any]]:
    """Kea subnet id -> enabled tenant (same rule the Kea renderer uses)."""
    mapping: dict[int, dict[str, Any]] = {}
    for tenant in state.get("tenants") or []:
        if tenant.get("admin_state", "enabled") != "enabled":
            continue
        try:
            mapping[kea_subnet_id(tenant)] = tenant
        except HostServiceValidationError:
            LOG.error("tenant %s has an invalid kea_subnet_id; its leases are ignored", tenant.get("tenant_key"))
    return mapping


def _rows(txn: StoreTransaction, sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
    cursor = txn.connection.execute(sql, tuple(params))
    names = [d[0] for d in cursor.description]
    return [dict(zip(names, values)) for values in cursor.fetchall()]


def open_binding(txn: StoreTransaction, tenant_key: str, private_ipv4: str) -> dict[str, Any] | None:
    rows = _rows(txn, "SELECT * FROM bindings WHERE tenant_key=? AND private_ipv4=? AND valid_to IS NULL ORDER BY id DESC LIMIT 1", (tenant_key, private_ipv4))
    return rows[0] if rows else None


def open_bindings(store: DesiredStateStore) -> list[dict[str, Any]]:
    """Every open binding (valid_to IS NULL): input of MAC enforcement (ADR-016)."""
    with store.transaction() as txn:
        return _rows(txn, "SELECT tenant_key, private_ipv4, mac, valid_to FROM bindings WHERE valid_to IS NULL")


def binding_at(store: DesiredStateStore, tenant_key: str, private_ipv4: str, at: int) -> dict[str, Any] | None:
    """The binding valid at epoch ``at`` (valid_from <= at < valid_to), if any."""
    with store.transaction() as txn:
        rows = _rows(txn, "SELECT * FROM bindings WHERE tenant_key=? AND private_ipv4=? AND valid_from<=? AND (valid_to IS NULL OR valid_to>?) "
                          "ORDER BY valid_from DESC, id DESC LIMIT 1", (tenant_key, private_ipv4, at, at))
    return rows[0] if rows else None


@dataclass
class SyncResult:
    opened: int = 0
    closed: int = 0
    renewed: int = 0
    unmapped: int = 0
    out_of_subnet: int = 0
    open_latency_seconds: list[float] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        return {"opened": self.opened, "closed": self.closed, "renewed": self.renewed,
                "unmapped": self.unmapped, "out_of_subnet": self.out_of_subnet}


def sync_bindings(store: DesiredStateStore, leases: Iterable[Lease], now: int | None = None, source: str = "kea-memfile") -> SyncResult:
    """Reconcile the open bindings with the currently active leases (one transaction)."""
    now = int(time.time()) if now is None else int(now)
    result = SyncResult()
    with store.transaction() as txn:
        tenants = subnet_tenants(txn.read() or {})
        current: dict[tuple[str, str], Lease] = {}
        for lease in leases:
            if not lease.active_at(now):
                continue
            tenant = tenants.get(lease.subnet_id)
            if tenant is None:
                result.unmapped += 1
                continue
            try:
                in_subnet = ipaddress.ip_address(lease.address) in ipaddress.ip_interface(tenant["gateway_ip"]).network
            except (KeyError, ValueError):
                in_subnet = False
            if not in_subnet:
                result.out_of_subnet += 1
                continue
            current[(tenant["tenant_key"], lease.address)] = lease

        for row in _rows(txn, "SELECT * FROM bindings WHERE valid_to IS NULL"):
            key = (row["tenant_key"], row["private_ipv4"])
            lease = current.get(key)
            if lease is not None and lease.mac == row["mac"]:
                current.pop(key)
                if lease.expire != row["lease_expire"]:
                    txn.connection.execute("UPDATE bindings SET lease_expire=? WHERE id=?", (lease.expire, row["id"]))
                    result.renewed += 1
                continue
            if lease is None:
                # Lease vanished: it ran out (closed at its expiry) or was
                # released/deleted early (closed now).
                expired = row["lease_expire"] is not None and row["lease_expire"] <= now
                valid_to, reason = (row["lease_expire"], "lease_expired") if expired else (now, "lease_released")
            else:
                valid_to, reason = min(now, max(lease.cltt, row["valid_from"])), "mac_changed"
            valid_to = max(valid_to, row["valid_from"])
            txn.connection.execute("UPDATE bindings SET valid_to=?, close_reason=? WHERE id=?", (valid_to, reason, row["id"]))
            txn.append_audit({"event": "binding.closed", "actor": ACTOR, "tenant_key": row["tenant_key"], "private_ipv4": row["private_ipv4"],
                              "mac": row["mac"], "valid_to": iso(valid_to), "reason": reason})
            result.closed += 1

        for (tenant_key, address), lease in sorted(current.items()):
            previous = _rows(txn, "SELECT MAX(valid_to) AS last FROM bindings WHERE tenant_key=? AND private_ipv4=?", (tenant_key, address))[0]["last"]
            valid_from = min(now, lease.cltt)
            if previous is not None and valid_from < previous:
                valid_from = previous  # never overlap the binding that was just closed
            txn.connection.execute(
                "INSERT INTO bindings(tenant_key,private_ipv4,mac,client_id,hostname,kea_subnet_id,valid_from,valid_to,lease_expire,close_reason,source) "
                "VALUES(?,?,?,?,?,?,?,NULL,?,NULL,?)",
                (tenant_key, address, lease.mac, lease.client_id, lease.hostname, lease.subnet_id, valid_from, lease.expire, source))
            txn.append_audit({"event": "binding.opened", "actor": ACTOR, "tenant_key": tenant_key, "private_ipv4": address,
                              "mac": lease.mac, "valid_from": iso(valid_from), "lease_expire": iso(lease.expire)})
            result.opened += 1
            result.open_latency_seconds.append(max(0.0, float(now - lease.cltt)))
    return result


def check_activation_mac(txn: StoreTransaction, state: dict[str, Any], subscriber: dict[str, Any], actor: str) -> None:
    """Audit a portal-supplied MAC that differs from the DHCP binding (log-only).

    MACIP enforcement is Phase 6; until then every tenant behaves as
    ``mac_enforcement: log_only`` and the activation proceeds.
    """
    mac = (subscriber.get("mac") or "").lower()
    if not mac:
        return
    binding = open_binding(txn, subscriber["tenant_key"], subscriber["private_ipv4"])
    if binding is None or binding["mac"] == mac:
        return
    tenant = next((t for t in state.get("tenants", []) if t.get("tenant_key") == subscriber["tenant_key"]), {})
    txn.append_audit({"event": "subscriber.mac_mismatch", "actor": actor, "session_key": subscriber["session_key"],
                      "portal_mac": mac, "binding_mac": binding["mac"], "mac_enforcement": tenant.get("mac_enforcement", "log_only"),
                      "action": "logged"})


class LeaseWatcher:
    """Poll the lease source and keep bindings current (target p95 <= 2 s).

    A source error leaves bindings untouched and is logged once per distinct
    error, not on every tick.
    """

    def __init__(self, store: DesiredStateStore, source: Any, interval_seconds: float = 1.0,
                 on_change: Any = None) -> None:
        self.store, self.source, self.interval = store, source, interval_seconds
        # Called (in this thread) when a binding opened or closed, so MAC
        # enforcement follows leases within one poll instead of a reconcile tick.
        self.on_change = on_change
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_error: str | None = None
        self.last_result: SyncResult | None = None

    def run_once(self, now: float | None = None) -> SyncResult | None:
        now = time.time() if now is None else now
        try:
            leases = self.source.active(now)
            result = sync_bindings(self.store, leases, int(now))
        except (LeaseSourceError, OSError) as exc:
            error = f"{type(exc).__name__}: {exc}"
            if error != self.last_error:
                LOG.error("lease sync skipped, bindings kept: %s", error)
            self.last_error = error
            return None
        except Exception as exc:  # never kill the watcher thread
            self.last_error = f"{type(exc).__name__}: {exc}"
            LOG.exception("lease sync failed")
            return None
        if self.last_error is not None:
            LOG.info("lease sync recovered")
        self.last_error, self.last_result = None, result
        if result.opened or result.closed:
            LOG.info("lease sync: %s", result.summary())
            if self.on_change is not None:
                try:
                    self.on_change(result)
                except Exception:  # the reconciler retries on its next tick
                    LOG.exception("binding change hook failed")
        return result

    def start(self) -> None:
        def loop() -> None:
            self.run_once()
            while not self._stop.wait(self.interval):
                self.run_once()
        self._thread = threading.Thread(target=loop, name="bsnl-lease-watcher", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
