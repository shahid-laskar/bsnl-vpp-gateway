"""Fail-closed, idempotent subscriber lifecycle (control-plane state only).

Each operation runs in one store transaction: state change, idempotency record
and audit event commit together or not at all.
"""
from __future__ import annotations

import ipaddress
import json
import re
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from .contract import session_key_for
from .store import DesiredStateStore, StoreTransaction, request_hash

MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", re.IGNORECASE)
ACTIVE_STATE = "authenticated"
INACTIVE_STATES = frozenset({"deactivated", "expired"})
SYSTEM_ACTOR = "controller"


class StaleEventError(ValueError):
    """An event that would undo a newer decision (e.g. activation after logout)."""


@dataclass(frozen=True)
class LifecycleResult:
    operation_id: str
    idempotency_key: str
    gateway_revision: int
    changed: bool
    authorized: bool
    session_key: str
    reason: str


class SubscriberLifecycle:
    def __init__(self, store: DesiredStateStore, audit_path: Any = None) -> None:
        # audit_path is kept for call compatibility; the store owns auditing.
        self.store = store
        self._lock = threading.RLock()

    # Public operations -------------------------------------------------------------------
    def activate(self, subscriber: dict[str, Any], *, idempotency_key: str, operation_id: str, now: datetime | None = None, actor: str = SYSTEM_ACTOR) -> LifecycleResult:
        self._validate(subscriber)
        now = now or datetime.now(timezone.utc)
        fingerprint = request_hash({"operation": "activate", "subscriber": subscriber})
        with self._lock, self.store.transaction() as txn:
            replay = self._replay(txn, idempotency_key, fingerprint, subscriber["session_key"], operation_id, actor)
            if replay is not None:
                return replay
            expiry = parse_expiry(subscriber.get("valid_until"))
            if expiry is None or expiry <= now:
                raise ValueError("authenticated subscriber requires a future valid_until")
            state = txn.read() or {}
            self._validate_tenant(state, subscriber["tenant_key"], subscriber["private_ipv4"])
            items = state.setdefault("subscribers", [])
            existing = next((x for x in items if x.get("session_key") == subscriber["session_key"]), None)
            if (existing is not None and existing.get("state") in INACTIVE_STATES
                    and existing.get("session_id") and existing.get("session_id") == subscriber.get("session_id")):
                # A portal session id is used for exactly one login. If it was
                # already ended, this activation is late or replayed.
                raise StaleEventError("session already ended; a new login must use a new session_id")
            if existing is not None and existing.get("state") == ACTIVE_STATE and all(existing.get(k) == v for k, v in subscriber.items()):
                return self._finish(txn, state, subscriber["session_key"], idempotency_key, operation_id, False, True, "already_active", fingerprint, actor, "activate")
            value = {**subscriber, "state": ACTIVE_STATE, "activated_at": now.isoformat()}
            if existing is None:
                items.append(value)
            else:
                existing.clear()
                existing.update(value)
            self._bump(txn, state)
            return self._finish(txn, state, value["session_key"], idempotency_key, operation_id, True, True, "activated", fingerprint, actor, "activate")

    def deactivate(self, session_key: str, *, idempotency_key: str, operation_id: str, reason: str = "portal_deactivation", actor: str = SYSTEM_ACTOR) -> LifecycleResult:
        if not session_key:
            raise ValueError("session_key is required")
        fingerprint = request_hash({"operation": "deactivate", "session_key": session_key, "reason": reason})
        with self._lock, self.store.transaction() as txn:
            replay = self._replay(txn, idempotency_key, fingerprint, session_key, operation_id, actor)
            if replay is not None:
                return replay
            state = txn.read() or {}
            return self._deactivate_in(txn, state, session_key, idempotency_key, operation_id, reason, fingerprint, actor)

    def expire(self, *, now: datetime | None = None, operation_id: str = "expiry-reconciler") -> list[LifecycleResult]:
        """Deactivate every authenticated subscriber whose valid_until has passed."""
        now = now or datetime.now(timezone.utc)
        results: list[LifecycleResult] = []
        with self._lock, self.store.transaction() as txn:
            state = txn.read() or {}
            for item in list(state.get("subscribers", [])):
                expiry = parse_expiry(item.get("valid_until"))
                if item.get("state") == ACTIVE_STATE and expiry is not None and expiry <= now:
                    key = f"expire:{item['session_key']}:{expiry.isoformat()}"
                    fingerprint = request_hash({"operation": "deactivate", "session_key": item["session_key"], "reason": "expired"})
                    if txn.get_idempotency(key) is None:
                        results.append(self._deactivate_in(txn, state, item["session_key"], key, operation_id, "expired", fingerprint, SYSTEM_ACTOR))
        return results

    def deactivate_tenant_subscribers(self, txn: StoreTransaction, state: dict[str, Any], tenant_keys: set[str], reason: str) -> list[LifecycleResult]:
        """Used by topology merge when a tenant is removed or disabled."""
        results = []
        for item in list(state.get("subscribers", [])):
            if item.get("tenant_key") in tenant_keys and item.get("state") == ACTIVE_STATE:
                key = f"{reason}:{item['session_key']}:{state.get('gateway_revision', 0)}"
                fingerprint = request_hash({"operation": "deactivate", "session_key": item["session_key"], "reason": reason})
                results.append(self._deactivate_in(txn, state, item["session_key"], key, "topology-merge", reason, fingerprint, SYSTEM_ACTOR))
        return results

    # Internals ---------------------------------------------------------------------------
    def _deactivate_in(self, txn, state, session_key, idempotency_key, operation_id, reason, fingerprint, actor) -> LifecycleResult:
        items = state.setdefault("subscribers", [])
        existing = next((x for x in items if x.get("session_key") == session_key), None)
        if existing is None:
            return self._finish(txn, state, session_key, idempotency_key, operation_id, False, False, "not_found", fingerprint, actor, "deactivate")
        if existing.get("state") in INACTIVE_STATES:
            return self._finish(txn, state, session_key, idempotency_key, operation_id, False, False, "already_inactive", fingerprint, actor, "deactivate")
        existing["state"] = "expired" if reason == "expired" else "deactivated"
        existing["valid_until"] = None
        existing["ended_at"] = datetime.now(timezone.utc).isoformat()
        self._bump(txn, state)
        return self._finish(txn, state, session_key, idempotency_key, operation_id, True, False, reason, fingerprint, actor, "deactivate")

    @staticmethod
    def _bump(txn: StoreTransaction, state: dict[str, Any]) -> None:
        state["gateway_revision"] = int(state.get("gateway_revision", 0)) + 1
        txn.write(state)

    @staticmethod
    def _finish(txn, state, session_key, idempotency_key, operation_id, changed, authorized, reason, fingerprint, actor, operation) -> LifecycleResult:
        result = LifecycleResult(operation_id, idempotency_key, int(state.get("gateway_revision", 0)), changed, authorized, session_key, reason)
        txn.put_idempotency(idempotency_key, fingerprint, asdict(result))
        txn.append_audit({**asdict(result), "event": f"subscriber.{operation}", "actor": actor})
        return result

    @staticmethod
    def _replay(txn, key, fingerprint, session_key, operation_id, actor) -> LifecycleResult | None:
        if not key:
            raise ValueError("idempotency_key is required")
        record = txn.get_idempotency(key)
        if record is None:
            return None
        if record["request_hash"] != fingerprint:
            raise ValueError("idempotency key was already used for a different request")
        saved = json.loads(record["result"])
        result = LifecycleResult(operation_id, key, saved["gateway_revision"], False, saved["authorized"], session_key, "idempotent_replay")
        txn.append_audit({**asdict(result), "event": "subscriber.replay", "actor": actor})
        return result

    @staticmethod
    def _validate(subscriber: dict[str, Any]) -> None:
        required = ("session_key", "tenant_key", "subscriber_id", "private_ipv4")
        missing = [key for key in required if not subscriber.get(key)]
        if missing:
            raise ValueError(f"missing subscriber fields: {', '.join(missing)}")
        ipaddress.ip_address(subscriber["private_ipv4"])
        if subscriber.get("mac") and not MAC_RE.fullmatch(subscriber["mac"]):
            raise ValueError("mac must be a colon-separated six-octet address")
        if subscriber["session_key"] != session_key_for(subscriber["tenant_key"], subscriber["private_ipv4"]):
            raise ValueError("session_key must equal tenant_key + '/' + private_ipv4")

    @staticmethod
    def _validate_tenant(state: dict[str, Any], tenant_key: str, private_ipv4: str) -> None:
        tenant = next((x for x in state.get("tenants", []) if x.get("tenant_key") == tenant_key and x.get("admin_state") == "enabled"), None)
        if tenant is None:
            raise ValueError("subscriber tenant is missing or disabled")
        try:
            gateway = ipaddress.ip_interface(tenant["gateway_ip"])
        except (KeyError, ValueError) as exc:
            raise ValueError("subscriber tenant has no valid gateway_ip") from exc
        address = ipaddress.ip_address(private_ipv4)
        if address not in gateway.network or address in (gateway.ip, gateway.network.network_address, gateway.network.broadcast_address):
            raise ValueError("private_ipv4 is not a usable host address in the tenant subnet")


def parse_expiry(value: Any) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
