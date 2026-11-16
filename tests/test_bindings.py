"""P5-T4/T6: Kea lease -> SubscriberBinding history and the bindings API."""
import json
import threading
import time
from datetime import datetime, timezone
from http.client import HTTPConnection
from urllib.parse import urlencode

import pytest

from controller.api import SubscriberApiServer
from controller.bindings import LeaseWatcher, binding_at, sync_bindings
from controller.contract import _validator
from controller.leases import KeaMemfileLeaseSource, Lease, LeaseSourceError
from controller.store import DesiredStateStore
from controller.subscribers import SubscriberLifecycle

TENANT = "lab-vpp-01/host-vpp-access/0x8100/200/101"
OTHER = "lab-vpp-01/host-vpp-access/0x8100/200/102"
HEADER = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id"
MAC_A, MAC_B = "02:00:00:00:00:0a", "02:00:00:00:00:0b"
T0 = 1_800_000_000


def row(address, mac, expire, lifetime=300, subnet=101, state=0, hostname=""):
    return f"{address},{mac},01:{mac},{lifetime},{expire},{subnet},0,0,{hostname},{state},,0"


def lease(address="10.9.101.5", mac=MAC_A, expire=T0 + 300, lifetime=300, subnet=101, state=0):
    return Lease(address, mac, "", lifetime, expire, subnet, "", state)


@pytest.fixture
def store(tmp_path):
    s = DesiredStateStore(tmp_path / "state.sqlite3")
    s.write({"schema_version": 2, "gateway_revision": 1, "subscribers": [], "tenants": [
        {"tenant_key": TENANT, "admin_state": "enabled", "gateway_ip": "10.9.101.1/24", "kea_subnet_id": 101, "mac_enforcement": "log_only"},
        {"tenant_key": OTHER, "admin_state": "disabled", "gateway_ip": "10.9.102.1/24", "kea_subnet_id": 102},
    ]})
    return s


def all_bindings(store):
    with store.transaction() as txn:
        cur = txn.connection.execute("SELECT private_ipv4, mac, valid_from, valid_to, close_reason, lease_expire FROM bindings ORDER BY id")
        return cur.fetchall()


# --- Kea memfile reader ------------------------------------------------------------------
def test_memfile_last_row_wins_and_zero_lifetime_deletes(tmp_path):
    f = tmp_path / "kea-leases4.csv"
    f.write_text("\n".join([HEADER, row("10.9.101.5", MAC_A, T0 + 300), row("10.9.101.6", MAC_B, T0 + 300),
                            row("10.9.101.5", MAC_A, T0 + 600), row("10.9.101.6", MAC_B, T0 + 300, lifetime=0),
                            "garbage,row", ""]))
    current = KeaMemfileLeaseSource(f).current()
    assert set(current) == {"10.9.101.5"}
    assert current["10.9.101.5"].expire == T0 + 600 and current["10.9.101.5"].cltt == T0 + 300


def test_memfile_follows_kea_lfc_load_order(tmp_path):
    f = tmp_path / "kea-leases4.csv"
    (tmp_path / "kea-leases4.csv.2").write_text("\n".join([HEADER, row("10.9.101.5", MAC_A, T0 + 100)]))
    (tmp_path / "kea-leases4.csv.1").write_text("\n".join([HEADER, row("10.9.101.5", MAC_A, T0 + 200)]))
    f.write_text("\n".join([HEADER, row("10.9.101.7", MAC_B, T0 + 300)]))
    current = KeaMemfileLeaseSource(f).current()
    assert current["10.9.101.5"].expire == T0 + 200 and "10.9.101.7" in current
    # After LFC finishes: .completed replaces .2/.1 (which are stale and ignored).
    (tmp_path / "kea-leases4.csv.completed").write_text("\n".join([HEADER, row("10.9.101.8", MAC_A, T0 + 400)]))
    assert set(KeaMemfileLeaseSource(f).current()) == {"10.9.101.7", "10.9.101.8"}


def test_active_excludes_expired_declined_and_macless(tmp_path):
    f = tmp_path / "kea-leases4.csv"
    f.write_text("\n".join([HEADER, row("10.9.101.5", MAC_A, T0 + 300), row("10.9.101.6", MAC_B, T0 - 1),
                            row("10.9.101.7", MAC_B, T0 + 300, state=1), row("10.9.101.8", "", T0 + 300)]))
    assert [l.address for l in KeaMemfileLeaseSource(f).active(T0)] == ["10.9.101.5"]


def test_missing_lease_file_is_an_error_not_an_empty_set(tmp_path):
    with pytest.raises(LeaseSourceError):
        KeaMemfileLeaseSource(tmp_path / "absent.csv").active(T0)


# --- binding history ---------------------------------------------------------------------
def test_open_renew_release_history(store):
    assert sync_bindings(store, [lease()], T0).opened == 1
    assert sync_bindings(store, [lease()], T0 + 1).summary()["renewed"] == 0          # unchanged: no write
    assert sync_bindings(store, [lease(expire=T0 + 450)], T0 + 150).renewed == 1    # renewal moves expiry only
    assert sync_bindings(store, [], T0 + 200).closed == 1                            # released early
    assert all_bindings(store) == [("10.9.101.5", MAC_A, T0, T0 + 200, "lease_released", T0 + 450)]


def test_lease_running_out_closes_at_its_expiry_not_at_detection(store):
    sync_bindings(store, [lease(expire=T0 + 300)], T0)
    sync_bindings(store, [], T0 + 900)   # controller was down past the expiry
    assert all_bindings(store)[0][3:5] == (T0 + 300, "lease_expired")


def test_ip_moving_to_another_mac_closes_and_opens_without_overlap(store):
    sync_bindings(store, [lease(mac=MAC_A, expire=T0 + 300)], T0)
    sync_bindings(store, [lease(mac=MAC_B, expire=T0 + 400 + 300)], T0 + 410)
    (_, a, a_from, a_to, a_reason, _), (_, b, b_from, b_to, _, _) = all_bindings(store)
    assert (a, a_reason, b, b_to) == (MAC_A, "mac_changed", MAC_B, None)
    assert a_from == T0 and a_to == T0 + 400 == b_from
    at = lambda t: (binding_at(store, TENANT, "10.9.101.5", t) or {}).get("mac")
    assert (at(T0 - 1), at(T0 + 10), at(T0 + 399), at(T0 + 400), at(T0 + 500)) == (None, MAC_A, MAC_A, MAC_B, MAC_B)


def test_leases_outside_enabled_tenants_are_ignored(store):
    result = sync_bindings(store, [lease("10.9.102.5", subnet=102), lease("10.9.101.5", subnet=999), lease("10.9.55.5", subnet=101)], T0)
    assert (result.opened, result.unmapped, result.out_of_subnet) == (0, 2, 1)


def test_binding_events_are_audited(store):
    sync_bindings(store, [lease()], T0)
    sync_bindings(store, [], T0 + 10)
    events = [(e["event"], e["actor"]) for e in store.audit_events()]
    assert events == [("binding.opened", "kea-lease-sync"), ("binding.closed", "kea-lease-sync")]


def test_watcher_keeps_bindings_when_the_source_fails(store):
    class Failing:
        def active(self, now):
            raise LeaseSourceError("permission denied")
    sync_bindings(store, [lease()], T0)
    watcher = LeaseWatcher(store, Failing())
    assert watcher.run_once(T0 + 1) is None and "permission denied" in watcher.last_error
    assert all_bindings(store)[0][3] is None


def test_watcher_picks_up_a_new_lease_within_one_poll(store, tmp_path):
    f = tmp_path / "kea-leases4.csv"
    f.write_text(HEADER + "\n")
    watcher = LeaseWatcher(store, KeaMemfileLeaseSource(f), interval_seconds=0.05)
    watcher.start()
    try:
        now = int(time.time())
        with f.open("a") as handle:
            handle.write(row("10.9.101.9", MAC_B, now + 300) + "\n")
        deadline = time.monotonic() + 2.0
        while binding_at(store, TENANT, "10.9.101.9", int(time.time())) is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert binding_at(store, TENANT, "10.9.101.9", int(time.time()))["mac"] == MAC_B
    finally:
        watcher.stop()


# --- activation MAC cross-check (log-only) ------------------------------------------------
def test_activation_with_a_different_mac_is_audited_and_allowed(store):
    sync_bindings(store, [lease(expire=int(time.time()) + 300)], int(time.time()))
    lifecycle = SubscriberLifecycle(store)
    sub = {"session_key": f"{TENANT}/10.9.101.5", "tenant_key": TENANT, "subscriber_id": "u1", "session_id": "s1",
           "private_ipv4": "10.9.101.5", "mac": MAC_B, "valid_until": "2099-01-01T00:00:00+00:00"}
    assert lifecycle.activate(sub, idempotency_key="k1", operation_id="op").authorized
    mismatch = [e for e in store.audit_events() if e["event"] == "subscriber.mac_mismatch"]
    assert len(mismatch) == 1 and mismatch[0]["binding_mac"] == MAC_A and mismatch[0]["action"] == "logged"
    lifecycle.activate({**sub, "session_key": f"{TENANT}/10.9.101.6", "private_ipv4": "10.9.101.6"}, idempotency_key="k2", operation_id="op")
    assert len([e for e in store.audit_events() if e["event"] == "subscriber.mac_mismatch"]) == 1  # no binding -> nothing to compare


# --- GET /v1/bindings ----------------------------------------------------------------------
@pytest.fixture
def server(store, tmp_path, monkeypatch):
    monkeypatch.setenv("BSNL_VPP_CONTROLLER_TOKEN", "test-token")
    instance = SubscriberApiServer(("127.0.0.1", 0), str(store.path), None)
    threading.Thread(target=instance.serve_forever, daemon=True).start()
    yield instance
    instance.shutdown()
    instance.server_close()


def get(server, query, auth=True):
    connection = HTTPConnection("127.0.0.1", server.server_port)
    connection.request("GET", "/v1/bindings?" + (query if isinstance(query, str) else urlencode(query)),
                       headers={"Authorization": "Bearer test-token"} if auth else {})
    response = connection.getresponse()
    payload = json.loads(response.read())
    connection.close()
    return response.status, payload


def test_bindings_api_requires_authentication(server):
    assert get(server, {"tenant_key": TENANT, "private_ipv4": "10.9.101.5"}, auth=False)[0] == 401


@pytest.mark.parametrize("query", ["tenant_key=x", "private_ipv4=10.9.101.5", "tenant_key=x&private_ipv4=nope",
                                   "tenant_key=x&private_ipv4=10.9.101.5&at=yesterday", "tenant_key=x&tenant_key=y&private_ipv4=10.9.101.5",
                                   "tenant_key=x&private_ipv4=10.9.101.5&extra=1"])
def test_bindings_api_rejects_bad_queries(server, query):
    assert get(server, query)[0] == 400


def test_bindings_api_returns_current_and_historical_binding(server, store):
    now = int(time.time())
    sync_bindings(store, [lease(mac=MAC_A, expire=now - 100 + 300)], now - 100)
    sync_bindings(store, [lease(mac=MAC_B, expire=now + 300)], now)
    status, current = get(server, {"tenant_key": TENANT, "private_ipv4": "10.9.101.5"})
    assert status == 200 and current["binding"]["mac"] == MAC_B and current["binding"]["valid_to"] is None
    past = datetime.fromtimestamp(now - 50, timezone.utc).isoformat()
    status, historical = get(server, {"tenant_key": TENANT, "private_ipv4": "10.9.101.5", "at": past})
    assert historical["binding"]["mac"] == MAC_A and historical["binding"]["close_reason"] == "mac_changed"
    for payload in (current, historical):
        assert not list(_validator("bindingResponse").iter_errors(payload))


def test_bindings_api_unknown_address_returns_null_binding(server):
    status, payload = get(server, {"tenant_key": TENANT, "private_ipv4": "10.9.101.77"})
    assert status == 200 and payload["binding"] is None
    assert not list(_validator("bindingResponse").iter_errors(payload))
