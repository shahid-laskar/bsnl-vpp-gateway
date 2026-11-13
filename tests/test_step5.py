"""Remediation step 5: per-subscriber authorization enforced in VPP (D-09 B)."""
import json
import threading
from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection
from pathlib import Path
from types import SimpleNamespace

import pytest

from controller.api import SubscriberApiServer
from controller.policy import DENY, PERMIT, AclRule, PolicyValidationError, compile_tenant_acl
from controller.state import merge_topology
from controller.store import DesiredStateStore
from controller.subscribers import SubscriberLifecycle
from controller.vpp_adapter import VppApiAdapter, load_snapshot
from tests.fake_vpp import FakeVppApi, FakeVppClient

REPO = Path(__file__).resolve().parent.parent
LAB = json.loads((REPO / "config" / "lab" / "desired-state.json").read_text())
TENANT = LAB["tenants"][0]["tenant_key"]
POLICY = LAB["policies"]["lab-preauth-v1"]
SNAPSHOT = REPO / "artifacts" / "api-crc-26.10.json"


def subscriber(ip="10.9.101.7", state="authenticated"):
    return {"session_key": f"{TENANT}/{ip}", "tenant_key": TENANT, "subscriber_id": "42",
            "private_ipv4": ip, "state": state}


# --- compiled policy -------------------------------------------------------------------
def test_rule_order_preauth_then_protected_then_subscribers_then_deny():
    rules = compile_tenant_acl(LAB["tenants"][0], POLICY, [subscriber()])
    kinds = [("permit" if r.is_permit == PERMIT else "deny", r.src_prefix) for r in rules]
    first_deny = next(i for i, k in enumerate(kinds) if k[0] == "deny")
    sub_permit = kinds.index(("permit", "10.9.101.7/32"))
    assert all(k[0] == "permit" for k in kinds[:first_deny])
    assert first_deny < sub_permit
    assert rules[-1] == AclRule(DENY, "0.0.0.0/0", "0.0.0.0/0")


def test_only_authenticated_subscribers_of_the_tenant_get_permits():
    subs = [subscriber("10.9.101.7"), subscriber("10.9.101.8", "deactivated"), subscriber("10.9.101.9", "expired"),
            {"tenant_key": "other", "private_ipv4": "10.9.101.10", "state": "authenticated"}]
    permits = {r.src_prefix for r in compile_tenant_acl(LAB["tenants"][0], POLICY, subs) if r.src_prefix.endswith("/32")}
    assert permits == {"10.9.101.7/32"}


def test_ipv6_policy_entries_are_rejected():
    with pytest.raises(PolicyValidationError, match="IPv4 only"):
        compile_tenant_acl(LAB["tenants"][0], {**POLICY, "authenticated_destinations": ["::/0"]}, [])


# --- enforcement in (fake) VPP -----------------------------------------------------------
def provisioned():
    api = FakeVppApi()
    api.add_interface("host-vpp-access", flags=1)
    client = FakeVppClient(set(load_snapshot(SNAPSHOT)["messages"].values()), api)
    adapter = VppApiAdapter("/fake.sock", snapshot_path=SNAPSHOT, enable_writes=True, client_factory=lambda s: client)
    adapter.connect()
    return adapter, api


def state_with(*subs):
    return {**LAB, "subscribers": list(subs)}


def subif(api):
    return next(i for i, v in api.interfaces.items() if v["tags"] == 2)


def test_preauth_allows_only_essentials_and_protects_management():
    adapter, api = provisioned()
    adapter.apply(state_with())
    sw = subif(api)
    assert api.permits(sw, "10.9.101.7", "10.44.0.209", proto=6, dport=443)       # portal HTTPS
    assert api.permits(sw, "10.9.101.7", "198.51.100.2", proto=17, dport=53)     # DNS
    assert api.permits(sw, "10.9.101.7", "10.9.101.1", proto=17, dport=67)       # DHCP unicast renew (S-1)
    assert not api.permits(sw, "10.9.101.7", "10.44.0.10", proto=6, dport=22)    # management LAN
    assert not api.permits(sw, "10.9.101.7", "198.51.100.2", proto=6, dport=22)  # gateway host SSH
    assert not api.permits(sw, "10.9.101.7", "192.0.2.1")                        # authorized-only target
    assert not api.permits(sw, "10.9.101.7", "1.1.1.1", proto=17, dport=443)     # QUIC
    assert not api.permits(sw, "10.9.101.7", "1.1.1.1", proto=6, dport=853)      # DoT
    assert not api.permits(sw, "10.9.101.7", "8.8.8.8", proto=17, dport=53)      # foreign resolver


def test_authorization_opens_only_policy_destinations_and_deauth_closes_them():
    adapter, api = provisioned()
    adapter.apply(state_with(subscriber()))
    sw = subif(api)
    assert api.permits(sw, "10.9.101.7", "192.0.2.1")
    assert not api.permits(sw, "10.9.101.8", "192.0.2.1")                        # another subscriber
    assert not api.permits(sw, "10.9.101.7", "10.44.0.10", proto=6, dport=22)    # still protected
    assert not api.permits(sw, "10.9.101.7", "10.9.101.8")                       # intra-tenant blocked
    adapter.apply(state_with(subscriber(state="deactivated")))
    assert not api.permits(sw, "10.9.101.7", "192.0.2.1")


def test_converged_policy_makes_zero_writes_and_restores_after_vpp_restart():
    adapter, api = provisioned()
    adapter.apply(state_with(subscriber()))
    adapter.apply(state_with(subscriber()))
    assert adapter.last_apply_writes == []
    api.restart()
    api.acls.clear()
    api.acl_bindings.clear()
    adapter.apply(state_with(subscriber()))
    assert api.permits(subif(api), "10.9.101.7", "192.0.2.1")


def test_capability_reports_enforcement_only_after_successful_apply():
    adapter, _ = provisioned()
    assert adapter.capabilities()["subscriber_policy_enforced"] is False
    adapter.apply(state_with())
    assert adapter.capabilities()["subscriber_policy_enforced"] is True


# --- API: dataplane_enforced reflects VPP ----------------------------------------------------
@pytest.fixture
def api_server(tmp_path, monkeypatch):
    monkeypatch.setenv("BSNL_VPP_CONTROLLER_TOKEN", "t")
    monkeypatch.delenv("BSNL_VPP_PORTAL_HMAC_SECRET", raising=False)
    store = DesiredStateStore(tmp_path / "s.sqlite3")
    lifecycle = SubscriberLifecycle(store)
    merge_topology(store, LAB, lifecycle)
    adapter, api = provisioned()
    adapter.apply(store.read())
    server = SubscriberApiServer(("127.0.0.1", 0), str(tmp_path / "s.sqlite3"), adapter=adapter, lifecycle=lifecycle)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server, api
    server.shutdown()
    server.server_close()


def post(server, path, body, key):
    raw = json.dumps(body).encode()
    connection = HTTPConnection("127.0.0.1", server.server_port)
    connection.request("POST", path, body=raw, headers={"Content-Type": "application/json", "Authorization": "Bearer t", "Idempotency-Key": key})
    response = connection.getresponse()
    payload = json.loads(response.read())
    connection.close()
    return response.status, payload


def activation(ip, session_id, subscriber_id):
    expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    return {"operation_id": f"op-{session_id}", "subscriber": {
        "session_key": f"{TENANT}/{ip}", "tenant_key": TENANT, "subscriber_id": subscriber_id,
        "session_id": session_id, "private_ipv4": ip, "mac": None, "valid_until": expiry}}


def test_activate_and_deactivate_are_enforced_before_responding(api_server):
    server, api = api_server
    status, payload = post(server, "/v1/subscribers/activate", activation("10.9.101.7", "s1", "42"), "a1")
    assert status == 200 and payload["dataplane_enforced"] is True
    assert api.permits(subif(api), "10.9.101.7", "192.0.2.1")
    status, payload = post(server, "/v1/subscribers/deactivate", {"operation_id": "op2", "session_key": f"{TENANT}/10.9.101.7", "reason": "logout"}, "d1")
    assert status == 200 and payload["dataplane_enforced"] is True and payload["authorized"] is False
    assert not api.permits(subif(api), "10.9.101.7", "192.0.2.1")


def test_enforcement_failure_is_reported_not_hidden(api_server):
    server, api = api_server
    api.acl_add_replace = lambda **kw: SimpleNamespace(retval=-1, acl_index=0)
    status, payload = post(server, "/v1/subscribers/activate", activation("10.9.101.8", "s2", "43"), "a2")
    assert status == 200 and payload["authorized"] is True and payload["dataplane_enforced"] is False
    assert server.adapter.capabilities()["subscriber_policy_enforced"] is False
