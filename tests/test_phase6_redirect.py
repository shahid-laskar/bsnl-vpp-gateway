"""Phase 6: pre-auth HTTP redirect via ABF (D-09 candidate B, ADR-015)."""
import copy
import json
import threading
from http.client import HTTPConnection
from pathlib import Path

import pytest

from controller.policy import (DENY, PERMIT, AclRule, PolicyValidationError, compile_redirect_acl,
                               compile_tenant_acl, redirect_tag)
from controller.redirector import RedirectServer, validate_location
from controller.vpp_adapter import VppApiAdapter, load_snapshot
from tests.fake_vpp import FakeVppApi, FakeVppClient

REPO = Path(__file__).resolve().parent.parent
LAB = json.loads((REPO / "config" / "lab" / "desired-state.json").read_text())
# ACL/ABF/restart behaviour only; MAC enforcement (lab: "enforce") is covered by test_phase6_mac.py.
LAB["tenants"][0]["mac_enforcement"] = "log_only"
TENANT = LAB["tenants"][0]
POLICY = LAB["policies"]["lab-preauth-v1"]
SNAPSHOT = REPO / "artifacts" / "api-crc-26.10.json"
REDIRECTOR = "198.51.100.2"


def subscriber(ip="10.9.101.7", state="authenticated"):
    return {"session_key": f"{TENANT['tenant_key']}/{ip}", "tenant_key": TENANT["tenant_key"], "subscriber_id": "42",
            "private_ipv4": ip, "state": state}


def test_lab_policy_enables_redirect():
    assert POLICY["http_redirect"] == {"next_hop": REDIRECTOR}


# --- compiled rules ----------------------------------------------------------------------
def test_http_permit_sits_after_protected_and_subscriber_rules_before_deny_all():
    rules = compile_tenant_acl(TENANT, POLICY, [subscriber()], redirect=True)
    http = AclRule(PERMIT, "10.9.101.0/24", "0.0.0.0/0", 6, (0, 65535), (80, 80))
    assert rules[-2] == http and rules[-1] == AclRule(DENY, "0.0.0.0/0", "0.0.0.0/0")
    assert rules.index(AclRule(DENY, "0.0.0.0/0", "10.44.0.0/22")) < rules.index(http)
    assert http not in compile_tenant_acl(TENANT, POLICY, [subscriber()])


def test_redirect_acl_exempts_portal_and_authenticated_destinations():
    rules = compile_redirect_acl(TENANT, POLICY, [subscriber("10.9.101.7"), subscriber("10.9.101.8", "deactivated")])
    assert AclRule(DENY, "10.9.101.0/24", "10.44.0.209/32", 6, (0, 65535), (80, 80)) in rules
    assert AclRule(DENY, "10.9.101.7/32", "192.0.2.0/24", 6, (0, 65535), (80, 80)) in rules
    assert not any(r.src_prefix == "10.9.101.8/32" for r in rules)
    assert rules[-1] == AclRule(PERMIT, "10.9.101.0/24", "0.0.0.0/0", 6, (0, 65535), (80, 80))


@pytest.mark.parametrize("bad", [{"next_hop": "::1"}, {"next_hop": "nope"}, {}, "198.51.100.2"])
def test_invalid_redirect_config_is_rejected(bad):
    adapter, _ = provisioned()
    state = with_policy(http_redirect=bad)
    with pytest.raises(Exception, match="http_redirect"):
        adapter.apply(state)


# --- enforcement in (fake) VPP -----------------------------------------------------------
def provisioned():
    api = FakeVppApi()
    api.add_interface("host-vpp-access", flags=1)
    client = FakeVppClient(set(load_snapshot(SNAPSHOT)["messages"].values()), api)
    adapter = VppApiAdapter("/fake.sock", snapshot_path=SNAPSHOT, enable_writes=True, client_factory=lambda s: client)
    adapter.connect()
    return adapter, api


def with_policy(subscribers=(), **changes):
    state = copy.deepcopy(LAB)
    state["policies"]["lab-preauth-v1"].update(changes)
    state["policies"]["lab-preauth-v1"] = {k: v for k, v in state["policies"]["lab-preauth-v1"].items() if v is not None}
    state["subscribers"] = list(subscribers)
    return state


def subif(api):
    return next(i for i, v in api.interfaces.items() if v["tags"] == 2)


def forwarded_to_redirector(api, sw, src, dst, dport=80):
    return api.permits(sw, src, dst, proto=6, dport=dport) and api.steers(sw, src, dst, 6, dport) == REDIRECTOR


def test_preauth_http_anywhere_is_steered_to_the_redirector():
    adapter, api = provisioned()
    adapter.apply(with_policy())
    sw = subif(api)
    assert forwarded_to_redirector(api, sw, "10.9.101.7", "93.184.216.34")
    assert forwarded_to_redirector(api, sw, "10.9.101.7", "192.0.2.1")            # authorized target, pre-auth
    # portal HTTP is permitted and forwarded normally
    assert api.permits(sw, "10.9.101.7", "10.44.0.209", proto=6, dport=80)
    assert api.steers(sw, "10.9.101.7", "10.44.0.209") is None
    # management LAN and gateway host stay denied by the ACL before ABF
    assert not api.permits(sw, "10.9.101.7", "10.44.1.234", proto=6, dport=80)
    assert not api.permits(sw, "10.9.101.7", "198.51.100.2", proto=6, dport=80)
    # HTTPS, QUIC and other ports are not redirected and stay denied
    assert not api.permits(sw, "10.9.101.7", "93.184.216.34", proto=6, dport=443)
    assert not api.permits(sw, "10.9.101.7", "93.184.216.34", proto=17, dport=443)
    assert not api.permits(sw, "10.9.101.7", "93.184.216.34", proto=6, dport=8080)


def test_authenticated_subscriber_is_exempt_only_for_its_destinations():
    adapter, api = provisioned()
    adapter.apply(with_policy([subscriber("10.9.101.7")]))
    sw = subif(api)
    assert api.permits(sw, "10.9.101.7", "192.0.2.1", proto=6, dport=80)
    assert api.steers(sw, "10.9.101.7", "192.0.2.1") is None                       # not redirected
    assert forwarded_to_redirector(api, sw, "10.9.101.8", "192.0.2.1")             # still pre-auth
    assert adapter.policy_applied[TENANT["tenant_key"]] == {"10.9.101.7"}
    assert adapter.enforce_subscriber(with_policy([subscriber("10.9.101.7")]), f"{TENANT['tenant_key']}/10.9.101.7", True)
    # deactivation: redirected again, permit gone
    assert adapter.enforce_subscriber(with_policy(), f"{TENANT['tenant_key']}/10.9.101.7", False)
    assert forwarded_to_redirector(api, sw, "10.9.101.7", "192.0.2.1")


def test_abf_written_before_the_tenant_acl_and_second_apply_is_silent():
    adapter, api = provisioned()
    adapter.apply(with_policy())
    writes = adapter.last_apply_writes
    attach = writes.index("abf_itf_attach_add_del")
    tenant_acl = max(i for i, w in enumerate(writes) if w == "acl_add_replace")
    assert attach < tenant_acl
    adapter.apply(with_policy())
    assert adapter.last_apply_writes == []
    assert [p["hops"] for p in api.abf_policies.values()] == [[REDIRECTOR]]
    tags = {a["tag"] for a in api.acls.values()}
    assert redirect_tag(TENANT["tenant_key"]) in tags


def test_disabling_redirect_drops_the_permit_then_the_abf_objects():
    adapter, api = provisioned()
    adapter.apply(with_policy())
    sw = subif(api)
    adapter.apply(with_policy(http_redirect=None))
    writes = adapter.last_apply_writes
    assert writes.index("acl_add_replace") < writes.index("abf_itf_attach_add_del") < writes.index("abf_policy_add_del")
    assert api.abf_policies == {} and api.abf_attachments == []
    assert {a["tag"] for a in api.acls.values()} == {f"bsnl:acl/{TENANT['tenant_key']}"}
    assert not api.permits(sw, "10.9.101.7", "93.184.216.34", proto=6, dport=80)


def test_next_hop_change_replaces_the_policy():
    adapter, api = provisioned()
    adapter.apply(with_policy())
    adapter.apply(with_policy(http_redirect={"next_hop": "198.51.100.3"}))
    assert [p["hops"] for p in api.abf_policies.values()] == [["198.51.100.3"]]
    assert len(api.abf_attachments) == 1
    assert api.steers(subif(api), "10.9.101.7", "93.184.216.34") == "198.51.100.3"


def test_snapshot_pins_abf_messages():
    names = set(load_snapshot(SNAPSHOT)["messages"])
    assert {"abf_policy_add_del", "abf_policy_dump", "abf_itf_attach_add_del", "abf_itf_attach_dump"} <= names


# --- redirector ----------------------------------------------------------------------------
LOGIN = "https://wifi.bsnl.co.in/portal/login/"


@pytest.fixture
def redirector():
    server = RedirectServer(("127.0.0.1", 0), LOGIN, max_clients=4)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


@pytest.mark.parametrize("method", ["GET", "HEAD", "POST"])
def test_redirector_answers_every_request_with_a_fixed_302(redirector, method):
    conn = HTTPConnection("127.0.0.1", redirector, timeout=5)
    conn.request(method, "/any/path?x=1", body=b"a=b" if method == "POST" else None,
                 headers={"Host": "evil.example"})
    response = conn.getresponse()
    body = response.read()
    assert response.status == 302
    assert response.getheader("Location") == LOGIN
    assert response.getheader("Cache-Control") == "no-store"
    assert "evil.example" not in body.decode() and (body == b"" if method == "HEAD" else LOGIN in body.decode())


@pytest.mark.parametrize("bad", ["javascript:alert(1)", "/relative", "https://x/\r\nSet-Cookie: a=b", "ftp://x/"])
def test_redirect_location_must_be_absolute_http(bad):
    with pytest.raises(ValueError):
        validate_location(bad)
