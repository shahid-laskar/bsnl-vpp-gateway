"""D-09 candidate A: per-subscriber authorization with SVS (ADR-017)."""
import copy
import json
from pathlib import Path

import pytest

from controller.policy import DENY, PERMIT, AclRule, PolicyValidationError, compile_tenant_acl
from controller.vpp_adapter import VppApiAdapter, load_snapshot
from tests.fake_vpp import FakeVppApi, FakeVppClient

REPO = Path(__file__).resolve().parent.parent
LAB = json.loads((REPO / "config" / "lab" / "desired-state.json").read_text())
TENANT = LAB["tenants"][0]
KEY = TENANT["tenant_key"]
POLICY_REF = TENANT["pre_auth_policy_ref"]
SNAPSHOT = REPO / "artifacts" / "api-crc-26.10.json"
SUBNET = "10.9.101.0/24"


def sub(ip, state="authenticated"):
    return {"session_key": f"{KEY}/{ip}", "tenant_key": KEY, "subscriber_id": ip, "private_ipv4": ip, "state": state}


def state(*subs, authorization="svs", **tenant_changes):
    s = copy.deepcopy(LAB)
    s["tenants"][0]["mac_enforcement"] = "log_only"   # MAC: test_phase6_mac.py
    s["tenants"][0].update(tenant_changes)
    s["policies"][POLICY_REF]["authorization"] = authorization
    if authorization == "acl":
        s["tenants"][0]["vrf_id"] = tenant_changes.get("vrf_id", 0)
    s["subscribers"] = list(subs)
    return s


def provisioned():
    api = FakeVppApi()
    api.add_interface("host-vpp-access", flags=1)
    client = FakeVppClient(set(load_snapshot(SNAPSHOT)["messages"].values()), api)
    adapter = VppApiAdapter("/fake.sock", snapshot_path=SNAPSHOT, enable_writes=True, client_factory=lambda s: client)
    adapter.connect()
    return adapter, api


def subif(api):
    return next(i for i, v in api.interfaces.items() if v["tags"] == 2)


def test_lab_desired_state_uses_svs_with_a_captive_vrf():
    policy = LAB["policies"][POLICY_REF]
    assert policy["authorization"] == "svs" and policy["internet_vrf"] == 0
    assert TENANT["vrf_id"] == 101 and TENANT["svs_table_id"] == 1101


def test_static_acl_has_no_per_subscriber_rules():
    rules = compile_tenant_acl(state()["tenants"][0], state()["policies"][POLICY_REF], [sub("10.9.101.7")],
                               redirect=True, authorization="svs")
    assert not any(r.src_prefix.endswith("/32") for r in rules)
    assert AclRule(PERMIT, SUBNET, "192.0.2.0/24") in rules
    assert rules.index(AclRule(DENY, "0.0.0.0/0", "10.44.0.0/22")) < rules.index(AclRule(PERMIT, SUBNET, "192.0.2.0/24"))
    assert rules[-1] == AclRule(DENY, "0.0.0.0/0", "0.0.0.0/0")


def test_svs_mode_steers_only_authenticated_sources_to_the_internet_vrf():
    adapter, api = provisioned()
    adapter.apply(state(sub("10.9.101.7"), sub("10.9.101.8", "deactivated")))
    sw = subif(api)
    assert api.tables[sw] == 101                                  # captive VRF
    assert api.svs_enabled == {sw: 1101}
    assert api.lookup_table(sw, "10.9.101.7") == 0                # internet VRF
    assert api.lookup_table(sw, "10.9.101.8") == 101              # falls through (R-11)
    assert api.permits(sw, "10.9.101.8", "192.0.2.1")             # static ACL: the VRF decides
    assert not api.permits(sw, "10.9.101.7", "10.44.1.234", proto=6, dport=22)
    assert adapter.policy_applied[KEY] == {"10.9.101.7"}
    assert getattr(api, "abf_policies", {}) == {} and not any(a["tag"].startswith("bsnl:abf/") for a in api.acls.values())
    adapter.apply(state(sub("10.9.101.7"), sub("10.9.101.8", "deactivated")))
    assert adapter.last_apply_writes == []


def test_login_and_logout_are_one_svs_write_each():
    adapter, api = provisioned()
    adapter.apply(state(*[sub(f"10.9.101.{i}") for i in range(10, 60)]))
    sw = subif(api)
    assert adapter.enforce_subscriber(state(sub("10.9.101.7")), f"{KEY}/10.9.101.7", True)
    assert adapter.last_apply_writes == ["svs_route_add_del"]
    assert api.lookup_table(sw, "10.9.101.7") == 0 and "10.9.101.7" in adapter.policy_applied[KEY]
    assert adapter.enforce_subscriber(state(), f"{KEY}/10.9.101.7", False)
    assert adapter.last_apply_writes == ["svs_route_add_del"]
    assert api.lookup_table(sw, "10.9.101.7") == 101


def test_fast_path_falls_back_to_a_full_apply():
    adapter, api = provisioned()
    adapter.apply(state())
    # Deactivating an address that has no entry: VPP refuses the delete; the
    # full apply converges and confirms the subscriber is not authorized.
    assert adapter.enforce_subscriber(state(), f"{KEY}/10.9.101.9", False)
    assert "svs_route_add_del" not in adapter.last_apply_writes
    # Before any successful full apply there is no fast path either.
    fresh, _ = provisioned()
    assert fresh.enforce_subscriber(state(sub("10.9.101.7")), f"{KEY}/10.9.101.7", True)
    assert "sw_interface_set_table" in fresh.last_apply_writes


def test_reconcile_repairs_entries():
    adapter, api = provisioned()
    adapter.apply(state(sub("10.9.101.7")))
    api.svs_routes[1101]["10.9.101.99/32"] = 0                   # stray entry
    del api.svs_routes[1101]["10.9.101.7/32"]                     # lost entry
    adapter.apply(state(sub("10.9.101.7")))
    assert set(api.svs_routes[1101]) == {"10.9.101.7/32"}


@pytest.mark.parametrize("changes,match", [({"vrf_id": 0}, "captive vrf_id"), ({"svs_table_id": 101}, "must differ")])
def test_unsafe_vrf_layout_is_refused(changes, match):
    adapter, api = provisioned()
    with pytest.raises(PolicyValidationError, match=match):
        adapter.apply(state(sub("10.9.101.7"), **changes))
    assert getattr(api, "svs_enabled", {}) == {}


def test_back_to_acl_mode_removes_svs():
    adapter, api = provisioned()
    adapter.apply(state(sub("10.9.101.7")))
    adapter.apply(state(sub("10.9.101.7"), authorization="acl"))
    sw = subif(api)
    assert api.svs_enabled == {} and 1101 not in api.svs_tables
    assert api.tables[sw] == 0
    assert api.permits(sw, "10.9.101.7", "192.0.2.1") and not api.permits(sw, "10.9.101.8", "192.0.2.1")
    assert adapter.policy_applied[KEY] == {"10.9.101.7"}


def test_unknown_authorization_is_refused():
    adapter, _ = provisioned()
    with pytest.raises(PolicyValidationError, match="authorization"):
        adapter.apply(state(authorization="vrf"))


def test_snapshot_pins_svs_messages():
    names = set(load_snapshot(SNAPSHOT)["messages"])
    assert {"svs_table_add_del", "svs_enable_disable", "svs_route_add_del", "svs_dump", "ip_route_dump"} <= names
