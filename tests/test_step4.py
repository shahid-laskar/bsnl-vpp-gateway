"""Remediation step 4: store atomicity, topology merge, expiry loop, stale
events, QinQ convergence against a fake VPP, CRC pinning, host services."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from controller.host_services import HostServiceValidationError, host_service_plans, lease_timers, render_dns_records, render_dnsmasq_config, render_kea_subnet
from controller.interfaces import SUB_IF_DOT1AD, SUB_IF_EXACT_MATCH, SUB_IF_TWO_TAGS, VppInterfaceProvisioner, interface_plans
from controller.reconcile import LabAdapter, Reconciler
from controller.state import merge_topology
from controller.store import DesiredStateStore
from controller.subscribers import StaleEventError, SubscriberLifecycle
from controller.vpp_adapter import CrcMismatchError, VppApiAdapter, load_snapshot
from tests.fake_vpp import FakeVppApi, FakeVppClient

REPO = Path(__file__).resolve().parent.parent
TENANT = "lab-vpp-01/host-vpp-access/0x8100/200/101"
NOW = datetime.now(timezone.utc)


def topology(**tenant_changes):
    tenant = {"tenant_key": TENANT, "customer_id": "c", "ingress_port": "access0", "parent_interface": "host-vpp-access",
              "outer_tpid": "0x8100", "outer_vlan": 200, "inner_vlan": 101, "vrf_id": 0,
              "gateway_ip": "10.9.101.1/24", "dhcp_ranges": [{"start": "10.9.101.5", "end": "10.9.101.105"}], "admin_state": "enabled"}
    tenant.update(tenant_changes)
    return {"schema_version": 2, "gateway_id": "lab-vpp-01", "gateway_revision": 1, "tenants": [tenant], "subscribers": [], "nat_pools": [], "policies": {}, "qos_profiles": {}}


def subscriber(ip="10.9.101.7", session_id="sess-1", minutes=30):
    return {"session_key": f"{TENANT}/{ip}", "tenant_key": TENANT, "subscriber_id": "42", "session_id": session_id,
            "private_ipv4": ip, "mac": "02:00:00:00:00:07", "valid_until": (NOW + timedelta(minutes=minutes)).isoformat()}


@pytest.fixture
def env(tmp_path):
    store = DesiredStateStore(tmp_path / "c.sqlite3", tmp_path / "audit.jsonl")
    lifecycle = SubscriberLifecycle(store)
    merge_topology(store, topology(), lifecycle)
    return store, lifecycle


# --- store -----------------------------------------------------------------------------
def test_failed_operation_rolls_back_state_idempotency_and_audit(env):
    store, lifecycle = env
    before_state, before_audit = store.read(), len(store.audit_events())
    with pytest.raises(RuntimeError):
        with store.transaction() as txn:
            state = txn.read()
            state["gateway_revision"] += 1
            txn.write(state)
            txn.put_idempotency("k", "h", {"x": 1})
            txn.append_audit({"event": "x"})
            raise RuntimeError("crash mid-operation")
    assert store.read() == before_state
    assert len(store.audit_events()) == before_audit
    with store.transaction() as txn:
        assert txn.get_idempotency("k") is None


def test_audit_events_carry_actor_timestamp_and_revision(env):
    store, lifecycle = env
    lifecycle.activate(subscriber(), idempotency_key="k1", operation_id="op1", actor="cert:bsnl-portal")
    event = store.audit_events()[-1]
    assert event["actor"] == "cert:bsnl-portal" and event["event"] == "subscriber.activate"
    assert event["gateway_revision"] >= 2 and datetime.fromisoformat(event["ts"])


def test_idempotency_records_expire(env):
    store, lifecycle = env
    lifecycle.activate(subscriber(), idempotency_key="k1", operation_id="op1")
    assert store.prune_idempotency(now=NOW) == 0
    assert store.prune_idempotency(now=NOW + timedelta(days=8)) >= 1


# --- topology merge (C-2) ---------------------------------------------------------------
def test_restart_with_unchanged_topology_keeps_subscribers_and_revision(env):
    store, lifecycle = env
    lifecycle.activate(subscriber(), idempotency_key="k1", operation_id="op1")
    revision = store.read()["gateway_revision"]
    merged = merge_topology(store, topology(), lifecycle)
    assert merged["gateway_revision"] == revision
    assert merged["subscribers"][0]["state"] == "authenticated"


def test_topology_edit_keeps_subscribers_even_with_higher_file_revision(env):
    store, lifecycle = env
    lifecycle.activate(subscriber(), idempotency_key="k1", operation_id="op1")
    edited = topology(mtu=1500)
    edited["gateway_revision"] = 999
    merged = merge_topology(store, edited, lifecycle)
    assert merged["gateway_revision"] == 1000
    assert [s["state"] for s in merged["subscribers"]] == ["authenticated"]


def test_disabling_a_tenant_deactivates_its_subscribers(env):
    store, lifecycle = env
    lifecycle.activate(subscriber(), idempotency_key="k1", operation_id="op1")
    merged = merge_topology(store, topology(admin_state="disabled"), lifecycle)
    assert merged["subscribers"][0]["state"] == "deactivated"
    assert any(e.get("reason") == "tenant_removed" for e in store.audit_events())


# --- lifecycle (C-1, C-3) ----------------------------------------------------------------
def test_reconciler_expires_sessions_while_running(env):
    store, lifecycle = env
    short = subscriber()
    short["valid_until"] = (NOW + timedelta(seconds=1)).isoformat()
    lifecycle.activate(short, idempotency_key="k1", operation_id="op1", now=NOW)
    reconciler = Reconciler(store, lifecycle, LabAdapter(), interval_seconds=3600)
    assert lifecycle.expire(now=NOW) == []
    import controller.subscribers as subs
    real = subs.datetime

    class Later(real):
        @classmethod
        def now(cls, tz=None):
            return NOW + timedelta(seconds=5)
    subs.datetime = Later
    try:
        summary = reconciler.run_once()
    finally:
        subs.datetime = real
    assert summary["expired"] == 1
    assert store.read()["subscribers"][0]["state"] == "expired"


def test_activation_after_logout_for_same_portal_session_is_rejected(env):
    store, lifecycle = env
    lifecycle.activate(subscriber(), idempotency_key="a1", operation_id="op1")
    lifecycle.deactivate(f"{TENANT}/10.9.101.7", idempotency_key="d1", operation_id="op2", reason="logout")
    with pytest.raises(StaleEventError):
        lifecycle.activate(subscriber(), idempotency_key="a1-late", operation_id="op3")
    new_login = lifecycle.activate(subscriber(session_id="sess-2"), idempotency_key="a2", operation_id="op4")
    assert new_login.authorized and new_login.reason == "activated"


# --- QinQ provisioning against fake VPP (C-6, P3/P4 acceptance) -------------------------------
def fake_with_parent():
    api = FakeVppApi()
    parent = api.add_interface("host-vpp-access", flags=1)
    return api, parent


def test_create_then_second_apply_makes_zero_writes():
    api, _ = fake_with_parent()
    provisioner = VppInterfaceProvisioner(api, enable_writes=True)
    provisioner.apply(topology())
    assert "create_subif" in provisioner.writes
    provisioner.apply(topology())
    assert provisioner.writes == []


def test_adopts_cli_created_subinterface_without_recreating_it():
    api, parent = fake_with_parent()
    index = api.add_interface("host-vpp-access.101", parent=parent, outer=200, inner=101, flags=1, sub_flags=SUB_IF_TWO_TAGS | SUB_IF_EXACT_MATCH)
    api.addresses[index] = {"10.9.101.1/24"}
    provisioner = VppInterfaceProvisioner(api, enable_writes=True)
    provisioner.apply(topology())
    assert "create_subif" not in provisioner.writes
    assert set(provisioner.writes) <= {"sw_interface_tag_add_del", "sw_interface_set_mtu"}
    assert api.interfaces[index]["tag"].startswith("bsnl:interface/")


def test_vpp_restart_is_restored_and_drift_repaired():
    api, _ = fake_with_parent()
    provisioner = VppInterfaceProvisioner(api, enable_writes=True)
    provisioner.apply(topology())
    api.restart()
    provisioner.apply(topology())
    sub = next(i for i, v in api.interfaces.items() if v["tags"] == 2)
    assert api.addresses[sub] == {"10.9.101.1/24"} and api.interfaces[sub]["admin"] == 1
    api.addresses[sub].clear()
    provisioner.apply(topology())
    assert provisioner.writes == ["sw_interface_add_del_address"]


def test_two_tenants_same_inner_vlan_different_outer_get_distinct_subinterfaces():
    api, _ = fake_with_parent()
    state = topology()
    second = dict(state["tenants"][0], tenant_key="lab-vpp-01/host-vpp-access/0x8100/300/101", outer_vlan=300, gateway_ip="10.9.102.1/24")
    state["tenants"].append(second)
    provisioner = VppInterfaceProvisioner(api, enable_writes=True)
    provisioner.apply(state)
    subs = sorted((v["outer"], v["inner"]) for v in api.interfaces.values() if v["tags"] == 2)
    assert subs == [(200, 101), (300, 101)]
    provisioner.apply(state)
    assert provisioner.writes == []


def test_only_controller_tagged_orphans_are_deleted():
    api, parent = fake_with_parent()
    foreign = api.add_interface("host-vpp-access.999", parent=parent, outer=10, inner=20, sub_flags=SUB_IF_TWO_TAGS | SUB_IF_EXACT_MATCH)
    stale = api.add_interface("host-vpp-access.777", parent=parent, outer=11, inner=21, sub_flags=SUB_IF_TWO_TAGS | SUB_IF_EXACT_MATCH, tag="bsnl:interface/old-tenant")
    VppInterfaceProvisioner(api, enable_writes=True).apply(topology())
    assert foreign in api.interfaces and stale not in api.interfaces


def test_refuses_to_adopt_incompatible_tpid():
    api, parent = fake_with_parent()
    api.add_interface("host-vpp-access.101", parent=parent, outer=200, inner=101, sub_flags=SUB_IF_TWO_TAGS | SUB_IF_EXACT_MATCH | SUB_IF_DOT1AD)
    with pytest.raises(RuntimeError, match="TPID"):
        VppInterfaceProvisioner(api, enable_writes=True).apply(topology())


def test_port_map_resolves_logical_ingress_port():
    state = topology()
    del state["tenants"][0]["parent_interface"]
    assert interface_plans(state, {"access0": "host-vpp-access"})[0].parent_interface == "host-vpp-access"


def test_writes_disabled_never_mutates():
    api, _ = fake_with_parent()
    VppInterfaceProvisioner(api, enable_writes=False).apply(topology())
    assert not set(api.calls) & VppInterfaceProvisioner.MUTATING


# --- VPP adapter / CRC pinning (C-8) ------------------------------------------------------
SNAPSHOT = REPO / "artifacts" / "api-crc-26.10.json"


def adapter_with(table, enable_writes=False):
    api = FakeVppApi()
    api.add_interface("host-vpp-access", flags=1)
    client = FakeVppClient(table, api)
    return VppApiAdapter("/fake.sock", snapshot_path=SNAPSHOT, enable_writes=enable_writes, client_factory=lambda s: client), client


def test_crc_mismatch_refuses_to_operate():
    snapshot = load_snapshot(SNAPSHOT)
    table = set(snapshot["messages"].values()) - {snapshot["messages"]["create_subif"]}
    adapter, client = adapter_with(table, enable_writes=True)
    with pytest.raises(CrcMismatchError):
        adapter.connect()
    caps = adapter.capabilities()
    assert caps["api_crc_ok"] is False and caps["writes_enabled"] is False and not client.connected
    with pytest.raises(RuntimeError):
        adapter.apply(topology())


def test_matching_crcs_allow_observation_and_never_claim_subscriber_enforcement():
    adapter, _ = adapter_with(set(load_snapshot(SNAPSHOT)["messages"].values()), enable_writes=True)
    adapter.connect()
    caps = adapter.capabilities()
    assert caps["api_crc_ok"] and caps["writes_enabled"] and caps["vpp_version"] == "26.10-release"
    assert caps["subscriber_policy_enforced"] is False
    adapter.apply(topology())
    assert "create_subif" in adapter.last_apply_writes
    assert adapter.observed_state()["qinq_subinterfaces"][0]["outer_vlan"] == 200


# --- host services (C-7) -----------------------------------------------------------------------
SERVICES = json.loads((REPO / "config" / "lab" / "host-services.json").read_text())


def test_lab_config_keeps_kea_subnet_101_and_derives_timers():
    lab = json.loads((REPO / "config" / "lab" / "desired-state.json").read_text())
    subnet = render_kea_subnet(host_service_plans(lab, SERVICES)[0])
    assert subnet["id"] == 101
    assert (subnet["valid-lifetime"], subnet["renew-timer"], subnet["rebind-timer"]) == (300, 150, 262)
    assert lease_timers(60) == (30, 52)


def test_kea_subnet_ids_do_not_collide_on_shared_inner_vlan():
    state = topology()
    state["tenants"].append(dict(state["tenants"][0], tenant_key="t2", outer_vlan=300, gateway_ip="10.9.102.1/24",
                                 dhcp_ranges=[{"start": "10.9.102.5", "end": "10.9.102.9"}]))
    ids = [p.kea_subnet_id for p in host_service_plans(state, SERVICES)]
    assert len(set(ids)) == 2
    state["tenants"][0]["kea_subnet_id"] = ids[1]
    with pytest.raises(HostServiceValidationError, match="used by both"):
        host_service_plans(state, SERVICES)


def test_dns_records_come_from_services_config_not_constants():
    records = render_dns_records({**SERVICES, "portal_address": "192.0.2.10"})
    assert records["wifi.bsnl.co.in"] == "192.0.2.10" and records["portal.lab"] == "198.51.100.2"
    rendered = render_dnsmasq_config(host_service_plans(topology(), SERVICES), SERVICES)
    assert "address=/captive.apple.com/10.44.0.209" in rendered
