"""Restart recovery (2026-11-17): after a VPP restart the controller must
re-apply its policy within seconds, not on the next 30 s reconcile tick, and
must not write before VPP's own startup config (bsnl-lab.cli) has finished."""
import json
from pathlib import Path

import pytest

from controller.interfaces import SUB_IF_EXACT_MATCH, SUB_IF_TWO_TAGS
from controller.reconcile import Reconciler
from controller.vpp_adapter import VppApiAdapter, VppStartupPending, load_snapshot
from tests.fake_vpp import FakeVppApi, FakeVppClient
from tests.test_vpp_reconnect import BrokenPipeApi

REPO = Path(__file__).resolve().parent.parent
SNAPSHOT = REPO / "artifacts" / "api-crc-26.10.json"
LAB = json.loads((REPO / "config" / "lab" / "desired-state.json").read_text())
TENANT = LAB["tenants"][0]["tenant_key"]
MUTATING = {"create_subif", "acl_add_replace", "acl_interface_set_acl_list", "acl_del", "sw_interface_add_del_address"}


def state(*ips):
    subs = [{"session_key": f"{TENANT}/{ip}", "tenant_key": TENANT, "subscriber_id": "42", "private_ipv4": ip, "state": "authenticated"} for ip in ips]
    return {**LAB, "subscribers": subs}


def fresh_vpp():
    """VPP right after start, before its startup config ran: parents only."""
    api = FakeVppApi()
    api.add_interface("host-vpp-access", flags=1)
    return api


def run_startup_script(api):
    """What bsnl-lab.cli leaves behind: the QinQ sub-interface with the static
    pre-auth ACL bound as its input ACL (the script's last command)."""
    parent = next(i for i, v in api.interfaces.items() if v["name"] == "host-vpp-access")
    sw = api.add_interface("host-vpp-access.101", parent=parent, outer=200, inner=101, flags=1,
                           sub_flags=SUB_IF_TWO_TAGS | SUB_IF_EXACT_MATCH)
    static = api.acl_add_replace(0xFFFFFFFF, "", 0, []).acl_index
    api.acl_interface_set_acl_list(sw, 1, 1, [static])
    api.calls.clear()
    return sw, static


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def adapter_for(*apis, clock=None, settle=10.0, writes=True):
    messages = set(load_snapshot(SNAPSHOT)["messages"].values())
    clients = iter(FakeVppClient(messages, api) for api in apis)
    adapter = VppApiAdapter("/fake.sock", snapshot_path=SNAPSHOT, enable_writes=writes, client_factory=lambda s: next(clients),
                            port_map={"access0": "host-vpp-access"}, settle_seconds=settle, clock=clock or Clock())
    adapter.connect()
    return adapter


def test_writes_wait_until_the_vpp_startup_script_has_finished():
    api = fresh_vpp()
    adapter = adapter_for(api)
    with pytest.raises(VppStartupPending):
        adapter.apply(state("10.9.101.7"))
    assert not MUTATING & set(api.calls)  # nothing created that the script would then collide with
    sw, static = run_startup_script(api)
    adapter.apply(state("10.9.101.7"))
    assert api.acl_bindings[sw] != [static]  # tagged tenant ACL replaced the static one
    assert api.permits(sw, "10.9.101.7", "192.0.2.1")


def test_without_a_startup_script_writes_proceed_after_the_settle_window():
    api, clock = fresh_vpp(), Clock()
    adapter = adapter_for(api, clock=clock)
    with pytest.raises(VppStartupPending):
        adapter.apply(state())
    clock.now += 10
    adapter.apply(state())  # controller creates the sub-interface itself
    assert "create_subif" in api.calls


def test_new_connection_clears_stale_policy_enforcement():
    api = fresh_vpp()
    run_startup_script(api)
    adapter = adapter_for(api, fresh_vpp())
    adapter.apply(state())
    assert adapter.capabilities()["subscriber_policy_enforced"] is True
    api.__class__ = BrokenPipeApi
    adapter.liveness()
    assert adapter.connect_count == 2
    assert adapter.capabilities()["subscriber_policy_enforced"] is False


class Store:
    def __init__(self, desired):
        self.desired = desired

    def read(self):
        return self.desired

    def prune_idempotency(self):
        return 0


class Lifecycle:
    def expire(self):
        return []


def test_watch_loop_reapplies_as_soon_as_restarted_vpp_has_finished_its_startup():
    before, after = fresh_vpp(), fresh_vpp()
    run_startup_script(before)
    adapter = adapter_for(before, after)
    reconciler = Reconciler(Store(state("10.9.101.7")), Lifecycle(), adapter, interval_seconds=30)
    assert reconciler.watch_once()["applied"] is True  # first connection: converge once
    assert reconciler.watch_once() is None             # steady state: ping only

    before.__class__ = BrokenPipeApi                   # VPP restarted
    summary = reconciler.watch_once()                  # reconnected, script still running
    assert summary == {"expired": 0, "pruned": 0, "applied": False, "startup_pending": True}
    assert not MUTATING & set(after.calls) and reconciler.last_error is None

    sw, _ = run_startup_script(after)
    summary = reconciler.watch_once()
    assert summary["applied"] is True and reconciler.recoveries == 2
    assert after.permits(sw, "10.9.101.7", "192.0.2.1")
    assert adapter.capabilities()["subscriber_policy_enforced"] is True
    assert reconciler.watch_once() is None


def test_observe_mode_watch_only_reconnects():
    before, after = fresh_vpp(), fresh_vpp()
    adapter = adapter_for(before, after, writes=False)
    reconciler = Reconciler(Store(state()), Lifecycle(), adapter)
    before.__class__ = BrokenPipeApi
    assert reconciler.watch_once() is None
    assert adapter.connect_count == 2 and reconciler.runs == 0


def test_adapters_without_liveness_are_not_watched():
    from controller.reconcile import LabAdapter
    reconciler = Reconciler(Store(state()), Lifecycle(), LabAdapter())
    assert reconciler.watch_once() is None
