"""Phase 6: MAC/IP source enforcement from lease bindings (ADR-016)."""
import copy
import json
from pathlib import Path

import pytest

from controller.bindings import LeaseWatcher, SyncResult
from controller.mac_enforcement import (HEAD_MASK, MAC_OFFSET, TAIL_KEY, head_key, parse_head_key, wanted_pairs)
from controller.policy import PolicyValidationError
from controller.vpp_adapter import VppApiAdapter, load_snapshot
from tests.fake_vpp import FakeVppApi, FakeVppClient

REPO = Path(__file__).resolve().parent.parent
LAB = json.loads((REPO / "config" / "lab" / "desired-state.json").read_text())
TENANT = LAB["tenants"][0]["tenant_key"]
SNAPSHOT = REPO / "artifacts" / "api-crc-26.10.json"
MAC_A, MAC_B, MAC_X = "02:aa:00:00:00:01", "02:aa:00:00:00:02", "02:aa:00:00:00:99"


def binding(ip, mac, tenant=TENANT, valid_to=None):
    return {"tenant_key": tenant, "private_ipv4": ip, "mac": mac, "valid_to": valid_to}


def state(mode="enforce"):
    s = copy.deepcopy(LAB)
    s["tenants"][0]["mac_enforcement"] = mode
    s["subscribers"] = []
    return s


def provisioned(bindings=None):
    api = FakeVppApi()
    api.add_interface("host-vpp-access", flags=1)
    client = FakeVppClient(set(load_snapshot(SNAPSHOT)["messages"].values()), api)
    adapter = VppApiAdapter("/fake.sock", snapshot_path=SNAPSHOT, enable_writes=True, client_factory=lambda s: client)
    adapter.connect()
    box = {"rows": list(bindings or [])}
    adapter.bindings_provider = lambda: list(box["rows"])
    return adapter, api, box


def subif(api):
    return next(i for i, v in api.interfaces.items() if v["tags"] == 2)


def test_lab_tenant_enforces_mac():
    assert LAB["tenants"][0]["mac_enforcement"] == "enforce"


# --- keys and selection ----------------------------------------------------------------------
def test_key_layout_is_relative_to_the_ip_header_of_a_double_tagged_frame():
    assert MAC_OFFSET == -16 and len(HEAD_MASK) == 32
    key = head_key(MAC_A, "10.9.101.7")
    assert key[:6] == bytes.fromhex("02aa00000001") and key[28:32] == bytes([10, 9, 101, 7])
    assert parse_head_key(key) == (MAC_A, "10.9.101.7")


def test_only_open_in_subnet_bindings_of_the_tenant_are_permitted():
    rows = [binding("10.9.101.7", MAC_A), binding("10.9.101.8", MAC_B, valid_to=1),
            binding("10.9.101.9", MAC_B, tenant="other"), binding("10.9.102.9", MAC_B), binding("10.9.101.10", "not-a-mac")]
    assert wanted_pairs(LAB["tenants"][0], rows) == {(MAC_A, "10.9.101.7")}


# --- enforcement in (fake) VPP ----------------------------------------------------------------
def test_log_only_writes_nothing_and_permits_everything():
    adapter, api, _ = provisioned([binding("10.9.101.7", MAC_A)])
    adapter.apply(state("log_only"))
    assert not any(w.startswith(("classify", "input_acl")) for w in adapter.last_apply_writes)
    assert api.mac_permits(subif(api), MAC_X, "10.9.101.200")
    assert adapter.capabilities()["mac_enforcement"] == {TENANT: "log_only"}


def test_enforce_permits_bound_pairs_and_dhcp_only():
    adapter, api, _ = provisioned([binding("10.9.101.7", MAC_A), binding("10.9.101.8", MAC_B)])
    adapter.apply(state())
    sw = subif(api)
    assert api.mac_permits(sw, MAC_A, "10.9.101.7") and api.mac_permits(sw, MAC_B, "10.9.101.8")
    assert not api.mac_permits(sw, MAC_X, "10.9.101.7")        # same IP, other device
    assert not api.mac_permits(sw, MAC_A, "10.9.101.8")        # bound device, someone else's IP
    assert not api.mac_permits(sw, MAC_X, "10.9.101.200")      # no lease at all
    assert api.mac_permits(sw, MAC_X, "0.0.0.0")               # DHCP DISCOVER/REQUEST
    assert adapter.capabilities()["mac_enforcement"] == {TENANT: "enforce"}
    assert adapter.mac_enforced[TENANT] == {"10.9.101.7", "10.9.101.8"}


def test_chain_is_bound_after_its_sessions_and_second_apply_is_silent():
    adapter, api, _ = provisioned([binding("10.9.101.7", MAC_A)])
    adapter.apply(state())
    writes = adapter.last_apply_writes
    assert writes.index("input_acl_set_interface") > max(i for i, w in enumerate(writes) if w == "classify_add_del_session")
    adapter.apply(state())
    assert adapter.last_apply_writes == []


def test_binding_changes_update_sessions_in_place():
    adapter, api, box = provisioned([binding("10.9.101.7", MAC_A)])
    adapter.apply(state())
    sw, head = subif(api), api.inacl_ip4[subif(api)]
    box["rows"] = [binding("10.9.101.7", MAC_X), binding("10.9.101.9", MAC_B)]   # IP moved to a new device, new lease
    adapter.apply(state())
    assert api.inacl_ip4[sw] == head
    assert adapter.last_apply_writes.count("classify_add_del_session") == 3 and "input_acl_set_interface" not in adapter.last_apply_writes
    assert not api.mac_permits(sw, MAC_A, "10.9.101.7") and api.mac_permits(sw, MAC_X, "10.9.101.7")
    assert api.mac_permits(sw, MAC_B, "10.9.101.9")
    box["rows"] = []
    adapter.apply(state())
    assert not api.mac_permits(sw, MAC_X, "10.9.101.7") and api.mac_permits(sw, MAC_X, "0.0.0.0")


def test_back_to_log_only_unbinds_and_deletes_the_chain():
    adapter, api, _ = provisioned([binding("10.9.101.7", MAC_A)])
    adapter.apply(state())
    adapter.apply(state("log_only"))
    assert api.inacl_ip4 == {} and api.cls_tables == {}
    assert api.mac_permits(subif(api), MAC_X, "10.9.101.200")


def test_enforce_without_a_lease_source_is_refused():
    adapter, api, _ = provisioned()
    adapter.bindings_provider = None
    with pytest.raises(PolicyValidationError, match="lease bindings"):
        adapter.apply(state())
    assert api.inacl_ip4 == {}


def test_foreign_input_acl_table_is_never_touched():
    adapter, api, _ = provisioned()
    adapter.apply(state("log_only"))
    sw = subif(api)
    foreign = api.classify_add_del_table(True, False, 0xFFFFFFFF, 16, 1 << 20, 0, 1, 0xFFFFFFFF, 0, 0, 0, 16, b"\xff" * 16).new_table_index
    api.input_acl_set_interface(sw, foreign, 0xFFFFFFFF, 0xFFFFFFFF, True)
    with pytest.raises(RuntimeError, match="does not own"):
        adapter.apply(state())
    with pytest.raises(RuntimeError, match="does not own"):
        adapter.apply(state("log_only"))
    assert api.inacl_ip4[sw] == foreign


def test_invalid_mode_is_rejected():
    adapter, _, _ = provisioned()
    with pytest.raises(PolicyValidationError, match="mac_enforcement"):
        adapter.apply(state("strict"))


def test_tail_session_is_repaired():
    adapter, api, _ = provisioned()
    adapter.apply(state())
    tail = api.cls_tables[api.inacl_ip4[subif(api)]]["next"]
    api.cls_tables[tail]["sessions"].clear()
    adapter.apply(state())
    assert TAIL_KEY in api.cls_tables[tail]["sessions"]


def test_snapshot_pins_classifier_messages():
    names = set(load_snapshot(SNAPSHOT)["messages"])
    assert {"classify_add_del_table", "classify_add_del_session", "classify_table_by_interface", "classify_table_info",
            "classify_session_dump", "input_acl_set_interface"} <= names


# --- lease watcher hook ------------------------------------------------------------------------
class Source:
    def __init__(self):
        self.leases = []

    def active(self, now):
        return list(self.leases)


@pytest.mark.parametrize("opened,closed,renewed,called", [(1, 0, 0, True), (0, 1, 0, True), (0, 0, 3, False)])
def test_lease_watcher_calls_the_hook_on_open_and_close_only(monkeypatch, opened, closed, renewed, called):
    import controller.bindings as b
    monkeypatch.setattr(b, "sync_bindings", lambda store, leases, now: SyncResult(opened=opened, closed=closed, renewed=renewed))
    seen = []
    watcher = LeaseWatcher(store=None, source=Source(), on_change=seen.append)
    watcher.run_once(now=1000)
    assert bool(seen) is called


def test_lease_watcher_survives_a_failing_hook(monkeypatch):
    import controller.bindings as b
    monkeypatch.setattr(b, "sync_bindings", lambda store, leases, now: SyncResult(opened=1))
    watcher = LeaseWatcher(store=None, source=Source(), on_change=lambda r: 1 / 0)
    assert watcher.run_once(now=1000).opened == 1
