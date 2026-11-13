import sqlite3

import pytest

from controller.keys import desired_object_keys
from controller.store import DesiredStateStore
from controller.validation import validate_desired_state


def valid_state():
    return {
        "schema_version": 2,
        "gateway_id": "g",
        "gateway_revision": 1,
        "tenants": [{
            "tenant_key": "g/access0/0x8100/200/101",
            "customer_id": "c",
            "ingress_port": "access0",
            "outer_tpid": "0x8100",
            "outer_vlan": 200,
            "inner_vlan": 101,
            "vrf_id": 101,
            "gateway_ip": "10.9.101.1/24",
            "admin_state": "enabled",
        }],
        "subscribers": [],
        "nat_pools": [],
        "policies": {},
        "qos_profiles": {},
    }


def test_sqlite_store_uses_wal_and_audit(tmp_path):
    store = DesiredStateStore(tmp_path / "controller.sqlite3")
    state = valid_state()
    store.write(state)
    store.append_audit({"operation_id": "op-1"})
    assert store.read() == state
    with sqlite3.connect(tmp_path / "controller.sqlite3") as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert connection.execute("SELECT COUNT(*) FROM audit").fetchone()[0] == 1


def test_schema_validation_and_deterministic_keys():
    state = valid_state()
    validate_desired_state(state)
    assert desired_object_keys(state) == ["interface/g/access0/0x8100/200/101", "interface/g/access0/0x8100/200/101/address", "interface/g/access0/0x8100/200/101/vrf", "tenant/g/access0/0x8100/200/101"]
    state["tenants"].append(dict(state["tenants"][0]))
    with pytest.raises(ValueError, match="duplicate tenant_key"):
        validate_desired_state(state)
