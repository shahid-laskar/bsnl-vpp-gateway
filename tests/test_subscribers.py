from datetime import datetime, timedelta, timezone
import pytest
from controller.store import DesiredStateStore
from controller.subscribers import SubscriberLifecycle
def base_state():
    return {"schema_version": 2, "gateway_id": "lab-vpp-01", "gateway_revision": 1, "tenants": [{"tenant_key": "tenant-1", "admin_state": "enabled", "gateway_ip": "10.9.101.1/24"}], "subscribers": []}
def subscriber(expiry):
    return {"session_key": "tenant-1/10.9.101.5", "tenant_key": "tenant-1", "subscriber_id": "usr-1", "session_id": "sess-1", "private_ipv4": "10.9.101.5", "mac": "02:00:00:00:00:01", "valid_until": expiry.isoformat()}
def lifecycle(tmp_path):
    store = DesiredStateStore(tmp_path / "desired.json"); store.write(base_state()); return SubscriberLifecycle(store, tmp_path / "audit.jsonl"), store
def test_activation_is_idempotent_and_audited(tmp_path):
    service, store = lifecycle(tmp_path); expiry = datetime.now(timezone.utc) + timedelta(minutes=5)
    first = service.activate(subscriber(expiry), idempotency_key="k1", operation_id="op1"); second = service.activate(subscriber(expiry), idempotency_key="k1", operation_id="op1")
    assert first.changed is True; assert second.changed is False; assert first.authorized is second.authorized is True; assert len(store.read()["subscribers"]) == 1; assert len((tmp_path / "audit.jsonl").read_text().splitlines()) == 2
def test_expiry_deactivates_without_authorization(tmp_path):
    service, store = lifecycle(tmp_path); expiry = datetime.now(timezone.utc) + timedelta(seconds=1); service.activate(subscriber(expiry), idempotency_key="k1", operation_id="op1"); results = service.expire(now=expiry + timedelta(seconds=1))
    assert results[0].reason == "expired"; assert results[0].authorized is False; assert store.read()["subscribers"][0]["state"] == "deactivated"
def test_activation_rejects_disabled_tenant(tmp_path):
    service, store = lifecycle(tmp_path); current = store.read(); current["tenants"][0]["admin_state"] = "disabled"; store.write(current)
    with pytest.raises(ValueError, match="missing or disabled"): service.activate(subscriber(datetime.now(timezone.utc) + timedelta(minutes=5)), idempotency_key="k1", operation_id="op1")


def test_idempotency_key_conflict_is_rejected(tmp_path):
    service, _ = lifecycle(tmp_path)
    first = subscriber(datetime.now(timezone.utc) + timedelta(minutes=5))
    service.activate(first, idempotency_key="same-key", operation_id="op1")
    first["subscriber_id"] = "different-user"
    with pytest.raises(ValueError, match="different request"):
        service.activate(first, idempotency_key="same-key", operation_id="op2")

def test_deactivation_requires_session_key(tmp_path):
    service, _ = lifecycle(tmp_path)
    with pytest.raises(ValueError, match="session_key is required"):
        service.deactivate("", idempotency_key="k1", operation_id="op1")


def test_activation_rejects_session_key_not_bound_to_tenant_and_ip(tmp_path):
    service, _ = lifecycle(tmp_path)
    value = subscriber(datetime.now(timezone.utc) + timedelta(minutes=5))
    value["session_key"] = "sess-1"  # old Django client sent the portal session UUID
    with pytest.raises(ValueError, match="session_key must equal"):
        service.activate(value, idempotency_key="k1", operation_id="op1")

@pytest.mark.parametrize("address", ["10.9.102.5", "10.9.101.1", "10.9.101.255"])
def test_activation_rejects_address_outside_tenant_subnet(tmp_path, address):
    service, _ = lifecycle(tmp_path)
    value = subscriber(datetime.now(timezone.utc) + timedelta(minutes=5))
    value["private_ipv4"], value["session_key"] = address, f"tenant-1/{address}"
    with pytest.raises(ValueError, match="usable host address"):
        service.activate(value, idempotency_key="k1", operation_id="op1")
