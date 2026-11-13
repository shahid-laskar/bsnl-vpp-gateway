from datetime import datetime, timedelta, timezone
import pytest
from controller.store import DesiredStateStore
from controller.subscribers import SubscriberLifecycle
def base_state():
    return {"schema_version": 2, "gateway_id": "lab-vpp-01", "gateway_revision": 1, "tenants": [{"tenant_key": "tenant-1", "admin_state": "enabled"}], "subscribers": []}
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
