import json
import os
import hashlib
import hmac
import time
import threading
from http.client import HTTPConnection

from controller.api import SubscriberApiServer
from controller.store import DesiredStateStore


def make_server(tmp_path, monkeypatch):
    store = DesiredStateStore(tmp_path / "desired.json")
    store.write({
        "schema_version": 2,
        "gateway_revision": 1,
        "tenants": [{
            "tenant_key": "lab-vpp-01/host-vpp-access/0x8100/200/101",
            "admin_state": "enabled",
        }],
        "subscribers": [],
    })
    monkeypatch.setenv("BSNL_VPP_CONTROLLER_TOKEN", "test-token")
    server = SubscriberApiServer(("127.0.0.1", 0), str(tmp_path / "desired.json"), str(tmp_path / "audit.jsonl"))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def request(server, method, path, body, headers):
    connection = HTTPConnection("127.0.0.1", server.server_port)
    connection.request(method, path, body=json.dumps(body), headers={"Content-Type": "application/json", **headers})
    response = connection.getresponse()
    payload = json.loads(response.read())
    connection.close()
    return response.status, payload


def test_api_requires_token_and_idempotency(tmp_path, monkeypatch):
    server = make_server(tmp_path, monkeypatch)
    status, payload = request(server, "POST", "/v1/subscribers/deactivate", {}, {"Authorization": "Bearer test-token"})
    assert status == 400
    assert payload["error"] == "Idempotency-Key is required"
    server.shutdown()
    server.server_close()


def test_api_rejects_missing_token(tmp_path, monkeypatch):
    monkeypatch.delenv("BSNL_VPP_CONTROLLER_TOKEN", raising=False)
    server = SubscriberApiServer(("127.0.0.1", 0), str(tmp_path / "desired.json"), str(tmp_path / "audit.jsonl"))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    status, payload = request(server, "POST", "/v1/subscribers/deactivate", {}, {})
    assert status == 401
    assert payload["error"] == "unauthorized"
    server.shutdown()
    server.server_close()


def test_api_activates_qualified_lab_subscriber(tmp_path, monkeypatch):
    server = make_server(tmp_path, monkeypatch)
    subscriber = {
        "session_key": "lab-vpp-01/host-vpp-access/0x8100/200/101/10.9.101.5",
        "tenant_key": "lab-vpp-01/host-vpp-access/0x8100/200/101",
        "subscriber_id": "lab-user-1",
        "session_id": "sess-1",
        "private_ipv4": "10.9.101.5",
        "mac": "02:00:00:00:00:01",
        "valid_until": "2099-01-01T00:00:00+00:00",
    }
    headers = {"Authorization": "Bearer test-token", "Idempotency-Key": "portal-event-1"}
    status, payload = request(server, "POST", "/v1/subscribers/activate", {"operation_id": "op-1", "subscriber": subscriber}, headers)
    assert status == 200
    assert payload["authorized"] is True
    assert payload["reason"] == "activated"
    status, payload = request(server, "POST", "/v1/subscribers/activate", {"operation_id": "op-1", "subscriber": subscriber}, headers)
    assert status == 200
    assert payload["changed"] is False
    server.shutdown()
    server.server_close()

def test_api_requires_valid_portal_hmac_and_timestamp(tmp_path, monkeypatch):
    monkeypatch.delenv("BSNL_VPP_CONTROLLER_TOKEN", raising=False)
    secret = "portal-shared-secret"
    monkeypatch.setenv("BSNL_VPP_PORTAL_HMAC_SECRET", secret)
    server = SubscriberApiServer(("127.0.0.1", 0), str(tmp_path / "desired.json"), str(tmp_path / "audit.jsonl"))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    body = {"operation_id": "op-1", "session_key": "unknown"}
    raw = json.dumps(body).encode()
    timestamp = str(int(time.time()))
    message = (timestamp + "\n/v1/subscribers/deactivate\n").encode() + raw
    signature = "sha256=" + hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
    status, payload = request(server, "POST", "/v1/subscribers/deactivate", body, {
        "Idempotency-Key": "portal-hmac-1",
        "X-BSNL-Timestamp": timestamp,
        "X-BSNL-Signature": signature,
    })
    assert status == 200
    assert payload["reason"] == "not_found"
    status, payload = request(server, "POST", "/v1/subscribers/deactivate", body, {
        "Idempotency-Key": "portal-hmac-2",
        "X-BSNL-Timestamp": str(int(time.time()) - 301),
        "X-BSNL-Signature": signature,
    })
    assert status == 401
    server.shutdown()
    server.server_close()
