import json
import secrets
import threading
import time
from http.client import HTTPConnection

import pytest

from controller.api import SubscriberApiServer, peer_names
from controller.contract import sign
from controller.store import DesiredStateStore

TENANT = "lab-vpp-01/host-vpp-access/0x8100/200/101"
SECRET = "portal-shared-secret"


@pytest.fixture
def server(tmp_path, monkeypatch):
    store = DesiredStateStore(tmp_path / "state.sqlite3")
    store.write({
        "schema_version": 2,
        "gateway_revision": 1,
        "tenants": [{"tenant_key": TENANT, "admin_state": "enabled", "gateway_ip": "10.9.101.1/24"}],
        "subscribers": [],
    })
    monkeypatch.setenv("BSNL_VPP_CONTROLLER_TOKEN", "test-token")
    monkeypatch.delenv("BSNL_VPP_PORTAL_HMAC_SECRET", raising=False)
    instance = SubscriberApiServer(("127.0.0.1", 0), str(tmp_path / "state.sqlite3"), str(tmp_path / "audit.jsonl"))
    threading.Thread(target=instance.serve_forever, daemon=True).start()
    yield instance
    instance.shutdown()
    instance.server_close()


def raw_request(server, method, path, raw, headers):
    connection = HTTPConnection("127.0.0.1", server.server_port)
    connection.request(method, path, body=raw, headers=headers)
    response = connection.getresponse()
    payload = json.loads(response.read())
    connection.close()
    return response.status, payload


def request(server, method, path, body, headers, signed=False, timestamp=None):
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    headers = {"Content-Type": "application/json", "Authorization": "Bearer test-token", **headers}
    if signed:
        ts = str(int(time.time()) if timestamp is None else timestamp)
        nonce = secrets.token_hex(16)
        headers["X-BSNL-Timestamp"] = ts
        headers["X-BSNL-Nonce"] = nonce
        headers["X-BSNL-Signature"] = sign(SECRET, ts, nonce, method, path, headers.get("Idempotency-Key", ""), raw)
    return raw_request(server, method, path, raw, headers)


def activation(address="10.9.101.5"):
    return {"operation_id": "op-1", "subscriber": {
        "session_key": f"{TENANT}/{address}", "tenant_key": TENANT, "subscriber_id": "lab-user-1",
        "session_id": "sess-1", "private_ipv4": address, "mac": "02:00:00:00:00:01",
        "valid_until": "2099-01-01T00:00:00+00:00",
    }}


def test_api_requires_idempotency_key(server):
    status, payload = request(server, "POST", "/v1/subscribers/deactivate", {"operation_id": "op", "session_key": f"{TENANT}/10.9.101.5"}, {})
    assert status == 400 and payload["error"] == "Idempotency-Key is required"


def test_api_rejects_missing_credentials(server):
    status, payload = raw_request(server, "POST", "/v1/subscribers/deactivate", b"{}", {"Content-Type": "application/json"})
    assert status == 401 and payload["error"] == "unauthorized"


def test_api_rejects_bad_content_length_without_crashing(server):
    connection = HTTPConnection("127.0.0.1", server.server_port)
    connection.putrequest("POST", "/v1/subscribers/activate")
    connection.putheader("Content-Length", "abc")
    connection.endheaders()
    response = connection.getresponse()
    assert response.status == 400
    connection.close()


def test_api_activates_and_reports_dataplane_not_enforced(server):
    headers = {"Idempotency-Key": "portal-event-1"}
    status, payload = request(server, "POST", "/v1/subscribers/activate", activation(), headers)
    assert status == 200
    assert payload["authorized"] is True and payload["reason"] == "activated"
    assert payload["contract_version"] == "v1"
    assert payload["dataplane_enforced"] is False  # adapter is still dry-run
    status, payload = request(server, "POST", "/v1/subscribers/activate", activation(), headers)
    assert status == 200 and payload["changed"] is False


def test_api_rejects_legacy_flat_django_payload(server):
    legacy = {"tenant_key": TENANT, "subscriber_id": "1", "session_id": "s", "private_ipv4": "10.9.101.5", "mac": None, "valid_until": "2099-01-01T00:00:00+00:00"}
    status, payload = request(server, "POST", "/v1/subscribers/activate", legacy, {"Idempotency-Key": "k"})
    assert status == 400 and ("operation_id" in payload["error"] or "subscriber" in payload["error"])


def test_api_rejects_naive_valid_until(server):
    body = activation()
    body["subscriber"]["valid_until"] = "2099-01-01T00:00:00"
    status, _ = request(server, "POST", "/v1/subscribers/activate", body, {"Idempotency-Key": "k-naive"})
    assert status == 400


def test_hmac_is_additive_to_transport_auth(server, monkeypatch):
    monkeypatch.setenv("BSNL_VPP_PORTAL_HMAC_SECRET", SECRET)
    body = {"operation_id": "op-1", "session_key": f"{TENANT}/10.9.101.9"}
    # valid HMAC but no transport credential -> rejected
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ts, nonce = str(int(time.time())), secrets.token_hex(16)
    headers = {"Content-Type": "application/json", "Idempotency-Key": "h-0", "X-BSNL-Timestamp": ts, "X-BSNL-Nonce": nonce,
               "X-BSNL-Signature": sign(SECRET, ts, nonce, "POST", "/v1/subscribers/deactivate", "h-0", raw)}
    assert raw_request(server, "POST", "/v1/subscribers/deactivate", raw, headers)[0] == 401
    # transport credential but no HMAC -> rejected
    assert request(server, "POST", "/v1/subscribers/deactivate", body, {"Idempotency-Key": "h-1"})[0] == 401
    # both -> accepted
    status, payload = request(server, "POST", "/v1/subscribers/deactivate", body, {"Idempotency-Key": "h-2"}, signed=True)
    assert status == 200 and payload["reason"] == "not_found"


def test_hmac_rejects_stale_timestamp_replay_and_rebound_idempotency_key(server, monkeypatch):
    monkeypatch.setenv("BSNL_VPP_PORTAL_HMAC_SECRET", SECRET)
    body = {"operation_id": "op-1", "session_key": f"{TENANT}/10.9.101.9"}
    assert request(server, "POST", "/v1/subscribers/deactivate", body, {"Idempotency-Key": "s-1"}, signed=True, timestamp=int(time.time()) - 301)[0] == 401
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ts, nonce = str(int(time.time())), secrets.token_hex(16)
    signature = sign(SECRET, ts, nonce, "POST", "/v1/subscribers/deactivate", "r-1", raw)
    base = {"Content-Type": "application/json", "Authorization": "Bearer test-token", "X-BSNL-Timestamp": ts, "X-BSNL-Nonce": nonce, "X-BSNL-Signature": signature}
    assert raw_request(server, "POST", "/v1/subscribers/deactivate", raw, {**base, "Idempotency-Key": "r-1"})[0] == 200
    # exact replay of an accepted request
    assert raw_request(server, "POST", "/v1/subscribers/deactivate", raw, {**base, "Idempotency-Key": "r-1"})[0] == 401
    # same signature re-used under a fresh Idempotency-Key
    assert raw_request(server, "POST", "/v1/subscribers/deactivate", raw, {**base, "Idempotency-Key": "r-2"})[0] == 401


def test_get_endpoints_require_auth_except_health(server):
    connection = HTTPConnection("127.0.0.1", server.server_port)
    for path, expected in (("/health", 200), ("/v1/capabilities", 401), ("/v1/observed-state", 401)):
        connection.request("GET", path)
        response = connection.getresponse()
        response.read()
        assert response.status == expected, path
    connection.request("GET", "/v1/capabilities", headers={"Authorization": "Bearer test-token"})
    response = connection.getresponse()
    assert response.status == 200 and json.loads(response.read())["writes_enabled"] is False
    connection.close()


def test_client_certificate_allowlist(server, monkeypatch):
    cert = {"subject": ((("commonName", "bsnl-portal"),),), "subjectAltName": (("DNS", "portal.internal"),)}
    assert peer_names(cert) == {"bsnl-portal", "portal.internal"}
    handler = type("H", (), {})()
    from controller.api import SubscriberApiHandler
    handler.connection = type("C", (), {"getpeercert": lambda self: cert})()
    handler.headers = {}
    monkeypatch.setenv("BSNL_VPP_ALLOWED_CLIENTS", "bsnl-portal")
    assert SubscriberApiHandler._transport_actor(handler) == "cert:bsnl-portal"
    monkeypatch.setenv("BSNL_VPP_ALLOWED_CLIENTS", "someone-else")
    assert SubscriberApiHandler._transport_actor(handler) is None


def test_legitimate_same_second_retry_with_fresh_nonce_is_accepted(server, monkeypatch):
    """Regression: found by the cross-repo E2E run. An identical retry within
    the same second must not be mistaken for a replay; the fresh nonce makes
    it distinct and the Idempotency-Key de-duplicates it."""
    monkeypatch.setenv("BSNL_VPP_PORTAL_HMAC_SECRET", SECRET)
    ts = int(time.time())
    first = request(server, "POST", "/v1/subscribers/activate", activation(), {"Idempotency-Key": "same"}, signed=True, timestamp=ts)
    retry = request(server, "POST", "/v1/subscribers/activate", activation(), {"Idempotency-Key": "same"}, signed=True, timestamp=ts)
    assert first[0] == retry[0] == 200
    assert first[1]["reason"] == "activated" and retry[1]["reason"] == "idempotent_replay"


def test_missing_or_malformed_nonce_is_rejected(server, monkeypatch):
    monkeypatch.setenv("BSNL_VPP_PORTAL_HMAC_SECRET", SECRET)
    raw = json.dumps(activation(), sort_keys=True, separators=(",", ":")).encode()
    ts = str(int(time.time()))
    for nonce in ("", "short", "Z" * 32):
        headers = {"Content-Type": "application/json", "Authorization": "Bearer test-token", "Idempotency-Key": "n",
                   "X-BSNL-Timestamp": ts, "X-BSNL-Nonce": nonce,
                   "X-BSNL-Signature": sign(SECRET, ts, nonce, "POST", "/v1/subscribers/activate", "n", raw)}
        assert raw_request(server, "POST", "/v1/subscribers/activate", raw, headers)[0] == 401, nonce


def test_activation_after_logout_returns_409_and_audit_names_actor(server):
    headers = {"Idempotency-Key": "a-1"}
    assert request(server, "POST", "/v1/subscribers/activate", activation(), headers)[0] == 200
    body = {"operation_id": "op-2", "session_key": f"{TENANT}/10.9.101.5", "reason": "logout"}
    assert request(server, "POST", "/v1/subscribers/deactivate", body, {"Idempotency-Key": "d-1"})[0] == 200
    status, payload = request(server, "POST", "/v1/subscribers/activate", activation(), {"Idempotency-Key": "a-late"})
    assert status == 409 and "already ended" in payload["error"]
    events = server.lifecycle.store.audit_events()
    assert {e["actor"] for e in events if e.get("event", "").startswith("subscriber.")} == {"token"}
