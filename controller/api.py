from __future__ import annotations

import hmac
import json
import logging
import os
import ssl
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .contract import CONTRACT_VERSION, ContractError, ReplayCache, validate_request, verify_signature
from .reconcile import LabAdapter
from .store import DesiredStateStore
from .subscribers import StaleEventError, SubscriberLifecycle

LOG = logging.getLogger("bsnl_vpp.api")
MAX_BODY_BYTES = 1024 * 1024
ROUTES = {
    "/v1/subscribers/activate": "activateRequest",
    "/v1/subscribers/deactivate": "deactivateRequest",
}


def peer_names(cert: dict[str, Any] | None) -> set[str]:
    """Subject CN and DNS/URI SANs of a verified client certificate."""
    if not cert:
        return set()
    names = {value for rdn in cert.get("subject", ()) for key, value in rdn if key == "commonName"}
    names.update(value for kind, value in cert.get("subjectAltName", ()) if kind in {"DNS", "URI"})
    return names


class SubscriberApiHandler(BaseHTTPRequestHandler):
    server_version = "bsnl-vpp-controller/0.2"

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _transport_actor(self) -> str | None:
        """Authenticate the caller at the transport layer; return an actor name.

        mTLS: the TLS layer already requires a CA-signed client certificate;
        additionally the certificate CN/SAN must be in
        BSNL_VPP_ALLOWED_CLIENTS when that list is configured.
        Without TLS (tests, local tooling): bearer token.
        """
        getpeercert = getattr(self.connection, "getpeercert", None)
        cert = getpeercert() if getpeercert else None
        if cert:
            names = peer_names(cert)
            allowed = {item.strip() for item in os.environ.get("BSNL_VPP_ALLOWED_CLIENTS", "").split(",") if item.strip()}
            if allowed and not names & allowed:
                return None
            return "cert:" + (sorted(names & allowed or names)[0] if names else "unnamed")
        configured = os.environ.get("BSNL_VPP_CONTROLLER_TOKEN")
        supplied = self.headers.get("Authorization", "")
        if configured and supplied.startswith("Bearer ") and hmac.compare_digest(supplied[7:], configured):
            return "token"
        return None

    def _read_body(self) -> bytes | None:
        raw_length = self.headers.get("Content-Length", "")
        if not raw_length.isdigit() or not 0 < int(raw_length) <= MAX_BODY_BYTES:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "request body must be between 1 byte and 1 MiB"})
            return None
        return self.rfile.read(int(raw_length))

    def do_GET(self) -> None:
        if self.path == "/health":
            self._json(HTTPStatus.OK, {"status": "ok", "contract_version": CONTRACT_VERSION})
            return
        if self.path not in {"/v1/capabilities", "/v1/observed-state"}:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        if self._transport_actor() is None:
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        adapter = self.server.adapter
        payload = adapter.capabilities() if self.path == "/v1/capabilities" else adapter.observed_state()
        self._json(HTTPStatus.OK, {**payload, "contract_version": CONTRACT_VERSION})

    def do_POST(self) -> None:
        definition = ROUTES.get(self.path)
        if definition is None:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        raw = self._read_body()
        if raw is None:
            return
        actor = self._transport_actor()
        if actor is None:
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        secret = os.environ.get("BSNL_VPP_PORTAL_HMAC_SECRET")
        if secret:
            problem = verify_signature(secret, self.headers, "POST", self.path, raw, self.server.replay_cache)
            if problem is not None:
                LOG.warning("rejected portal event from %s: %s", actor, problem)
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                return
        idempotency_key = self.headers.get("Idempotency-Key", "")
        if not idempotency_key or len(idempotency_key) > 256:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Idempotency-Key is required"})
            return
        try:
            body = json.loads(raw)
            validate_request(definition, body)
            lifecycle = self.server.lifecycle
            if definition == "activateRequest":
                result = lifecycle.activate(body["subscriber"], idempotency_key=idempotency_key, operation_id=body["operation_id"], actor=actor)
            else:
                result = lifecycle.deactivate(body["session_key"], idempotency_key=idempotency_key, operation_id=body["operation_id"], reason=body.get("reason", "portal_deactivation"), actor=actor)
        except StaleEventError as exc:
            self._json(HTTPStatus.CONFLICT, {"error": str(exc)})
            return
        except (TypeError, ValueError, KeyError, json.JSONDecodeError, ContractError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return
        # dataplane_enforced: VPP now permits (activate) or no longer permits
        # (deactivate) this subscriber, confirmed by applying desired state
        # immediately. Interface writes alone never make a session usable.
        enforcer = getattr(self.server.adapter, "enforce_subscriber", None)
        enforced = bool(enforcer and enforcer(lifecycle.store.read() or {}, result.session_key, result.authorized))
        self._json(HTTPStatus.OK, {**result.__dict__, "contract_version": CONTRACT_VERSION, "dataplane_enforced": enforced})

    def log_message(self, *_args: Any) -> None:
        return


class SubscriberApiServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], store_path: str, audit_path: str | None = None, *, adapter: Any = None, lifecycle: SubscriberLifecycle | None = None) -> None:
        super().__init__(address, SubscriberApiHandler)
        self.lifecycle = lifecycle or SubscriberLifecycle(DesiredStateStore(store_path, audit_path))
        self.adapter = adapter or LabAdapter()
        self.replay_cache = ReplayCache()


def serve(listen: str = "127.0.0.1", port: int = 8787, store_path: str = "var/controller.sqlite3", audit_path: str | None = "var/audit.jsonl", tls_cert: str | None = None, tls_key: str | None = None, tls_ca: str | None = None, *, adapter: Any = None, lifecycle: SubscriberLifecycle | None = None) -> None:
    server = SubscriberApiServer((listen, port), store_path, audit_path, adapter=adapter, lifecycle=lifecycle)
    if any((tls_cert, tls_key, tls_ca)):
        if not all((tls_cert, tls_key, tls_ca)):
            raise ValueError("tls_cert, tls_key, and tls_ca must be provided together")
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_verify_locations(tls_ca)
        context.load_cert_chain(tls_cert, tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
