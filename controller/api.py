from __future__ import annotations

import hmac
import json
import os
import ssl
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .reconcile import LabAdapter
from .store import DesiredStateStore
from .subscribers import SubscriberLifecycle


class SubscriberApiHandler(BaseHTTPRequestHandler):
    server_version = "bsnl-vpp-controller/0.1"

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        if getattr(self.connection, "getpeercert", lambda: None)():
            return True
        configured = os.environ.get("BSNL_VPP_CONTROLLER_TOKEN")
        supplied = self.headers.get("Authorization", "")
        return bool(configured and supplied.startswith("Bearer ") and hmac.compare_digest(supplied[7:], configured))

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        value = json.loads(self.rfile.read(length))
        if not isinstance(value, dict):
            raise ValueError("JSON object required")
        return value

    def do_GET(self) -> None:
        if self.path == "/health":
            self._json(HTTPStatus.OK, {"status": "ok", "authorization_required": True})
            return
        if self.path == "/v1/capabilities":
            self._json(HTTPStatus.OK, self.server.adapter.capabilities())
            return
        if self.path == "/v1/observed-state":
            self._json(HTTPStatus.OK, self.server.adapter.observed_state())
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:
        if self.path not in {"/v1/subscribers/activate", "/v1/subscribers/deactivate"}:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        if not self._authorized():
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        idempotency_key = self.headers.get("Idempotency-Key", "")
        if not idempotency_key:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Idempotency-Key is required"})
            return
        try:
            body = self._body()
            operation_id = str(body.get("operation_id", ""))
            if not operation_id:
                raise ValueError("operation_id is required")
            lifecycle = self.server.lifecycle
            if self.path.endswith("/activate"):
                result = lifecycle.activate(body.get("subscriber", {}), idempotency_key=idempotency_key, operation_id=operation_id)
            else:
                result = lifecycle.deactivate(str(body.get("session_key", "")), idempotency_key=idempotency_key, operation_id=operation_id, reason=str(body.get("reason", "portal_deactivation")))
            self._json(HTTPStatus.OK, result.__dict__)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})

    def log_message(self, *_args: Any) -> None:
        return


class SubscriberApiServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], store_path: str, audit_path: str) -> None:
        super().__init__(address, SubscriberApiHandler)
        self.lifecycle = SubscriberLifecycle(DesiredStateStore(store_path), audit_path)
        self.adapter = LabAdapter()


def serve(listen: str = "127.0.0.1", port: int = 8787, store_path: str = "var/controller.sqlite3", audit_path: str = "var/audit.jsonl", tls_cert: str | None = None, tls_key: str | None = None, tls_ca: str | None = None) -> None:
    server = SubscriberApiServer((listen, port), store_path, audit_path)
    if any((tls_cert, tls_key, tls_ca)):
        if not all((tls_cert, tls_key, tls_ca)):
            raise ValueError("tls_cert, tls_key, and tls_ca must be provided together")
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(tls_ca)
        context.load_cert_chain(tls_cert, tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
