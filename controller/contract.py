"""Northbound API contract v1: request validation and portal request signing.

The Django client mirrors ``canonical_message``/``sign`` exactly; both repos
test against the golden vectors in ``config/contract/golden/``.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import threading
import time
from functools import lru_cache
from pathlib import Path
from typing import Any

import jsonschema

CONTRACT_VERSION = "v1"
SIGNATURE_PREFIX = "sha256="
DEFAULT_MAX_SKEW_SECONDS = 300
API_SCHEMA = Path(__file__).resolve().parent.parent / "config" / "schema" / "api-v1.schema.json"


class ContractError(ValueError):
    pass


@lru_cache(maxsize=1)
def _schema() -> dict[str, Any]:
    with API_SCHEMA.open(encoding="utf-8") as handle:
        return json.load(handle)


def _validator(definition: str) -> jsonschema.Draft202012Validator:
    schema = {**_schema(), "$ref": f"#/$defs/{definition}"}
    return jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())


def validate_request(definition: str, body: Any) -> None:
    errors = sorted(_validator(definition).iter_errors(body), key=lambda e: list(e.path))
    if errors:
        first = errors[0]
        where = "/".join(str(p) for p in first.path) or "body"
        raise ContractError(f"{where}: {first.message}")


def session_key_for(tenant_key: str, private_ipv4: str) -> str:
    return f"{tenant_key}/{private_ipv4}"


NONCE_RE = re.compile(r"^[0-9a-f]{32,64}$")


def canonical_message(timestamp: str, nonce: str, method: str, path: str, idempotency_key: str, body: bytes) -> bytes:
    """Bytes covered by the portal HMAC.

    Binds a per-request nonce, the timestamp, HTTP method, path and
    Idempotency-Key to a hash of the exact body, so a captured request cannot
    be replayed (nonce), re-targeted (method/path) or re-keyed
    (Idempotency-Key). A legitimate retry carries a fresh nonce and is
    de-duplicated by its Idempotency-Key instead.
    """
    digest = hashlib.sha256(body).hexdigest()
    return "\n".join((CONTRACT_VERSION, timestamp, nonce, method.upper(), path, idempotency_key, digest)).encode()


def sign(secret: str, timestamp: str, nonce: str, method: str, path: str, idempotency_key: str, body: bytes) -> str:
    mac = hmac.new(secret.encode(), canonical_message(timestamp, nonce, method, path, idempotency_key, body), hashlib.sha256)
    return SIGNATURE_PREFIX + mac.hexdigest()


class ReplayCache:
    """Remembers accepted nonces for twice the clock-skew window."""

    def __init__(self, window_seconds: int = DEFAULT_MAX_SKEW_SECONDS) -> None:
        self.window = window_seconds
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def check_and_add(self, nonce: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        with self._lock:
            for key in [k for k, expiry in self._seen.items() if expiry <= now]:
                del self._seen[key]
            if nonce in self._seen:
                return False
            self._seen[nonce] = now + 2 * self.window
            return True


def verify_signature(secret: str, headers: Any, method: str, path: str, body: bytes, replay: ReplayCache, now: float | None = None, max_skew: int = DEFAULT_MAX_SKEW_SECONDS) -> str | None:
    """Return None when valid, otherwise a short reason (never echoes secrets)."""
    timestamp = headers.get("X-BSNL-Timestamp", "")
    nonce = headers.get("X-BSNL-Nonce", "")
    signature = headers.get("X-BSNL-Signature", "")
    if not timestamp.isdigit() or not signature or not NONCE_RE.fullmatch(nonce):
        return "missing or malformed signature headers"
    now = time.time() if now is None else now
    if abs(int(now) - int(timestamp)) > max_skew:
        return "timestamp outside allowed window"
    expected = sign(secret, timestamp, nonce, method, path, headers.get("Idempotency-Key", ""), body)
    if not hmac.compare_digest(signature, expected):
        return "bad signature"
    if not replay.check_and_add(nonce, now):
        return "replayed request"
    return None
