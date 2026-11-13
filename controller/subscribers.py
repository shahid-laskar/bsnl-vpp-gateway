from __future__ import annotations
import ipaddress, json, re
import threading
from functools import wraps
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from .store import DesiredStateStore, request_hash
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", re.IGNORECASE)
ACTIVE_STATE = "authenticated"
INACTIVE_STATES = frozenset({"deactivated", "expired"})

def synchronized(method):
    @wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return wrapper
@dataclass(frozen=True)
class LifecycleResult:
    operation_id: str
    idempotency_key: str
    gateway_revision: int
    changed: bool
    authorized: bool
    session_key: str
    reason: str
class SubscriberLifecycle:
    """Fail-closed, idempotent subscriber state transitions. Control-plane state only."""
    def __init__(self, store: DesiredStateStore, audit_path: str | Path) -> None:
        self.store, self.audit_path = store, Path(audit_path)
        self._lock = threading.RLock()
    @synchronized
    def activate(self, subscriber: dict[str, Any], *, idempotency_key: str, operation_id: str, now: datetime | None = None) -> LifecycleResult:
        self._validate(subscriber); now = now or datetime.now(timezone.utc)
        fingerprint = request_hash({"operation": "activate", "subscriber": subscriber})
        replay = self._replay(idempotency_key, fingerprint, subscriber["session_key"], operation_id)
        if replay is not None:
            return replay
        expiry = self._parse_expiry(subscriber.get("valid_until"))
        if expiry is None or expiry <= now: raise ValueError("authenticated subscriber requires a future valid_until")
        state = self.store.read() or {}; self._validate_tenant(state, subscriber["tenant_key"])
        items = state.setdefault("subscribers", [])
        existing = next((x for x in items if x.get("session_key") == subscriber["session_key"]), None)
        if existing is not None and existing.get("state") == ACTIVE_STATE and all(existing.get(k) == v for k, v in subscriber.items()):
            result = self._result(state, subscriber["session_key"], idempotency_key, operation_id, False, True, "already_active"); self._audit(result); self.store.put_idempotency(idempotency_key, fingerprint, result.__dict__); return result
        value = {**subscriber, "state": ACTIVE_STATE}
        if existing is None: items.append(value)
        else: existing.clear(); existing.update(value)
        state["gateway_revision"] = int(state.get("gateway_revision", 0)) + 1; self.store.write(state)
        result = self._result(state, value["session_key"], idempotency_key, operation_id, True, True, "activated"); self._audit(result); self.store.put_idempotency(idempotency_key, fingerprint, result.__dict__); return result
    @synchronized
    def deactivate(self, session_key: str, *, idempotency_key: str, operation_id: str, reason: str = "portal_deactivation") -> LifecycleResult:
        if not session_key:
            raise ValueError("session_key is required")
        fingerprint = request_hash({"operation": "deactivate", "session_key": session_key, "reason": reason})
        replay = self._replay(idempotency_key, fingerprint, session_key, operation_id)
        if replay is not None:
            return replay
        state = self.store.read() or {}; items = state.setdefault("subscribers", [])
        existing = next((x for x in items if x.get("session_key") == session_key), None)
        if existing is None:
            result = self._result(state, session_key, idempotency_key, operation_id, False, False, "not_found"); self._audit(result); self.store.put_idempotency(idempotency_key, fingerprint, result.__dict__); return result
        if existing.get("state") in INACTIVE_STATES:
            result = self._result(state, session_key, idempotency_key, operation_id, False, False, "already_inactive"); self._audit(result); self.store.put_idempotency(idempotency_key, fingerprint, result.__dict__); return result
        existing["state"], existing["valid_until"] = "deactivated", None
        state["gateway_revision"] = int(state.get("gateway_revision", 0)) + 1; self.store.write(state)
        result = self._result(state, session_key, idempotency_key, operation_id, True, False, reason); self._audit(result); self.store.put_idempotency(idempotency_key, fingerprint, result.__dict__); return result
    def _replay(self, key: str, fingerprint: str, session_key: str, operation_id: str) -> LifecycleResult | None:
        if not key:
            raise ValueError("idempotency_key is required")
        record = self.store.get_idempotency(key)
        if record is None:
            return None
        if record["request_hash"] != fingerprint:
            raise ValueError("idempotency key was already used for a different request")
        saved = json.loads(record["result"])
        result = LifecycleResult(operation_id, key, saved["gateway_revision"], False, saved["authorized"], session_key, "idempotent_replay")
        self._audit(result)
        return result

    @synchronized
    def expire(self, *, now: datetime | None = None, operation_id: str = "expiry-reconciler") -> list[LifecycleResult]:
        now = now or datetime.now(timezone.utc); state = self.store.read() or {}; results = []
        for item in list(state.get("subscribers", [])):
            expiry = self._parse_expiry(item.get("valid_until"))
            if item.get("state") == ACTIVE_STATE and expiry is not None and expiry <= now:
                results.append(self.deactivate(item["session_key"], idempotency_key=f"expire:{item['session_key']}:{expiry.isoformat()}", operation_id=operation_id, reason="expired"))
        return results
    @staticmethod
    def _validate(subscriber: dict[str, Any]) -> None:
        required = ("session_key", "tenant_key", "subscriber_id", "private_ipv4"); missing = [key for key in required if not subscriber.get(key)]
        if missing: raise ValueError(f"missing subscriber fields: {', '.join(missing)}")
        ipaddress.ip_address(subscriber["private_ipv4"])
        if subscriber.get("mac") and not MAC_RE.fullmatch(subscriber["mac"]): raise ValueError("mac must be a colon-separated six-octet address")
    @staticmethod
    def _validate_tenant(state: dict[str, Any], tenant_key: str) -> None:
        if not any(x.get("tenant_key") == tenant_key and x.get("admin_state") == "enabled" for x in state.get("tenants", [])): raise ValueError("subscriber tenant is missing or disabled")
    @staticmethod
    def _parse_expiry(value: Any) -> datetime | None:
        if not value: return None
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00")); return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    @staticmethod
    def _result(state: dict[str, Any], session_key: str, idem: str, operation_id: str, changed: bool, authorized: bool, reason: str) -> LifecycleResult:
        return LifecycleResult(operation_id, idem, int(state.get("gateway_revision", 0)), changed, authorized, session_key, reason)
    def _audit(self, result: LifecycleResult) -> None:
        if getattr(self.store, "sqlite", False):
            self.store.append_audit(result.__dict__)
            return
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_path.open("a", encoding="utf-8") as handle: handle.write(json.dumps(result.__dict__, sort_keys=True) + "\n")
