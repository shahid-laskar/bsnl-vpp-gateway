from __future__ import annotations
from .interfaces import phase4_object_keys

from typing import Any


def tenant_object_key(tenant: dict[str, Any]) -> str:
    return f"tenant/{tenant['tenant_key']}"


def subscriber_object_key(subscriber: dict[str, Any]) -> str:
    return f"subscriber/{subscriber['session_key']}"


def desired_object_keys(state: dict[str, Any]) -> list[str]:
    keys = [tenant_object_key(item) for item in state.get("tenants", [])]
    keys.extend(subscriber_object_key(item) for item in state.get("subscribers", []))
    keys.extend(phase4_object_keys(state))
    return sorted(keys)
