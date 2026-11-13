from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .keys import desired_object_keys
from .interfaces import phase4_object_keys
from .validation import validate_desired_state


class DataplaneAdapter(Protocol):
    def observed_state(self) -> dict[str, Any]: ...
    def apply(self, desired_state: dict[str, Any]) -> list[str]: ...
    def capabilities(self) -> dict[str, Any]: ...


@dataclass
class ReconcileResult:
    changed_objects: list[str]
    observed_state: dict[str, Any]
    desired_object_keys: list[str]


class LabAdapter:
    """Safe Phase 3 adapter: validates and plans, but performs no VPP writes."""

    def observed_state(self) -> dict[str, Any]:
        return {"mode": "lab-dry-run", "vpp_connected": False, "objects": []}

    def capabilities(self) -> dict[str, Any]:
        return {"mode": "lab-dry-run", "writes_enabled": False, "phase": 4}

    def apply(self, desired_state: dict[str, Any]) -> list[str]:
        validate_desired_state(desired_state)
        return phase4_object_keys(desired_state)


def reconcile(adapter: DataplaneAdapter, desired_state: dict[str, Any]) -> ReconcileResult:
    validate_desired_state(desired_state)
    changed = adapter.apply(desired_state)
    return ReconcileResult(changed, adapter.observed_state(), desired_object_keys(desired_state))
