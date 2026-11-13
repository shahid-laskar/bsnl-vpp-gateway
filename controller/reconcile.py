from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any, Protocol

from .keys import desired_object_keys
from .interfaces import phase4_object_keys
from .store import DesiredStateStore
from .subscribers import SubscriberLifecycle
from .validation import validate_desired_state

LOG = logging.getLogger("bsnl_vpp.reconcile")


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
    """Dry-run adapter: validates and plans, performs no VPP access at all."""

    def observed_state(self) -> dict[str, Any]:
        return {"mode": "lab-dry-run", "vpp_connected": False, "objects": []}

    def capabilities(self) -> dict[str, Any]:
        return {"mode": "lab-dry-run", "writes_enabled": False, "subscriber_policy_enforced": False, "phase": 4}

    def apply(self, desired_state: dict[str, Any]) -> list[str]:
        validate_desired_state(desired_state)
        return phase4_object_keys(desired_state)


def reconcile(adapter: DataplaneAdapter, desired_state: dict[str, Any]) -> ReconcileResult:
    validate_desired_state(desired_state)
    changed = adapter.apply(desired_state)
    return ReconcileResult(changed, adapter.observed_state(), desired_object_keys(desired_state))


class Reconciler:
    """Periodic loop (P3-T6): expire subscribers locally, prune idempotency
    records and re-apply desired state (which also restores VPP objects after a
    VPP restart when writes are enabled). Errors are logged; the loop never dies.
    """

    def __init__(self, store: DesiredStateStore, lifecycle: SubscriberLifecycle, adapter: DataplaneAdapter, interval_seconds: float = 30.0) -> None:
        self.store, self.lifecycle, self.adapter = store, lifecycle, adapter
        self.interval = interval_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.runs = 0
        self.last_error: str | None = None

    def run_once(self) -> dict[str, Any]:
        summary: dict[str, Any] = {"expired": 0, "pruned": 0, "applied": False}
        try:
            summary["expired"] = len(self.lifecycle.expire())
            summary["pruned"] = self.store.prune_idempotency()
            state = self.store.read()
            if state:
                self.adapter.apply(state)
                summary["applied"] = True
                summary["writes"] = list(getattr(self.adapter, "last_apply_writes", []) or [])
            self.last_error = None
        except Exception as exc:  # keep reconciling on the next tick
            self.last_error = f"{type(exc).__name__}: {exc}"
            LOG.error("reconcile run failed: %s", self.last_error)
            summary["error"] = self.last_error
        self.runs += 1
        if summary.get("expired") or summary.get("writes"):
            LOG.info("reconcile: %s", summary)
        return summary

    def start(self) -> None:
        def loop() -> None:
            while not self._stop.wait(self.interval):
                self.run_once()
        self._thread = threading.Thread(target=loop, name="bsnl-reconciler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
