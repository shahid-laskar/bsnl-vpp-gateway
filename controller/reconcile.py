from __future__ import annotations

import logging
import threading
import time
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

    A second, fast loop (``watch_interval``, 1 s) pings VPP through the
    adapter. When the adapter reports a new connection (VPP restarted) it
    re-applies desired state as soon as the adapter allows writes again,
    instead of leaving authenticated subscribers on VPP's static pre-auth ACL
    until the next periodic tick (up to 30 s, measured 2026-11-16).
    """

    def __init__(self, store: DesiredStateStore, lifecycle: SubscriberLifecycle, adapter: DataplaneAdapter, interval_seconds: float = 30.0,
                 dns_views: Any = None, watch_interval: float = 1.0) -> None:
        self.store, self.lifecycle, self.adapter = store, lifecycle, adapter
        self.dns_views = dns_views
        self.interval = interval_seconds
        self.watch_interval = watch_interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._watch_thread: threading.Thread | None = None
        self._run_lock = threading.Lock()  # periodic tick and restart recovery never overlap
        self._generation = 0
        self._recovering_since: float | None = None
        self.runs = 0
        self.recoveries = 0
        self.last_error: str | None = None

    def run_once(self) -> dict[str, Any]:
        with self._run_lock:
            return self._run_once()

    def _run_once(self) -> dict[str, Any]:
        summary: dict[str, Any] = {"expired": 0, "pruned": 0, "applied": False}
        try:
            summary["expired"] = len(self.lifecycle.expire())
            summary["pruned"] = self.store.prune_idempotency()
            state = self.store.read()
            if state:
                self.adapter.apply(state)
                summary["applied"] = True
                summary["writes"] = list(getattr(self.adapter, "last_apply_writes", []) or [])
                if self.dns_views is not None:
                    summary["dns_reloaded"] = self.dns_views.sync(state)
            self.last_error = None
        except Exception as exc:  # keep reconciling on the next tick
            if getattr(exc, "startup_pending", False):  # VPP still starting; the watch loop retries in 1 s
                summary["startup_pending"] = True
                self.runs += 1
                return summary
            self.last_error = f"{type(exc).__name__}: {exc}"
            LOG.error("reconcile run failed: %s", self.last_error)
            summary["error"] = self.last_error
        self.runs += 1
        if summary.get("expired") or summary.get("writes"):
            LOG.info("reconcile: %s", summary)
        return summary

    def watch_once(self) -> dict[str, Any] | None:
        """One liveness check; re-applies after a (re)connect when writes are on.
        Returns the run_once summary when it ran, else None."""
        liveness = getattr(self.adapter, "liveness", None)
        if liveness is None:
            return None
        generation = liveness()
        if generation != self._generation:
            if generation:
                LOG.info("VPP connection %d established; re-applying desired state once VPP startup has finished", generation)
                self._recovering_since = time.monotonic()
            self._generation = generation
        if self._recovering_since is None:
            return None
        if not getattr(self.adapter, "enable_writes", False):
            self._recovering_since = None  # observe mode: reconnecting was all there was to do
            return None
        summary = self.run_once()
        if summary.get("applied") and "error" not in summary:
            self.recoveries += 1
            LOG.info("restart recovery: desired state re-applied %.1f s after reconnect (writes: %s)",
                     time.monotonic() - self._recovering_since, summary.get("writes"))
            self._recovering_since = None
        return summary

    def start(self) -> None:
        def loop() -> None:
            while not self._stop.wait(self.interval):
                self.run_once()

        def watch() -> None:
            while not self._stop.wait(self.watch_interval):
                try:
                    self.watch_once()
                except Exception as exc:  # never let the watch loop die
                    LOG.error("VPP watch failed: %s: %s", type(exc).__name__, exc)
        self._thread = threading.Thread(target=loop, name="bsnl-reconciler", daemon=True)
        self._thread.start()
        if hasattr(self.adapter, "liveness") and self.watch_interval > 0:
            self._watch_thread = threading.Thread(target=watch, name="bsnl-vpp-watch", daemon=True)
            self._watch_thread.start()

    def stop(self) -> None:
        self._stop.set()
        for thread in (self._thread, self._watch_thread):
            if thread is not None:
                thread.join(timeout=5)
