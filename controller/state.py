"""Desired-state ownership (remediation step 4, finding C-2).

Topology (gateway identity, tenants, NAT pools, policies, QoS profiles) comes
from the configuration file today and from Django later. Subscribers are
dynamic and only ever change through the API or the expiry reconciler.

At start-up the two are merged. The old behaviour (a config file with a higher
revision *replaced* the whole persisted state) silently dropped every active
subscriber whenever the topology file was edited.
"""
from __future__ import annotations

from typing import Any

from .store import DesiredStateStore, request_hash
from .subscribers import SubscriberLifecycle
from .validation import validate_desired_state

TOPOLOGY_KEYS = ("schema_version", "gateway_id", "tenants", "nat_pools", "policies", "qos_profiles")


def topology_of(state: dict[str, Any] | None) -> dict[str, Any]:
    return {key: (state or {}).get(key) for key in TOPOLOGY_KEYS}


def enabled_tenants(state: dict[str, Any]) -> set[str]:
    return {t["tenant_key"] for t in state.get("tenants") or [] if t.get("admin_state", "enabled") == "enabled"}


def merge_topology(store: DesiredStateStore, configured: dict[str, Any], lifecycle: SubscriberLifecycle) -> dict[str, Any]:
    """Apply the configured topology to the persisted state; keep subscribers.

    Returns the merged state. Bumps ``gateway_revision`` only when the topology
    actually changed, so restarting with an unchanged file is a no-op.
    """
    candidate = {**topology_of(configured), "subscribers": [], "gateway_revision": 0}
    validate_desired_state(candidate)
    with lifecycle._lock, store.transaction() as txn:
        persisted = txn.read()
        if persisted is None:
            state = {**topology_of(configured), "subscribers": [], "gateway_revision": int(configured.get("gateway_revision", 0))}
            state["topology_hash"] = request_hash(topology_of(configured))
            txn.write(state)
            txn.append_audit({"event": "topology.initialised", "actor": "config", "gateway_revision": state["gateway_revision"], "topology_hash": state["topology_hash"]})
            return state
        new_hash = request_hash(topology_of(configured))
        if persisted.get("topology_hash") == new_hash and topology_of(persisted) == topology_of(configured):
            return persisted
        removed = enabled_tenants(persisted) - enabled_tenants(configured)
        state = {**persisted, **topology_of(configured), "topology_hash": new_hash}
        state["gateway_revision"] = max(int(persisted.get("gateway_revision", 0)), int(configured.get("gateway_revision", 0))) + 1
        txn.write(state)
        txn.append_audit({"event": "topology.updated", "actor": "config", "gateway_revision": state["gateway_revision"], "topology_hash": new_hash, "tenants_removed_or_disabled": sorted(removed)})
        if removed:
            lifecycle.deactivate_tenant_subscribers(txn, state, removed, "tenant_removed")
        validate_desired_state(state)
        return state
