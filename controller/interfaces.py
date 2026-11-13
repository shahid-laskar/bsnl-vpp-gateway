"""Tenant QinQ sub-interface planning and VPP reconciliation (plan Phase 4).

Fixes from the 2026-11-13 audit (C-6):
- discovery is keyed per tenant by (parent, outer VLAN, inner VLAN); several
  tenants on one port no longer collapse into one;
- sub-interface ids are deterministic per (outer, inner), so two tenants with
  the same inner VLAN under different outer VLANs cannot collide;
- ``ingress_port`` names (``access0``) are mapped to VPP interface names
  through a port map (``config/lab/topology.yaml``);
- ``ensure`` verifies and repairs table, address, MTU, admin state and tag on
  existing sub-interfaces and issues no write when they already converge;
- objects are tagged ``bsnl:...``; only tagged objects are ever deleted.
"""
from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass
from typing import Any

SUB_IF_TWO_TAGS, SUB_IF_DOT1AD, SUB_IF_EXACT_MATCH = 4, 8, 16
IF_ADMIN_UP = 1
TAG_PREFIX = "bsnl:"
MAX_TAG = 63


class InterfaceValidationError(ValueError):
    pass


@dataclass(frozen=True)
class InterfacePlan:
    tenant_key: str
    parent_interface: str
    outer_tpid: str
    outer_vlan: int
    inner_vlan: int
    vrf_id: int
    gateway_prefix: str
    mtu: int
    isolation: str

    @property
    def object_key(self) -> str:
        return f"interface/{self.tenant_key}"

    @property
    def tag_key(self) -> str:
        return f"{self.parent_interface}/{self.outer_tpid}/{self.outer_vlan}/{self.inner_vlan}"

    @property
    def sub_id(self) -> int:
        # Unique per (outer, inner) on a parent; fits the u32 sub_id.
        return self.outer_vlan * 4096 + self.inner_vlan

    @property
    def vpp_tag(self) -> str:
        tag = TAG_PREFIX + self.object_key
        if len(tag) <= MAX_TAG:
            return tag
        return TAG_PREFIX + "interface/" + hashlib.sha256(self.tenant_key.encode()).hexdigest()[:40]


def interface_plan(tenant: dict[str, Any], port_map: dict[str, str] | None = None) -> InterfacePlan:
    required = ("tenant_key", "ingress_port", "outer_tpid", "outer_vlan", "inner_vlan", "gateway_ip")
    missing = [key for key in required if tenant.get(key) in (None, "")]
    if missing:
        raise InterfaceValidationError(f"tenant missing interface fields: {', '.join(missing)}")
    if tenant["outer_tpid"] not in ("0x8100", "0x88a8"):
        raise InterfaceValidationError("outer_tpid must be 0x8100 or 0x88a8")
    parent = tenant.get("parent_interface") or (port_map or {}).get(tenant["ingress_port"]) or tenant["ingress_port"]
    if not isinstance(parent, str) or not parent:
        raise InterfaceValidationError("parent_interface must be non-empty")
    if tenant.get("exact_match", True) is not True:
        raise InterfaceValidationError("Phase 4 requires exact_match=true")
    for field in ("outer_vlan", "inner_vlan"):
        value = tenant[field]
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 4094:
            raise InterfaceValidationError(f"{field} must be an integer from 1 to 4094")
    mtu = tenant.get("mtu", 1500)
    if isinstance(mtu, bool) or not isinstance(mtu, int) or not 576 <= mtu <= 9216:
        raise InterfaceValidationError("mtu must be between 576 and 9216")
    vrf_id = tenant.get("vrf_id", 0)
    if isinstance(vrf_id, bool) or not isinstance(vrf_id, int) or vrf_id < 0:
        raise InterfaceValidationError("vrf_id must be a non-negative integer")
    try:
        gateway = ipaddress.ip_interface(tenant["gateway_ip"])
    except ValueError as exc:
        raise InterfaceValidationError("gateway_ip must be an IPv4 interface prefix") from exc
    if gateway.version != 4:
        raise InterfaceValidationError("Phase 4 supports IPv4 subscriber interfaces only")
    isolation = tenant.get("intra_tenant_policy", "block")
    if isolation not in ("block", "allow"):
        raise InterfaceValidationError("intra_tenant_policy must be block or allow")
    return InterfacePlan(tenant["tenant_key"], parent, tenant["outer_tpid"], tenant["outer_vlan"], tenant["inner_vlan"], vrf_id, str(gateway), mtu, isolation)


def interface_plans(desired_state: dict[str, Any], port_map: dict[str, str] | None = None) -> list[InterfacePlan]:
    plans = [interface_plan(t, port_map) for t in desired_state.get("tenants", []) if t.get("admin_state", "enabled") == "enabled"]
    seen: dict[tuple[str, int, int], str] = {}
    for plan in plans:
        # VPP matches sub-interfaces on (parent, outer, inner) regardless of TPID.
        context = (plan.parent_interface, plan.outer_vlan, plan.inner_vlan)
        if context in seen and seen[context] != plan.tenant_key:
            raise InterfaceValidationError(f"duplicate QinQ context: {plan.tag_key}")
        seen[context] = plan.tenant_key
    return sorted(plans, key=lambda item: item.tenant_key)


def phase4_object_keys(desired_state: dict[str, Any], port_map: dict[str, str] | None = None) -> list[str]:
    keys = []
    for plan in interface_plans(desired_state, port_map):
        keys.extend((plan.object_key, f"{plan.object_key}/address", f"{plan.object_key}/vrf"))
    return keys


def _text(value: Any) -> str:
    return value.decode().rstrip("\x00") if isinstance(value, bytes) else str(value or "").rstrip("\x00")


class VppInterfaceProvisioner:
    """Converge VPP tenant sub-interfaces to the desired plans.

    Writes only happen with ``enable_writes=True``. ``writes`` counts mutating
    API calls of the last ``apply`` (P3 acceptance: a second apply of the same
    desired state makes zero writes).
    """

    MUTATING = frozenset({"create_subif", "delete_subif", "sw_interface_set_mtu", "sw_interface_set_table",
                          "sw_interface_add_del_address", "sw_interface_set_flags", "sw_interface_tag_add_del",
                          "ip_table_add_del_v2"})

    def __init__(self, client: Any, enable_writes: bool = False, port_map: dict[str, str] | None = None) -> None:
        self.client = client
        self.enable_writes = enable_writes
        self.port_map = port_map or {}
        self.writes: list[str] = []
        self.indexes: dict[str, int] = {}

    # Planning / observation --------------------------------------------------------------
    def observe(self) -> dict[str, Any]:
        interfaces = list(self._dump())
        by_index = {int(i.sw_if_index): i for i in interfaces}
        observed = []
        for item in interfaces:
            if int(getattr(item, "sub_number_of_tags", 0)) != 2:
                continue
            parent = by_index.get(int(getattr(item, "sup_sw_if_index", -1)))
            observed.append({
                "sw_if_index": int(item.sw_if_index),
                "name": _text(item.interface_name),
                "parent": _text(parent.interface_name) if parent is not None else None,
                "outer_vlan": int(item.sub_outer_vlan_id),
                "inner_vlan": int(item.sub_inner_vlan_id),
                "exact_match": bool(int(item.sub_if_flags) & SUB_IF_EXACT_MATCH),
                "dot1ad": bool(int(item.sub_if_flags) & SUB_IF_DOT1AD),
                "admin_up": bool(int(item.flags) & IF_ADMIN_UP),
                "tag": _text(getattr(item, "tag", "")),
            })
        return {"qinq_subinterfaces": observed}

    def apply(self, desired_state: dict[str, Any]) -> list[str]:
        plans = interface_plans(desired_state, self.port_map)
        self.writes = []
        if not self.enable_writes:
            return phase4_object_keys(desired_state, self.port_map)
        existing = self.discover(plans)
        self.indexes = {plan.tenant_key: self.ensure(plan, existing.get(plan.tenant_key)) for plan in plans}
        self.remove_orphans(plans)
        return phase4_object_keys(desired_state, self.port_map)

    def discover(self, plans: list[InterfacePlan]) -> dict[str, int]:
        interfaces = list(self._dump())
        parents = {name: self._index_of(interfaces, name) for name in {p.parent_interface for p in plans}}
        wanted = {(parents[p.parent_interface], p.outer_vlan, p.inner_vlan): p for p in plans}
        found: dict[str, int] = {}
        for item in interfaces:
            if int(getattr(item, "sub_number_of_tags", 0)) != 2:
                continue
            key = (int(item.sup_sw_if_index), int(item.sub_outer_vlan_id), int(item.sub_inner_vlan_id))
            plan = wanted.get(key)
            if plan is None:
                continue
            flags = int(item.sub_if_flags)
            if flags & SUB_IF_EXACT_MATCH == 0 or bool(flags & SUB_IF_DOT1AD) != (plan.outer_tpid == "0x88a8"):
                raise RuntimeError(f"existing QinQ interface for {plan.tenant_key} is not exact-match/TPID compatible; refusing to adopt it")
            found[plan.tenant_key] = int(item.sw_if_index)
        return found

    # Convergence -------------------------------------------------------------------------
    def ensure(self, plan: InterfacePlan, index: int | None) -> int:
        if not self.enable_writes:
            raise RuntimeError("VPP writes are disabled")
        if index is None:
            parent = self._index_of(list(self._dump()), plan.parent_interface)
            flags = SUB_IF_TWO_TAGS | SUB_IF_EXACT_MATCH | (SUB_IF_DOT1AD if plan.outer_tpid == "0x88a8" else 0)
            reply = self._write("create_subif", sw_if_index=parent, sub_id=plan.sub_id, sub_if_flags=flags,
                                outer_vlan_id=plan.outer_vlan, inner_vlan_id=plan.inner_vlan)
            index = int(reply.sw_if_index)
        current = next(iter(self._dump(index)), None)
        if current is None:
            raise RuntimeError(f"sub-interface {index} for {plan.tenant_key} vanished")
        if _text(getattr(current, "tag", "")) != plan.vpp_tag:
            self._write("sw_interface_tag_add_del", is_add=True, sw_if_index=index, tag=plan.vpp_tag)
        if list(getattr(current, "mtu", []) or [])[:1] != [plan.mtu]:
            self._write("sw_interface_set_mtu", sw_if_index=index, mtu=[plan.mtu, 0, 0, 0])
        if int(self._call("sw_interface_get_table", sw_if_index=index, is_ipv6=False).vrf_id) != plan.vrf_id:
            self._ensure_table(plan.vrf_id)
            # Changing the table flushes addresses, so re-read them afterwards.
            self._write("sw_interface_set_table", sw_if_index=index, is_ipv6=False, vrf_id=plan.vrf_id)
        addresses = {str(ipaddress.ip_interface(str(a.prefix))) for a in self._call("ip_address_dump", sw_if_index=index, is_ipv6=False)}
        wanted = str(ipaddress.ip_interface(plan.gateway_prefix))
        for stale in sorted(addresses - {wanted}):
            self._write("sw_interface_add_del_address", sw_if_index=index, is_add=False, del_all=False, prefix=stale)
        if wanted not in addresses:
            self._write("sw_interface_add_del_address", sw_if_index=index, is_add=True, del_all=False, prefix=wanted)
        if not int(current.flags) & IF_ADMIN_UP:
            self._write("sw_interface_set_flags", sw_if_index=index, flags=IF_ADMIN_UP)
        return index

    def remove_orphans(self, plans: list[InterfacePlan]) -> None:
        """Delete sub-interfaces this controller tagged that are no longer desired."""
        wanted_tags = {p.vpp_tag for p in plans}
        for item in self._dump():
            tag = _text(getattr(item, "tag", ""))
            if tag.startswith(TAG_PREFIX + "interface/") and tag not in wanted_tags:
                self._write("delete_subif", sw_if_index=int(item.sw_if_index))

    def _ensure_table(self, vrf_id: int) -> None:
        if vrf_id == 0:
            return
        tables = {int(t.table.table_id) for t in self._call("ip_table_dump") if not getattr(t.table, "is_ip6", False)}
        if vrf_id not in tables:
            self._write("ip_table_add_del_v2", table={"table_id": vrf_id, "is_ip6": False, "name": f"bsnl-vrf-{vrf_id}"}, create_mfib=True, is_add=True)

    # API plumbing ------------------------------------------------------------------------
    def _dump(self, sw_if_index: int | None = None):
        if sw_if_index is None:
            return self._call("sw_interface_dump")
        return self._call("sw_interface_dump", sw_if_index=sw_if_index)

    @staticmethod
    def _index_of(interfaces: list[Any], name: str) -> int:
        matches = [i for i in interfaces if _text(i.interface_name) == name]
        if len(matches) != 1:
            raise RuntimeError(f"expected one VPP interface named {name!r}, found {len(matches)}")
        return int(matches[0].sw_if_index)

    def _write(self, method: str, **kwargs: Any) -> Any:
        if not self.enable_writes:
            raise RuntimeError("VPP writes are disabled")
        self.writes.append(method)
        return self._call(method, **kwargs)

    def _call(self, method: str, **kwargs: Any) -> Any:
        fn = getattr(self.client, method, None)
        if fn is None:
            raise RuntimeError(f"VPP API lacks {method}")
        result = fn(**kwargs)
        retval = int(getattr(result, "retval", 0) or 0)
        if retval:
            raise RuntimeError(f"{method} failed with retval={retval}")
        return result
