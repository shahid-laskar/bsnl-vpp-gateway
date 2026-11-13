from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from typing import Any


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


def interface_plan(tenant: dict[str, Any]) -> InterfacePlan:
    required = ("tenant_key", "ingress_port", "outer_tpid", "outer_vlan", "inner_vlan", "vrf_id", "gateway_ip")
    missing = [key for key in required if not tenant.get(key)]
    if missing:
        raise InterfaceValidationError(f"tenant missing interface fields: {', '.join(missing)}")
    if tenant["outer_tpid"] not in ("0x8100", "0x88a8"):
        raise InterfaceValidationError("outer_tpid must be 0x8100 or 0x88a8")
    parent = tenant.get("parent_interface", tenant["ingress_port"])
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
    try:
        gateway = ipaddress.ip_interface(tenant["gateway_ip"])
    except ValueError as exc:
        raise InterfaceValidationError("gateway_ip must be an IPv4 interface prefix") from exc
    if gateway.version != 4:
        raise InterfaceValidationError("Phase 4 supports IPv4 subscriber interfaces only")
    isolation = tenant.get("intra_tenant_policy", "block")
    if isolation not in ("block", "allow"):
        raise InterfaceValidationError("intra_tenant_policy must be block or allow")
    return InterfacePlan(tenant["tenant_key"], parent, tenant["outer_tpid"], tenant["outer_vlan"], tenant["inner_vlan"], int(tenant["vrf_id"]), str(gateway), mtu, isolation)


def interface_plans(desired_state: dict[str, Any]) -> list[InterfacePlan]:
    plans = [interface_plan(t) for t in desired_state.get("tenants", []) if t.get("admin_state", "enabled") == "enabled"]
    seen: dict[str, str] = {}
    for plan in plans:
        if plan.tag_key in seen and seen[plan.tag_key] != plan.tenant_key:
            raise InterfaceValidationError(f"duplicate QinQ context: {plan.tag_key}")
        seen[plan.tag_key] = plan.tenant_key
    return sorted(plans, key=lambda item: item.tenant_key)


def phase4_object_keys(desired_state: dict[str, Any]) -> list[str]:
    keys = []
    for plan in interface_plans(desired_state):
        keys.extend((plan.object_key, f"{plan.object_key}/address", f"{plan.object_key}/vrf"))
    return keys


class VppInterfaceProvisioner:
    """Guarded VPP 26.10 QinQ provisioning; ACL/NAT remain later phases."""

    def __init__(self, client: Any, enable_writes: bool = False) -> None:
        self.client = client
        self.enable_writes = enable_writes
        self._interfaces: dict[str, int] = {}
        self._tables: set[int] = set()
        self._tenant_vrfs: dict[str, int] = {}

    def apply(self, desired_state: dict[str, Any]) -> list[str]:
        plans = interface_plans(desired_state)
        if not self.enable_writes:
            return phase4_object_keys(desired_state)
        self.discover(plans)
        for plan in plans:
            self.ensure(plan)
        return phase4_object_keys(desired_state)

    def discover(self, plans: list[InterfacePlan]) -> dict[str, int]:
        """Load existing exact-match QinQ objects before creating anything."""
        dump = getattr(self.client, "sw_interface_dump", None)
        if dump is None:
            raise RuntimeError("VPP API lacks sw_interface_dump")
        parents = {plan.parent_interface: self._resolve_parent(plan.parent_interface) for plan in plans}
        wanted = {parents[plan.parent_interface]: plan for plan in plans}
        for item in dump():
            parent = int(getattr(item, "sup_sw_if_index", -1))
            if parent not in wanted or int(getattr(item, "sub_number_of_tags", 0)) != 2:
                continue
            plan = wanted[parent]
            if int(getattr(item, "sub_outer_vlan_id", -1)) != plan.outer_vlan or int(getattr(item, "sub_inner_vlan_id", -1)) != plan.inner_vlan:
                continue
            flags = int(getattr(item, "sub_if_flags", 0))
            if flags & 16 == 0 or (plan.outer_tpid == "0x88a8" and flags & 8 == 0):
                raise RuntimeError(f"existing QinQ interface for {plan.tenant_key} is not exact-match/TPID compatible")
            self._interfaces[plan.tenant_key] = int(item.sw_if_index)
        return dict(self._interfaces)

    def ensure(self, plan: InterfacePlan) -> int:
        if not self.enable_writes:
            raise RuntimeError("Phase 4 VPP writes are disabled")
        if plan.tenant_key in self._interfaces:
            return self._interfaces[plan.tenant_key]
        parent = self._resolve_parent(plan.parent_interface)
        flags = 4 | 16  # TWO_TAGS | EXACT_MATCH
        if plan.outer_tpid == "0x88a8":
            flags |= 8  # DOT1AD; 0x8100 uses dot1q outer
        reply = self.client.create_subif(sw_if_index=parent, sub_id=plan.inner_vlan, sub_if_flags=flags, outer_vlan_id=plan.outer_vlan, inner_vlan_id=plan.inner_vlan)
        self._check(reply, "create_subif")
        index = int(reply.sw_if_index)
        self._call("sw_interface_set_mtu", sw_if_index=index, mtu=[plan.mtu] * 4)
        self._ensure_table(plan.vrf_id)
        self._call("sw_interface_set_table", sw_if_index=index, is_ipv6=False, vrf_id=plan.vrf_id)
        prefix = ipaddress.ip_interface(plan.gateway_prefix)
        self._call("sw_interface_add_del_address", sw_if_index=index, is_add=True, del_all=False, prefix={"address": {"ip": {"version": 0, "address": prefix.ip.packed}}, "len": prefix.network.prefixlen})
        self._call("sw_interface_set_flags", sw_if_index=index, flags=1)
        self._interfaces[plan.tenant_key] = index
        self._tenant_vrfs[plan.tenant_key] = plan.vrf_id
        return index

    def delete(self, tenant_key: str) -> None:
        if not self.enable_writes:
            raise RuntimeError("Phase 4 VPP writes are disabled")
        index = self._interfaces.pop(tenant_key, None)
        if index is not None:
            self._call("delete_subif", sw_if_index=index)
        vrf_id = self._tenant_vrfs.pop(tenant_key, None)
        if vrf_id in self._tables and vrf_id not in self._tenant_vrfs.values():
            self._call("ip_table_add_del_v2", table={"table_id": vrf_id, "is_ip6": False, "name": f"bsnl-vpp-vrf-{vrf_id}"}, create_mfib=False, is_add=False)
            self._tables.remove(vrf_id)

    def _ensure_table(self, vrf_id: int) -> None:
        if vrf_id == 0 or vrf_id in self._tables:
            return
        self._call("ip_table_add_del_v2", table={"table_id": vrf_id, "is_ip6": False, "name": f"bsnl-vpp-vrf-{vrf_id}"}, create_mfib=False, is_add=True)
        self._tables.add(vrf_id)

    def _resolve_parent(self, name: str) -> int:
        dump = getattr(self.client, "sw_interface_dump", None)
        if dump is None:
            raise RuntimeError("VPP API lacks sw_interface_dump")
        matches = []
        for item in dump():
            value = getattr(item, "interface_name", b"")
            if isinstance(value, bytes):
                value = value.decode()
            if value == name:
                matches.append(item)
        if len(matches) != 1:
            raise RuntimeError(f"expected one parent interface named {name!r}, found {len(matches)}")
        return int(matches[0].sw_if_index)

    def _call(self, method: str, **kwargs: Any) -> Any:
        fn = getattr(self.client, method, None)
        if fn is None:
            raise RuntimeError(f"VPP API lacks {method}")
        result = fn(**kwargs)
        self._check(result, method)
        return result

    @staticmethod
    def _check(reply: Any, operation: str) -> None:
        retval = int(getattr(reply, "retval", 0))
        if retval:
            raise RuntimeError(f"{operation} failed with retval={retval}")
