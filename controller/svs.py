"""Per-subscriber authorization with Source VRF Select (D-09 candidate A, ADR-017).

The tenant sub-interface sits in a captive VRF (``tenant.vrf_id``) that only
routes to the portal, the resolver and the redirector host. An SVS table is
enabled on the sub-interface; each authenticated subscriber gets one entry
``<ip>/32 -> lookup in the internet VRF`` (``policy.internet_vrf``, lab 0).
A source without an entry falls through to the captive VRF (R-11, verified
2026-11-17). One API call per login, independent of the number of
subscribers (D-09 measurement in ADR-010).

The controller owns: the SVS FIB table (``tenant.svs_table_id``), its
enablement on the tenant sub-interface and the /32 entries in it. The captive
VRF's routes, the cross-VRF return route and the DHCP proxy are lab fixture
(``deployment/vpp/bsnl-lab.cli``).
"""
from __future__ import annotations

import ipaddress
from typing import Any

from .policy import PolicyValidationError

AF_IP4 = 0


def svs_config(tenant: dict[str, Any], policy: dict[str, Any]) -> tuple[int, int]:
    """(svs_table_id, internet_vrf) for an SVS tenant; validates the VRF split."""
    if "svs_table_id" not in tenant:
        raise PolicyValidationError(f"tenant {tenant['tenant_key']}: authorization=svs needs svs_table_id")
    table, internet = int(tenant["svs_table_id"]), int(policy.get("internet_vrf", 0))
    captive = int(tenant.get("vrf_id", 0))
    if captive == internet:
        # The static tenant ACL permits authenticated destinations for every
        # source; only the VRF split keeps unauthenticated sources out.
        raise PolicyValidationError(f"tenant {tenant['tenant_key']}: authorization=svs needs a captive vrf_id different from internet_vrf {internet}")
    if table in (captive, internet):
        raise PolicyValidationError(f"tenant {tenant['tenant_key']}: svs_table_id must differ from the captive and internet VRFs")
    return table, internet


def authenticated(tenant: dict[str, Any], subscribers: list[dict[str, Any]]) -> set[str]:
    subnet = ipaddress.ip_interface(tenant["gateway_ip"]).network
    out = set()
    for s in subscribers:
        if s.get("tenant_key") == tenant["tenant_key"] and s.get("state") == "authenticated":
            if ipaddress.ip_address(s["private_ipv4"]) not in subnet:
                raise PolicyValidationError(f"subscriber {s['private_ipv4']} outside tenant subnet {subnet}")
            out.add(s["private_ipv4"])
    return out


class SvsEnforcer:
    MUTATING = frozenset({"ip_table_add_del_v2", "svs_table_add_del", "svs_enable_disable", "svs_route_add_del"})

    def __init__(self, call: Any, write: Any) -> None:
        self._call, self._write = call, write

    def apply(self, tenant: dict[str, Any], policy: dict[str, Any], sw_if_index: int,
              subscribers: list[dict[str, Any]]) -> set[str]:
        table, internet = svs_config(tenant, policy)
        enabled = self._enabled(sw_if_index)
        if enabled is not None and enabled != table:
            self.remove(sw_if_index)
            enabled = None
        if enabled is None:
            tables = {int(t.table.table_id) for t in self._call("ip_table_dump") if not getattr(t.table, "is_ip6", False)}
            if table not in tables:
                self._write("ip_table_add_del_v2", table={"table_id": table, "is_ip6": False, "name": f"bsnl-svs-{table}"},
                            create_mfib=False, is_add=True)
            self._write("svs_table_add_del", is_add=True, af=AF_IP4, table_id=table)
            self._write("svs_enable_disable", is_enable=True, af=AF_IP4, table_id=table, sw_if_index=sw_if_index)
        subnet = ipaddress.ip_interface(tenant["gateway_ip"]).network
        want = authenticated(tenant, subscribers)
        have = self.entries(table, subnet)
        for address in sorted(have - want, key=ipaddress.ip_address):
            self.route(table, internet, address, False)
        for address in sorted(want - have, key=ipaddress.ip_address):
            self.route(table, internet, address, True)
        return want

    def route(self, table: int, internet: int, address: str, add: bool) -> None:
        self._write("svs_route_add_del", is_add=add, prefix=f"{address}/32", table_id=table, source_table_id=internet)

    def entries(self, table: int, subnet: Any) -> set[str]:
        """/32 entries of the SVS table inside the tenant subnet (the table also
        holds FIB special entries such as 0.0.0.0/0)."""
        out = set()
        for detail in self._call("ip_route_dump", table={"table_id": table, "is_ip6": False, "name": ""}):
            prefix = ipaddress.ip_network(str(detail.route.prefix), strict=False)
            if prefix.prefixlen == 32 and prefix.network_address in subnet:
                out.add(str(prefix.network_address))
        return out

    def _enabled(self, sw_if_index: int) -> int | None:
        for d in self._call("svs_dump"):
            if int(d.sw_if_index) == sw_if_index and int(getattr(d, "af", AF_IP4)) == AF_IP4:
                return int(d.table_id)
        return None

    def remove(self, sw_if_index: int) -> None:
        """Disable SVS on the interface and drop the table's entries (rollback to ACL mode)."""
        table = self._enabled(sw_if_index)
        if table is None:
            return
        for detail in self._call("ip_route_dump", table={"table_id": table, "is_ip6": False, "name": ""}):
            prefix = ipaddress.ip_network(str(detail.route.prefix), strict=False)
            if prefix.prefixlen == 32 and not prefix.network_address.is_multicast and str(prefix.network_address) not in ("0.0.0.0", "255.255.255.255"):
                self._write("svs_route_add_del", is_add=False, prefix=str(prefix), table_id=table,
                            source_table_id=int(getattr(detail.route.paths[0], "table_id", 0)) if getattr(detail.route, "paths", None) else 0)
        self._write("svs_enable_disable", is_enable=False, af=AF_IP4, table_id=table, sw_if_index=sw_if_index)
        self._write("svs_table_add_del", is_add=False, af=AF_IP4, table_id=table)
