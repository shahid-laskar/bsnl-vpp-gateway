"""In-memory stand-in for the vpp_papi API surface the controller uses."""
from __future__ import annotations

import ipaddress
from types import SimpleNamespace


class FakeAclMixin:
    """ACL plugin calls (acl_dump / add_replace / interface list / del)."""

    def _acl_init(self):
        if not hasattr(self, "acls"):
            self.acls: dict[int, dict] = {}
            self.acl_bindings: dict[int, list[int]] = {}
            self._next_acl = 0

    def acl_dump(self, acl_index):
        self._acl_init()
        self.calls.append("acl_dump")
        return [SimpleNamespace(acl_index=i, tag=a["tag"], count=len(a["r"]), r=[dict(r) for r in a["r"]]) for i, a in sorted(self.acls.items())]

    def acl_add_replace(self, acl_index, tag, count, r):
        self._acl_init()
        self.calls.append("acl_add_replace")
        if acl_index == 0xFFFFFFFF:
            acl_index, self._next_acl = self._next_acl, self._next_acl + 1
        elif acl_index not in self.acls:
            return SimpleNamespace(retval=-6, acl_index=acl_index)
        self.acls[acl_index] = {"tag": tag, "r": [dict(x) for x in r]}
        return SimpleNamespace(retval=0, acl_index=acl_index)

    def acl_interface_list_dump(self, sw_if_index):
        self._acl_init()
        self.calls.append("acl_interface_list_dump")
        acls = self.acl_bindings.get(sw_if_index)
        return [SimpleNamespace(sw_if_index=sw_if_index, count=len(acls), n_input=len(acls), acls=list(acls))] if acls else []

    def acl_interface_set_acl_list(self, sw_if_index, count, n_input, acls):
        self._acl_init()
        self.calls.append("acl_interface_set_acl_list")
        self.acl_bindings[sw_if_index] = list(acls)
        return SimpleNamespace(retval=0)

    def acl_del(self, acl_index):
        self._acl_init()
        self.calls.append("acl_del")
        if any(acl_index in b for b in self.acl_bindings.values()):
            return SimpleNamespace(retval=-142)
        self.acls.pop(acl_index, None)
        return SimpleNamespace(retval=0)

    def permits(self, sw_if_index, src, dst, proto=1, dport=0):
        """Evaluate the bound ACL first-match, like the ACL plugin input arc."""
        self._acl_init()
        for acl_index in self.acl_bindings.get(sw_if_index, []):
            for rule in self.acls[acl_index]["r"]:
                if ipaddress.ip_address(src) not in ipaddress.ip_network(rule["src_prefix"]):
                    continue
                if ipaddress.ip_address(dst) not in ipaddress.ip_network(rule["dst_prefix"]):
                    continue
                if rule["proto"] not in (0, proto):
                    continue
                if rule["proto"] in (6, 17) and not rule["dstport_or_icmpcode_first"] <= dport <= rule["dstport_or_icmpcode_last"]:
                    continue
                return bool(rule["is_permit"])
        return False


class FakeVppApi(FakeAclMixin):
    def __init__(self) -> None:
        self.interfaces: dict[int, dict] = {}
        self.addresses: dict[int, set[str]] = {}
        self.tables: dict[int, int] = {}
        self.vrfs: set[int] = {0}
        self.calls: list[str] = []
        self._next = 0
        self.add_interface("local0")

    # helpers for tests -----------------------------------------------------------------
    def add_interface(self, name, parent=None, outer=0, inner=0, flags=0, sub_flags=0, tag=""):
        index = self._next
        self._next += 1
        self.interfaces[index] = dict(name=name, parent=index if parent is None else parent, outer=outer, inner=inner,
                                      tags=2 if parent is not None else 0, admin=flags, sub_flags=sub_flags, tag=tag, mtu=[9000, 0, 0, 0])
        self.addresses[index] = set()
        self.tables[index] = 0
        return index

    def restart(self):
        """Simulate a VPP restart: only the physical/af_packet parents remain."""
        keep = {i: v for i, v in self.interfaces.items() if v["tags"] == 0}
        self.interfaces, self.vrfs = keep, {0}
        self.addresses = {i: set() for i in keep}
        self.tables = {i: 0 for i in keep}

    def _row(self, index):
        v = self.interfaces[index]
        return SimpleNamespace(sw_if_index=index, sup_sw_if_index=v["parent"], interface_name=v["name"], tag=v["tag"],
                               flags=v["admin"], mtu=list(v["mtu"]), sub_number_of_tags=v["tags"],
                               sub_outer_vlan_id=v["outer"], sub_inner_vlan_id=v["inner"], sub_if_flags=v["sub_flags"])

    # read API ----------------------------------------------------------------------------
    def sw_interface_dump(self, sw_if_index=None):
        self.calls.append("sw_interface_dump")
        if sw_if_index is None:
            return [self._row(i) for i in sorted(self.interfaces)]
        return [self._row(sw_if_index)] if sw_if_index in self.interfaces else []

    def sw_interface_get_table(self, sw_if_index, is_ipv6):
        self.calls.append("sw_interface_get_table")
        return SimpleNamespace(retval=0, vrf_id=self.tables[sw_if_index])

    def ip_address_dump(self, sw_if_index, is_ipv6):
        self.calls.append("ip_address_dump")
        return [SimpleNamespace(prefix=ipaddress.ip_interface(p)) for p in sorted(self.addresses[sw_if_index])]

    def ip_table_dump(self):
        self.calls.append("ip_table_dump")
        return [SimpleNamespace(table=SimpleNamespace(table_id=t, is_ip6=False)) for t in sorted(self.vrfs)]

    # write API ---------------------------------------------------------------------------
    def create_subif(self, sw_if_index, sub_id, sub_if_flags, outer_vlan_id, inner_vlan_id):
        self.calls.append("create_subif")
        name = f"{self.interfaces[sw_if_index]['name']}.{sub_id}"
        if any(v["name"] == name for v in self.interfaces.values()):
            return SimpleNamespace(retval=-56, sw_if_index=~0)
        index = self.add_interface(name, parent=sw_if_index, outer=outer_vlan_id, inner=inner_vlan_id, sub_flags=sub_if_flags)
        return SimpleNamespace(retval=0, sw_if_index=index)

    def delete_subif(self, sw_if_index):
        self.calls.append("delete_subif")
        self.interfaces.pop(sw_if_index)
        return SimpleNamespace(retval=0)

    def sw_interface_tag_add_del(self, is_add, sw_if_index, tag):
        self.calls.append("sw_interface_tag_add_del")
        self.interfaces[sw_if_index]["tag"] = tag if is_add else ""
        return SimpleNamespace(retval=0)

    def sw_interface_set_mtu(self, sw_if_index, mtu):
        self.calls.append("sw_interface_set_mtu")
        self.interfaces[sw_if_index]["mtu"] = [mtu[0]] + self.interfaces[sw_if_index]["mtu"][1:]
        return SimpleNamespace(retval=0)

    def sw_interface_set_table(self, sw_if_index, is_ipv6, vrf_id):
        self.calls.append("sw_interface_set_table")
        if vrf_id not in self.vrfs:
            return SimpleNamespace(retval=-2)
        self.tables[sw_if_index] = vrf_id
        self.addresses[sw_if_index] = set()  # VPP flushes addresses on table change
        return SimpleNamespace(retval=0)

    def ip_table_add_del_v2(self, table, create_mfib, is_add):
        self.calls.append("ip_table_add_del_v2")
        (self.vrfs.add if is_add else self.vrfs.discard)(table["table_id"])
        return SimpleNamespace(retval=0)

    def sw_interface_add_del_address(self, sw_if_index, is_add, del_all, prefix):
        self.calls.append("sw_interface_add_del_address")
        (self.addresses[sw_if_index].add if is_add else self.addresses[sw_if_index].discard)(str(ipaddress.ip_interface(prefix)))
        return SimpleNamespace(retval=0)

    def sw_interface_set_flags(self, sw_if_index, flags):
        self.calls.append("sw_interface_set_flags")
        self.interfaces[sw_if_index]["admin"] = flags
        return SimpleNamespace(retval=0)

    # session API ------------------------------------------------------------------------
    def show_version(self):
        return SimpleNamespace(retval=0, version="26.10-release")

    def control_ping(self):
        return SimpleNamespace(retval=0)


class FakeVppClient:
    """Mimics VPPApiClient: .api, connect/disconnect, validate_message_table."""

    def __init__(self, message_table: set[str], api: FakeVppApi | None = None) -> None:
        self.api = api or FakeVppApi()
        self.message_table = message_table
        self.connected = False

    def connect(self, name):
        self.connected = True

    def disconnect(self):
        self.connected = False

    def validate_message_table(self, wanted):
        return [m for m in wanted if m not in self.message_table]
