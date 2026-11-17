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
        if any(p["acl_index"] == acl_index for p in getattr(self, "abf_policies", {}).values()):
            return SimpleNamespace(retval=-142)  # in use by an ABF policy
        self.acls.pop(acl_index, None)
        return SimpleNamespace(retval=0)

    def _first_match(self, acl_index, src, dst, proto, dport):
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
        return None

    def permits(self, sw_if_index, src, dst, proto=1, dport=0):
        """Evaluate the bound ACL first-match, like the ACL plugin input arc."""
        self._acl_init()
        for acl_index in self.acl_bindings.get(sw_if_index, []):
            match = self._first_match(acl_index, src, dst, proto, dport)
            if match is not None:
                return match
        return False


class FakeAbfMixin:
    """ABF plugin calls; ``steers`` evaluates attachments like abf-input-ip4."""

    def _abf_init(self):
        if not hasattr(self, "abf_policies"):
            self.abf_policies: dict[int, dict] = {}
            self.abf_attachments: list[dict] = []

    @staticmethod
    def _hop(path):
        return str(ipaddress.ip_address(path["nh"]["address"]["ip4"]))

    def abf_policy_dump(self):
        self._abf_init()
        self.calls.append("abf_policy_dump")
        return [SimpleNamespace(policy=SimpleNamespace(
            policy_id=pid, acl_index=p["acl_index"], n_paths=len(p["hops"]),
            paths=[SimpleNamespace(nh=SimpleNamespace(address=SimpleNamespace(ip4=ipaddress.ip_address(h)))) for h in p["hops"]]))
            for pid, p in sorted(self.abf_policies.items())]

    def abf_policy_add_del(self, is_add, policy):
        self._abf_init()
        self.calls.append("abf_policy_add_del")
        pid = policy["policy_id"]
        for path in policy["paths"]:
            # vpp_papi refuses to pack a fib_path without its fixed 16-entry label_stack
            if len(path.get("label_stack", [])) != 16:
                raise ValueError("Exception while packing fib_path: label_stack must have 16 entries")
        if is_add:
            if policy["acl_index"] not in self.acls:
                return SimpleNamespace(retval=-6)
            entry = self.abf_policies.setdefault(pid, {"acl_index": policy["acl_index"], "hops": []})
            entry["hops"] += [self._hop(p) for p in policy["paths"] if self._hop(p) not in entry["hops"]]
            return SimpleNamespace(retval=0)
        if pid not in self.abf_policies:
            return SimpleNamespace(retval=-6)
        if any(a["policy_id"] == pid for a in self.abf_attachments):
            return SimpleNamespace(retval=-142)
        entry = self.abf_policies[pid]
        entry["hops"] = [h for h in entry["hops"] if h not in {self._hop(p) for p in policy["paths"]}]
        if not entry["hops"]:
            del self.abf_policies[pid]
        return SimpleNamespace(retval=0)

    def abf_itf_attach_dump(self):
        self._abf_init()
        self.calls.append("abf_itf_attach_dump")
        return [SimpleNamespace(attach=SimpleNamespace(**a)) for a in self.abf_attachments]

    def abf_itf_attach_add_del(self, is_add, attach):
        self._abf_init()
        self.calls.append("abf_itf_attach_add_del")
        key = (attach["policy_id"], attach["sw_if_index"], bool(attach["is_ipv6"]))
        present = [a for a in self.abf_attachments if (a["policy_id"], a["sw_if_index"], a["is_ipv6"]) == key]
        if is_add:
            if attach["policy_id"] not in self.abf_policies or present:
                return SimpleNamespace(retval=-6)
            self.abf_attachments.append({**attach, "is_ipv6": bool(attach["is_ipv6"])})
        else:
            if not present:
                return SimpleNamespace(retval=-6)
            self.abf_attachments.remove(present[0])
        return SimpleNamespace(retval=0)

    def steers(self, sw_if_index, src, dst, proto=6, dport=80):
        """Next hop ABF would send this packet to, or None (normal forwarding)."""
        self._abf_init()
        for attach in sorted((a for a in self.abf_attachments if a["sw_if_index"] == sw_if_index and not a["is_ipv6"]),
                             key=lambda a: a["priority"]):
            policy = self.abf_policies[attach["policy_id"]]
            if self._first_match(policy["acl_index"], src, dst, proto, dport):
                return policy["hops"][0]
        return None


class FakeClassifyMixin:
    """Classifier tables + ip4 input ACL; ``mac_permits`` walks the chain over a
    synthetic double-tagged frame, keyed relative to the IPv4 header like VPP
    does with current_data_flag 1."""

    NONE = 0xFFFFFFFF

    def _cls_init(self):
        if not hasattr(self, "cls_tables"):
            self.cls_tables: dict[int, dict] = {}
            self.inacl_ip4: dict[int, int] = {}
            self._next_cls = 0

    def classify_add_del_table(self, is_add, del_chain, table_index, nbuckets, memory_size, skip_n_vectors, match_n_vectors,
                               next_table_index, miss_next_index, current_data_flag, current_data_offset, mask_len, mask):
        self._cls_init()
        self.calls.append("classify_add_del_table")
        if is_add:
            if len(mask) != mask_len or mask_len != (skip_n_vectors + match_n_vectors) * 16:
                return SimpleNamespace(retval=-1, new_table_index=self.NONE)
            index, self._next_cls = self._next_cls, self._next_cls + 1
            self.cls_tables[index] = {"mask": bytes(mask), "vectors": match_n_vectors, "next": next_table_index,
                                      "miss": miss_next_index, "flag": current_data_flag, "offset": current_data_offset, "sessions": {}}
            return SimpleNamespace(retval=0, new_table_index=index, skip_n_vectors=skip_n_vectors, match_n_vectors=match_n_vectors)
        if table_index not in self.cls_tables or table_index in self.inacl_ip4.values():
            return SimpleNamespace(retval=-142, new_table_index=self.NONE)
        while table_index != self.NONE and table_index in self.cls_tables:
            nxt = self.cls_tables.pop(table_index)["next"]
            table_index = nxt if del_chain else self.NONE
        return SimpleNamespace(retval=0, new_table_index=self.NONE)

    def classify_add_del_session(self, is_add, table_index, hit_next_index, opaque_index, advance, action, metadata, match_len, match):
        self._cls_init()
        self.calls.append("classify_add_del_session")
        table = self.cls_tables.get(table_index)
        if table is None or match_len != len(match) or match_len < table["vectors"] * 16:
            return SimpleNamespace(retval=-1)
        key = bytes(a & b for a, b in zip(match, table["mask"]))
        if is_add:
            table["sessions"][key] = hit_next_index
        elif table["sessions"].pop(key, None) is None:
            return SimpleNamespace(retval=-6)
        return SimpleNamespace(retval=0)

    def classify_table_by_interface(self, sw_if_index):
        self._cls_init()
        self.calls.append("classify_table_by_interface")
        return SimpleNamespace(retval=0, sw_if_index=sw_if_index, l2_table_id=self.NONE,
                               ip4_table_id=self.inacl_ip4.get(sw_if_index, self.NONE), ip6_table_id=self.NONE)

    def classify_table_info(self, table_id):
        self._cls_init()
        self.calls.append("classify_table_info")
        t = self.cls_tables[table_id]
        return SimpleNamespace(retval=0, table_id=table_id, nbuckets=32, match_n_vectors=t["vectors"], skip_n_vectors=0,
                               active_sessions=len(t["sessions"]), next_table_index=t["next"], miss_next_index=t["miss"],
                               mask_length=len(t["mask"]), mask=t["mask"])

    def classify_session_dump(self, table_id):
        self._cls_init()
        self.calls.append("classify_session_dump")
        return [SimpleNamespace(table_id=table_id, hit_next_index=h, advance=0, opaque_index=self.NONE, match_length=len(k), match=k)
                for k, h in self.cls_tables[table_id]["sessions"].items()]

    def input_acl_set_interface(self, sw_if_index, ip4_table_index, ip6_table_index, l2_table_index, is_add):
        self._cls_init()
        self.calls.append("input_acl_set_interface")
        if is_add:
            if ip4_table_index not in self.cls_tables:
                return SimpleNamespace(retval=-1)
            self.inacl_ip4[sw_if_index] = ip4_table_index
        elif self.inacl_ip4.get(sw_if_index) == ip4_table_index:
            del self.inacl_ip4[sw_if_index]
        else:
            return SimpleNamespace(retval=-6)
        return SimpleNamespace(retval=0)

    def mac_permits(self, sw_if_index, mac, src_ip, outer=200, inner=101):
        """Would ip4-inacl let this (source MAC, source IPv4) through?"""
        self._cls_init()
        l2 = bytes.fromhex(mac.replace(":", "")) + bytes([0x81, 0, outer >> 8, outer & 255, 0x81, 0, inner >> 8, inner & 255, 8, 0])
        ip = bytes([0x45, 0, 0, 84, 0, 0, 0x40, 0, 64, 1, 0, 0]) + ipaddress.IPv4Address(src_ip).packed + bytes([10, 44, 0, 209])
        frame, ip_start = b"\x00" * 6 + l2 + ip + b"\x00" * 64, 22   # dst MAC, src MAC + tags + ethertype, IPv4
        table_index = self.inacl_ip4.get(sw_if_index, self.NONE)
        if table_index == self.NONE:
            return True
        while True:
            t = self.cls_tables[table_index]
            start = (ip_start if t["flag"] else 0) + t["offset"]
            region = frame[start:start + t["vectors"] * 16]
            key = bytes(a & b for a, b in zip(region, t["mask"]))
            if key in t["sessions"]:
                return t["sessions"][key] == self.NONE
            if t["next"] != self.NONE:
                table_index = t["next"]
                continue
            return t["miss"] == self.NONE


class FakeSvsMixin:
    """Source VRF Select: tables, interface enablement, /32 -> lookup-table entries."""

    SPECIAL = ("0.0.0.0/0", "0.0.0.0/32", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32")

    def _svs_init(self):
        if not hasattr(self, "svs_tables"):
            self.svs_tables: set[int] = set()
            self.svs_enabled: dict[int, int] = {}
            self.svs_routes: dict[int, dict[str, int]] = {}

    def svs_table_add_del(self, is_add, af, table_id):
        self._svs_init()
        self.calls.append("svs_table_add_del")
        if is_add:
            if table_id not in self.vrfs:
                return SimpleNamespace(retval=-2)
            self.svs_tables.add(table_id)
            self.svs_routes.setdefault(table_id, {})
        else:
            if table_id in self.svs_enabled.values():
                return SimpleNamespace(retval=-142)
            self.svs_tables.discard(table_id)
            self.svs_routes.pop(table_id, None)
        return SimpleNamespace(retval=0)

    def svs_enable_disable(self, is_enable, af, table_id, sw_if_index):
        self._svs_init()
        self.calls.append("svs_enable_disable")
        if is_enable:
            if table_id not in self.svs_tables:
                return SimpleNamespace(retval=-6)
            self.svs_enabled[sw_if_index] = table_id
        elif self.svs_enabled.get(sw_if_index) == table_id:
            del self.svs_enabled[sw_if_index]
        else:
            return SimpleNamespace(retval=-6)
        return SimpleNamespace(retval=0)

    def svs_route_add_del(self, is_add, prefix, table_id, source_table_id):
        self._svs_init()
        self.calls.append("svs_route_add_del")
        routes = self.svs_routes.get(table_id)
        if routes is None:
            return SimpleNamespace(retval=-6)
        key = str(ipaddress.ip_network(str(prefix)))
        if is_add:
            routes[key] = source_table_id
        elif routes.pop(key, None) is None:
            return SimpleNamespace(retval=-6)
        return SimpleNamespace(retval=0)

    def svs_dump(self):
        self._svs_init()
        self.calls.append("svs_dump")
        return [SimpleNamespace(table_id=t, sw_if_index=sw, af=0) for sw, t in sorted(self.svs_enabled.items())]

    def ip_route_dump(self, table):
        self._svs_init()
        self.calls.append("ip_route_dump")
        tid = table["table_id"]
        routes = dict(self.svs_routes.get(tid, {}))
        rows = [(p, None) for p in self.SPECIAL] + list(routes.items())
        return [SimpleNamespace(route=SimpleNamespace(table_id=tid, prefix=ipaddress.ip_network(p),
                                                      paths=[SimpleNamespace(table_id=lookup)] if lookup is not None else []))
                for p, lookup in rows]

    def lookup_table(self, sw_if_index, src):
        """FIB table a packet from ``src`` on ``sw_if_index`` is forwarded in."""
        self._svs_init()
        table = self.svs_enabled.get(sw_if_index)
        if table is not None:
            for prefix, lookup in self.svs_routes.get(table, {}).items():
                if ipaddress.ip_address(src) in ipaddress.ip_network(prefix):
                    return lookup
        return self.tables[sw_if_index]


class FakeVppApi(FakeAclMixin, FakeAbfMixin, FakeClassifyMixin, FakeSvsMixin):
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
