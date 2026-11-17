"""MAC/IP source enforcement from DHCP lease bindings (plan Phase 6, ADR-016).

A tenant with ``mac_enforcement: "enforce"`` gets a controller-owned chain of
two classifier tables as the IPv4 input ACL (``ip4-inacl``) of its QinQ
sub-interface:

    head  key = source MAC (IP header - 16) + source IPv4 (IP header + 12)
          one session per open SubscriberBinding (MAC, IP) of the tenant
          miss -> tail
    tail  key = source IPv4 only; one session for 0.0.0.0 (DHCP DISCOVER/
          REQUEST from clients that have no address yet); miss -> drop

A hit continues the ip4-unicast arc; anything else is dropped. Why not the
ACL plugin's MACIP ACLs: on this QinQ sub-interface (outer and inner 0x8100,
af_packet) VPP 26.10's MACIP built only L2/ARP tables keyed from the
Ethernet header with fixed tag layouts and every IPv4 packet missed (lab
trace 2026-11-17: ``input ACL table-miss drops``), while it worked on an
untagged interface. These tables are keyed relative to the IPv4 header
(``current_data_flag`` 1), so the tag layout only fixes the MAC offset:
14 + 4 x 2 tags = 22 bytes of L2 header, source MAC at 22 - 6 = 16 bytes
before the IP header.

Limits (ADR-016): IPv4 only (IPv6 is never permitted, F-10); ``ip4-inacl``
runs after ABF, so HTTP steered to the redirector is not MAC-checked (it can
only ever get a 302); ARP is not filtered.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Iterable

from .policy import PolicyValidationError

MODES = ("log_only", "enforce")
NO_TABLE = 0xFFFFFFFF
CONTINUE = 0xFFFFFFFF   # session hit / miss: continue the ip4-unicast arc
DROP = 0                # ip4-inacl next index 0 = error-drop
QINQ_L2_BYTES = 22
MAC_OFFSET = -(QINQ_L2_BYTES - 6)
HEAD_MASK = b"\xff" * 6 + b"\x00" * 22 + b"\xff" * 4          # 2 vectors
TAIL_MASK = b"\x00" * 12 + b"\xff" * 4                        # 1 vector
TAIL_KEY = b"\x00" * 16
HEAD_BUCKETS, HEAD_MEMORY = 4096, 16 << 20
TAIL_BUCKETS, TAIL_MEMORY = 2, 64 << 10
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def mac_mode(tenant: dict[str, Any]) -> str:
    mode = tenant.get("mac_enforcement", "log_only")
    if mode not in MODES:
        raise PolicyValidationError(f"tenant {tenant.get('tenant_key')}: mac_enforcement must be one of {MODES}, not {mode!r}")
    return mode


def head_key(mac: str, address: str) -> bytes:
    return bytes.fromhex(mac.replace(":", "")) + b"\x00" * 22 + ipaddress.IPv4Address(address).packed


def parse_head_key(match: bytes) -> tuple[str, str]:
    return ":".join(f"{b:02x}" for b in match[:6]), str(ipaddress.IPv4Address(match[28:32]))


def wanted_pairs(tenant: dict[str, Any], bindings: Iterable[dict[str, Any]]) -> set[tuple[str, str]]:
    """(mac, ip) of the tenant's open bindings inside its subnet."""
    subnet = ipaddress.ip_interface(tenant["gateway_ip"]).network
    pairs = set()
    for row in bindings:
        if row.get("tenant_key") != tenant["tenant_key"] or row.get("valid_to") is not None:
            continue
        mac = str(row.get("mac") or "").lower()
        try:
            address = ipaddress.IPv4Address(row.get("private_ipv4"))
        except ValueError:
            continue
        if MAC_RE.match(mac) and address in subnet:
            pairs.add((mac, str(address)))
    return pairs


class MacEnforcer:
    """Converge one tenant's classifier chain; zero writes when VPP matches."""

    MUTATING = frozenset({"classify_add_del_table", "classify_add_del_session", "input_acl_set_interface"})

    def __init__(self, call: Any, write: Any) -> None:
        self._call, self._write = call, write

    def apply(self, tenant: dict[str, Any], sw_if_index: int, bindings: list[dict[str, Any]] | None) -> set[str] | None:
        """Returns the IPv4 addresses permitted by MAC (enforce) or None (log_only)."""
        mode = mac_mode(tenant)
        head = int(self._call("classify_table_by_interface", sw_if_index=sw_if_index).ip4_table_id)
        head = None if head == NO_TABLE else head
        if mode != "enforce":
            if head is not None:
                self._require_ours(head, sw_if_index)
                self._remove(sw_if_index, head)
            return None
        if bindings is None:
            raise PolicyValidationError(f"tenant {tenant['tenant_key']}: mac_enforcement=enforce needs lease bindings (--kea-lease-file)")
        pairs = wanted_pairs(tenant, bindings)
        new_chain = head is None
        if new_chain:
            tail = self._create(TAIL_MASK, 1, NO_TABLE, 0, TAIL_BUCKETS, TAIL_MEMORY)
            self._session(tail, TAIL_KEY, True)
            head = self._create(HEAD_MASK, 2, tail, MAC_OFFSET, HEAD_BUCKETS, HEAD_MEMORY)
        else:
            tail = self._require_ours(head, sw_if_index)
            if TAIL_KEY not in self._keys(tail):
                self._session(tail, TAIL_KEY, True)
        want = {head_key(mac, ip) for mac, ip in pairs}
        have = self._keys(head) if not new_chain else set()
        for key in sorted(have - want):
            self._session(head, key, False)
        for key in sorted(want - have):
            self._session(head, key, True)
        if new_chain:
            # Bind only once the sessions exist: no window that drops bound subscribers.
            self._write("input_acl_set_interface", sw_if_index=sw_if_index, ip4_table_index=head,
                        ip6_table_index=NO_TABLE, l2_table_index=NO_TABLE, is_add=True)
        return {ip for _, ip in pairs}

    # helpers -------------------------------------------------------------------------------
    def _create(self, mask: bytes, vectors: int, next_table: int, offset: int, buckets: int, memory: int) -> int:
        reply = self._write("classify_add_del_table", is_add=True, del_chain=False, table_index=NO_TABLE,
                            nbuckets=buckets, memory_size=memory, skip_n_vectors=0, match_n_vectors=vectors,
                            next_table_index=next_table, miss_next_index=DROP, current_data_flag=1,
                            current_data_offset=offset, mask_len=len(mask), mask=mask)
        return int(reply.new_table_index)

    def _session(self, table: int, key: bytes, add: bool) -> None:
        self._write("classify_add_del_session", is_add=add, table_index=table, hit_next_index=CONTINUE,
                    opaque_index=NO_TABLE, advance=0, action=0, metadata=0, match_len=len(key), match=key)

    def _keys(self, table: int) -> set[bytes]:
        info = self._call("classify_table_info", table_id=table)
        size = int(info.match_n_vectors) * 16
        return {bytes(s.match)[:size] for s in self._call("classify_session_dump", table_id=table)}

    def _require_ours(self, head: int, sw_if_index: int) -> int:
        """Our chain is recognised by its masks and miss actions; returns the tail."""
        info = self._call("classify_table_info", table_id=head)
        tail = int(info.next_table_index)
        ok = bytes(info.mask)[:len(HEAD_MASK)] == HEAD_MASK and int(info.match_n_vectors) == 2 and tail != NO_TABLE
        if ok:
            tail_info = self._call("classify_table_info", table_id=tail)
            ok = (bytes(tail_info.mask)[:len(TAIL_MASK)] == TAIL_MASK and int(tail_info.match_n_vectors) == 1
                  and int(tail_info.next_table_index) == NO_TABLE)
        if not ok:
            raise RuntimeError(f"sw_if_index {sw_if_index} has an input ACL table {head} the controller does not own; refusing to change it")
        return tail

    def _remove(self, sw_if_index: int, head: int) -> None:
        self._write("input_acl_set_interface", sw_if_index=sw_if_index, ip4_table_index=head,
                    ip6_table_index=NO_TABLE, l2_table_index=NO_TABLE, is_add=False)
        self._write("classify_add_del_table", is_add=False, del_chain=True, table_index=head, nbuckets=0, memory_size=0,
                    skip_n_vectors=0, match_n_vectors=0, next_table_index=NO_TABLE, miss_next_index=NO_TABLE,
                    current_data_flag=0, current_data_offset=0, mask_len=0, mask=b"")
