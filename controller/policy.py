"""Subscriber access policy compiled to a per-tenant VPP ACL (plan Phase 6,
candidate B of D-09; remediation step 5).

The tenant's input ACL on its QinQ sub-interface is first-match:

1. pre-auth allowlist  (DHCP incl. unicast renew, DNS to the gateway resolver,
                        portal HTTP/HTTPS/ICMP) - for every source in the tenant
2. protected prefixes  denied for everyone (management LAN, gateway host),
                        so authorization can never reach them
3. one permit per authenticated subscriber /32 to the policy's
                        ``authenticated_destinations``
4. explicit deny-all   (counted; IPv6 is never permitted - F-10)

Stateless ``permit`` is used: the ACL only filters subscriber->network
traffic, so removing a subscriber's rule blocks new and existing flows
immediately (Phase 6 deactivation criterion). Return traffic is not filtered.

Authenticated destinations come from desired state; the lab deliberately has
no NAT/upstream yet (NAT is step 7), so authorization opens no internet path.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

PERMIT, DENY = 1, 0
PROTO = {"icmp": 1, "tcp": 6, "udp": 17, "any": 0}
ANY4 = "0.0.0.0/0"


class PolicyValidationError(ValueError):
    pass


@dataclass(frozen=True)
class AclRule:
    is_permit: int
    src_prefix: str
    dst_prefix: str
    proto: int = 0
    src_ports: tuple[int, int] = (0, 65535)
    dst_ports: tuple[int, int] = (0, 65535)

    def to_api(self) -> dict[str, Any]:
        return {
            "is_permit": self.is_permit,
            "src_prefix": self.src_prefix,
            "dst_prefix": self.dst_prefix,
            "proto": self.proto,
            "srcport_or_icmptype_first": self.src_ports[0],
            "srcport_or_icmptype_last": self.src_ports[1],
            "dstport_or_icmpcode_first": self.dst_ports[0],
            "dstport_or_icmpcode_last": self.dst_ports[1],
            "tcp_flags_mask": 0,
            "tcp_flags_value": 0,
        }

    @classmethod
    def from_api(cls, rule: Any) -> "AclRule":
        get = (lambda k: rule[k]) if isinstance(rule, dict) else (lambda k: getattr(rule, k))
        proto = int(get("proto"))
        ports = lambda a, b: (int(get(a)), int(get(b)))  # noqa: E731
        return cls(int(get("is_permit")), str(ipaddress.ip_network(str(get("src_prefix")), strict=False)),
                   str(ipaddress.ip_network(str(get("dst_prefix")), strict=False)), proto,
                   ports("srcport_or_icmptype_first", "srcport_or_icmptype_last"),
                   ports("dstport_or_icmpcode_first", "dstport_or_icmpcode_last"))


def _net(value: str, what: str) -> str:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise PolicyValidationError(f"{what}: invalid IPv4 prefix {value!r}") from exc
    if network.version != 4:
        raise PolicyValidationError(f"{what}: IPv4 only (IPv6 is not offered in v1, F-10)")
    return str(network)


def _ports(entry: dict[str, Any], key: str, proto: int) -> tuple[int, int]:
    if key not in entry:
        return (0, 65535) if proto != 1 else (0, 255)
    value = entry[key]
    low, high = (value, value) if isinstance(value, int) else tuple(value)
    if not (0 <= low <= high <= 65535):
        raise PolicyValidationError(f"{key} out of range: {value!r}")
    return int(low), int(high)


def preauth_rules(policy: dict[str, Any], tenant_subnet: str) -> list[AclRule]:
    rules = []
    for index, entry in enumerate(policy.get("preauth_allow", [])):
        proto = PROTO.get(str(entry.get("proto", "any")).lower())
        if proto is None:
            raise PolicyValidationError(f"preauth_allow[{index}]: unknown proto {entry.get('proto')!r}")
        rules.append(AclRule(PERMIT, _net(entry.get("src", tenant_subnet), f"preauth_allow[{index}].src"),
                             _net(entry["dst"], f"preauth_allow[{index}].dst"), proto,
                             _ports(entry, "src_port", proto), _ports(entry, "dst_port", proto)))
    return rules


def compile_tenant_acl(tenant: dict[str, Any], policy: dict[str, Any], subscribers: list[dict[str, Any]]) -> list[AclRule]:
    subnet = str(ipaddress.ip_interface(tenant["gateway_ip"]).network)
    rules = preauth_rules(policy, subnet)
    rules += [AclRule(DENY, ANY4, _net(p, "protected_destinations")) for p in policy.get("protected_destinations", [])]
    if tenant.get("intra_tenant_policy", "block") == "block":
        # Subscriber-to-subscriber traffic routed through the gateway (R-23
        # default). Traffic bridged by the access network never reaches VPP.
        rules.append(AclRule(DENY, ANY4, subnet))
    destinations = [_net(d, "authenticated_destinations") for d in policy.get("authenticated_destinations", [])]
    active = sorted({s["private_ipv4"] for s in subscribers
                     if s.get("tenant_key") == tenant["tenant_key"] and s.get("state") == "authenticated"},
                    key=lambda ip: ipaddress.ip_address(ip))
    for address in active:
        if ipaddress.ip_address(address) not in ipaddress.ip_network(subnet):
            raise PolicyValidationError(f"subscriber {address} outside tenant subnet {subnet}")
        rules += [AclRule(PERMIT, f"{address}/32", dst) for dst in destinations]
    rules.append(AclRule(DENY, ANY4, ANY4))
    return rules


def authorized_addresses(rules: list[AclRule]) -> set[str]:
    return {r.src_prefix.split("/")[0] for r in rules if r.is_permit == PERMIT and r.src_prefix.endswith("/32")}


def tenant_policy(state: dict[str, Any], tenant: dict[str, Any]) -> dict[str, Any] | None:
    ref = tenant.get("pre_auth_policy_ref")
    policy = (state.get("policies") or {}).get(ref) if ref else None
    if policy is None or not policy.get("dataplane_apply", False):
        return None
    return policy


def acl_tag(tenant_key: str) -> str:
    import hashlib
    tag = f"bsnl:acl/{tenant_key}"
    return tag if len(tag) <= 63 else "bsnl:acl/" + hashlib.sha256(tenant_key.encode()).hexdigest()[:40]


def _text(value: Any) -> str:
    return value.decode().rstrip("\x00") if isinstance(value, bytes) else str(value or "").rstrip("\x00")


class VppPolicyEnforcer:
    """Converge each tenant's tagged input ACL and its interface binding.

    Zero writes when VPP already matches. ``applied`` maps tenant_key to the
    subscriber addresses whose permits are confirmed in VPP after the last
    successful apply.
    """

    MUTATING = frozenset({"acl_add_replace", "acl_interface_set_acl_list", "acl_del"})
    NEW_ACL = 0xFFFFFFFF

    def __init__(self, api: Any, enable_writes: bool = False) -> None:
        self.api = api
        self.enable_writes = enable_writes
        self.writes: list[str] = []
        self.applied: dict[str, set[str]] = {}

    def apply(self, state: dict[str, Any], interface_index: dict[str, int]) -> dict[str, set[str]]:
        self.writes = []
        if not self.enable_writes:
            raise RuntimeError("VPP writes are disabled")
        existing = {_text(a.tag): a for a in self._call("acl_dump", acl_index=self.NEW_ACL) if _text(getattr(a, "tag", "")).startswith("bsnl:acl/")}
        applied: dict[str, set[str]] = {}
        wanted_tags = set()
        for tenant in state.get("tenants", []):
            if tenant.get("admin_state", "enabled") != "enabled":
                continue
            policy = tenant_policy(state, tenant)
            if policy is None:
                continue
            index = interface_index.get(tenant["tenant_key"])
            if index is None:
                raise RuntimeError(f"no VPP sub-interface for {tenant['tenant_key']}; cannot enforce policy")
            rules = compile_tenant_acl(tenant, policy, state.get("subscribers", []))
            tag = acl_tag(tenant["tenant_key"])
            wanted_tags.add(tag)
            current = existing.get(tag)
            if current is not None and [AclRule.from_api(r) for r in current.r] == rules:
                acl_index = int(current.acl_index)
            else:
                reply = self._write("acl_add_replace", acl_index=int(current.acl_index) if current is not None else self.NEW_ACL,
                                    tag=tag, count=len(rules), r=[r.to_api() for r in rules])
                acl_index = int(reply.acl_index)
            bound = next(iter(self._call("acl_interface_list_dump", sw_if_index=index)), None)
            if bound is None or int(bound.n_input) != 1 or [int(a) for a in bound.acls] != [acl_index]:
                self._write("acl_interface_set_acl_list", sw_if_index=index, count=1, n_input=1, acls=[acl_index])
            applied[tenant["tenant_key"]] = authorized_addresses(rules)
        for tag, acl in existing.items():
            if tag not in wanted_tags:
                try:
                    self._write("acl_del", acl_index=int(acl.acl_index))
                except RuntimeError:
                    pass  # still bound somewhere; leave it for an operator
        self.applied = applied
        return applied

    def _write(self, method: str, **kwargs: Any) -> Any:
        self.writes.append(method)
        return self._call(method, **kwargs)

    def _call(self, method: str, **kwargs: Any) -> Any:
        fn = getattr(self.api, method, None)
        if fn is None:
            raise RuntimeError(f"VPP API lacks {method}")
        result = fn(**kwargs)
        retval = int(getattr(result, "retval", 0) or 0)
        if retval:
            raise RuntimeError(f"{method} failed with retval={retval}")
        return result
