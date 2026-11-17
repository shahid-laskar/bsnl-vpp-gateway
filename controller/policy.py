"""Subscriber access policy compiled to a per-tenant VPP ACL (plan Phase 6,
candidate B of D-09; remediation step 5).

The tenant's input ACL on its QinQ sub-interface is first-match:

1. pre-auth allowlist  (DHCP incl. unicast renew, DNS to the gateway resolver,
                        portal HTTP/HTTPS/ICMP) - for every source in the tenant
2. protected prefixes  denied for everyone (management LAN, gateway host),
                        so authorization can never reach them
3. one permit per authenticated subscriber /32 to the policy's
                        ``authenticated_destinations``
4. HTTP redirect permit (only with ``http_redirect``): tcp/80 from the
                        tenant to any destination not denied above
5. explicit deny-all   (counted; IPv6 is never permitted - F-10)

HTTP redirect (Phase 6, ADR-015): VPP's ACL input feature runs before ABF on
the ip4-unicast arc, so pre-auth HTTP must first be permitted by the tenant ACL
(rule 4) and is then steered by an ABF policy to the redirector next hop. The
ABF match ACL (``compile_redirect_acl``) never steers HTTP to destinations the
pre-auth allowlist already permits (the portal) nor HTTP from an authenticated
subscriber to its authenticated destinations. The controller writes the ABF
policy and attachment *before* the tenant ACL that carries rule 4, so the
permit never exists without the steering.

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


HTTP = (80, 80)
ALL_PORTS = (0, 65535)


def _tenant_subnet(tenant: dict[str, Any]) -> str:
    return str(ipaddress.ip_interface(tenant["gateway_ip"]).network)


def _authenticated(tenant: dict[str, Any], subnet: str, subscribers: list[dict[str, Any]]) -> list[str]:
    active = sorted({s["private_ipv4"] for s in subscribers
                     if s.get("tenant_key") == tenant["tenant_key"] and s.get("state") == "authenticated"},
                    key=lambda ip: ipaddress.ip_address(ip))
    for address in active:
        if ipaddress.ip_address(address) not in ipaddress.ip_network(subnet):
            raise PolicyValidationError(f"subscriber {address} outside tenant subnet {subnet}")
    return active


def _destinations(policy: dict[str, Any]) -> list[str]:
    return [_net(d, "authenticated_destinations") for d in policy.get("authenticated_destinations", [])]


def redirect_config(policy: dict[str, Any]) -> dict[str, str] | None:
    """The policy's ``http_redirect`` ({"next_hop": IPv4}) or None."""
    config = policy.get("http_redirect")
    if config is None:
        return None
    if not isinstance(config, dict) or "next_hop" not in config:
        raise PolicyValidationError("http_redirect must be an object with next_hop")
    try:
        next_hop = ipaddress.ip_address(config["next_hop"])
    except ValueError as exc:
        raise PolicyValidationError(f"http_redirect.next_hop: invalid address {config['next_hop']!r}") from exc
    if next_hop.version != 4:
        raise PolicyValidationError("http_redirect.next_hop: IPv4 only")
    return {"next_hop": str(next_hop)}


def compile_tenant_acl(tenant: dict[str, Any], policy: dict[str, Any], subscribers: list[dict[str, Any]],
                       *, redirect: bool = False) -> list[AclRule]:
    subnet = _tenant_subnet(tenant)
    rules = preauth_rules(policy, subnet)
    rules += [AclRule(DENY, ANY4, _net(p, "protected_destinations")) for p in policy.get("protected_destinations", [])]
    if tenant.get("intra_tenant_policy", "block") == "block":
        # Subscriber-to-subscriber traffic routed through the gateway (R-23
        # default). Traffic bridged by the access network never reaches VPP.
        rules.append(AclRule(DENY, ANY4, subnet))
    destinations = _destinations(policy)
    for address in _authenticated(tenant, subnet, subscribers):
        rules += [AclRule(PERMIT, f"{address}/32", dst) for dst in destinations]
    if redirect:
        # Permitted here only so that the ABF policy (after the ACL on the
        # ip4-unicast arc) can steer it to the redirector; protected and
        # intra-tenant destinations are already denied above.
        rules.append(AclRule(PERMIT, subnet, ANY4, PROTO["tcp"], ALL_PORTS, HTTP))
    rules.append(AclRule(DENY, ANY4, ANY4))
    return rules


def compile_redirect_acl(tenant: dict[str, Any], policy: dict[str, Any], subscribers: list[dict[str, Any]]) -> list[AclRule]:
    """ABF match ACL: ``permit`` = steer to the redirector, ``deny`` = forward normally."""
    subnet = _tenant_subnet(tenant)
    rules = []
    for rule in preauth_rules(policy, subnet):
        # HTTP that the pre-auth allowlist already permits (the portal) is never steered.
        if rule.is_permit == PERMIT and rule.proto in (0, PROTO["tcp"]) and rule.dst_ports[0] <= 80 <= rule.dst_ports[1]:
            rules.append(AclRule(DENY, rule.src_prefix, rule.dst_prefix, PROTO["tcp"], ALL_PORTS, HTTP))
    destinations = _destinations(policy)
    for address in _authenticated(tenant, subnet, subscribers):
        rules += [AclRule(DENY, f"{address}/32", dst, PROTO["tcp"], ALL_PORTS, HTTP) for dst in destinations]
    rules.append(AclRule(PERMIT, subnet, ANY4, PROTO["tcp"], ALL_PORTS, HTTP))
    return rules


def authorized_addresses(rules: list[AclRule]) -> set[str]:
    return {r.src_prefix.split("/")[0] for r in rules if r.is_permit == PERMIT and r.src_prefix.endswith("/32")}


def redirect_exempt_addresses(rules: list[AclRule]) -> set[str]:
    return {r.src_prefix.split("/")[0] for r in rules if r.is_permit == DENY and r.src_prefix.endswith("/32")}


def tenant_policy(state: dict[str, Any], tenant: dict[str, Any]) -> dict[str, Any] | None:
    ref = tenant.get("pre_auth_policy_ref")
    policy = (state.get("policies") or {}).get(ref) if ref else None
    if policy is None or not policy.get("dataplane_apply", False):
        return None
    return policy


def _tag(kind: str, tenant_key: str) -> str:
    import hashlib
    tag = f"bsnl:{kind}/{tenant_key}"
    return tag if len(tag) <= 63 else f"bsnl:{kind}/" + hashlib.sha256(tenant_key.encode()).hexdigest()[:40]


def acl_tag(tenant_key: str) -> str:
    return _tag("acl", tenant_key)


def redirect_tag(tenant_key: str) -> str:
    """Tag of the tenant's ABF match ACL; the ABF policy using it is controller-owned."""
    return _tag("abf", tenant_key)


def _get(obj: Any, key: str) -> Any:
    return obj[key] if isinstance(obj, dict) else getattr(obj, key)


def fib_path_ip4(next_hop: str) -> dict[str, Any]:
    """vl_api_fib_path_t for a recursive IPv4 next hop in table 0.

    vpp_papi packs fixed-size arrays strictly: ``label_stack`` (16 entries)
    must be present even with ``n_labels`` 0.
    """
    no_label = {"is_uniform": 0, "label": 0, "ttl": 0, "exp": 0}
    return {"sw_if_index": 0xFFFFFFFF, "table_id": 0, "rpf_id": 0, "weight": 1, "preference": 0,
            "type": 0, "flags": 0, "proto": 0, "nh": {"address": {"ip4": next_hop}},
            "n_labels": 0, "label_stack": [dict(no_label) for _ in range(16)]}


def path_next_hops(policy: Any) -> list[str]:
    return [str(_get(_get(_get(p, "nh"), "address"), "ip4")) for p in _get(policy, "paths")]


def _text(value: Any) -> str:
    return value.decode().rstrip("\x00") if isinstance(value, bytes) else str(value or "").rstrip("\x00")


class VppPolicyEnforcer:
    """Converge each tenant's tagged input ACL and its interface binding, and
    (with ``http_redirect``) its tagged ABF match ACL, ABF policy and
    attachment.

    Zero writes when VPP already matches. ``applied`` maps tenant_key to the
    subscriber addresses whose permits are confirmed in VPP after the last
    successful apply (and, with redirect, whose HTTP is exempt from steering).
    """

    MUTATING = frozenset({"acl_add_replace", "acl_interface_set_acl_list", "acl_del",
                          "abf_policy_add_del", "abf_itf_attach_add_del",
                          "classify_add_del_table", "classify_add_del_session", "input_acl_set_interface"})
    NEW_ACL = 0xFFFFFFFF

    def __init__(self, api: Any, enable_writes: bool = False) -> None:
        self.api = api
        self.enable_writes = enable_writes
        self.writes: list[str] = []
        self.applied: dict[str, set[str]] = {}
        self.mac_enforced: dict[str, set[str] | None] = {}

    def apply(self, state: dict[str, Any], interface_index: dict[str, int],
              bindings: list[dict[str, Any]] | None = None) -> dict[str, set[str]]:
        """``bindings``: open lease bindings (MAC enforcement); None = no lease source."""
        from .mac_enforcement import MacEnforcer
        self.writes = []
        self.mac_enforced = {}
        if not self.enable_writes:
            raise RuntimeError("VPP writes are disabled")
        existing = {_text(a.tag): a for a in self._call("acl_dump", acl_index=self.NEW_ACL)
                    if _text(getattr(a, "tag", "")).startswith(("bsnl:acl/", "bsnl:abf/"))}
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
            subscribers = state.get("subscribers", [])
            redirect = redirect_config(policy)
            exempt = None
            if redirect is not None:
                # Steering first: the tenant ACL's HTTP permit must never exist
                # without the ABF policy that sends it to the redirector.
                abf_rules = compile_redirect_acl(tenant, policy, subscribers)
                abf_tag = redirect_tag(tenant["tenant_key"])
                wanted_tags.add(abf_tag)
                abf_acl = self._converge_acl(abf_tag, abf_rules, existing.get(abf_tag))
                self._converge_abf(abf_tag, abf_acl, redirect["next_hop"], index)
                exempt = redirect_exempt_addresses(abf_rules)
            rules = compile_tenant_acl(tenant, policy, subscribers, redirect=redirect is not None)
            tag = acl_tag(tenant["tenant_key"])
            wanted_tags.add(tag)
            acl_index = self._converge_acl(tag, rules, existing.get(tag))
            bound = next(iter(self._call("acl_interface_list_dump", sw_if_index=index)), None)
            if bound is None or int(bound.n_input) != 1 or [int(a) for a in bound.acls] != [acl_index]:
                self._write("acl_interface_set_acl_list", sw_if_index=index, count=1, n_input=1, acls=[acl_index])
            # MAC/IP source check from lease bindings (ADR-016), after the ACL so
            # a permit is in place before traffic of a new binding is allowed.
            self.mac_enforced[tenant["tenant_key"]] = MacEnforcer(self._call, self._write).apply(tenant, index, bindings)
            authorized = authorized_addresses(rules)
            applied[tenant["tenant_key"]] = authorized if exempt is None else authorized & exempt
        # Unwanted objects go after every tenant ACL is rewritten (an HTTP
        # permit is dropped before the ABF policy that steered it).
        for tag, acl in existing.items():
            if tag in wanted_tags:
                continue
            try:
                if tag.startswith("bsnl:abf/"):
                    self._remove_abf(int(acl.acl_index))
                self._write("acl_del", acl_index=int(acl.acl_index))
            except RuntimeError:
                pass  # still bound somewhere; leave it for an operator
        self.applied = applied
        return applied

    def _converge_acl(self, tag: str, rules: list[AclRule], current: Any) -> int:
        if current is not None and [AclRule.from_api(r) for r in current.r] == rules:
            return int(current.acl_index)
        reply = self._write("acl_add_replace", acl_index=int(current.acl_index) if current is not None else self.NEW_ACL,
                            tag=tag, count=len(rules), r=[r.to_api() for r in rules])
        return int(reply.acl_index)

    # ABF (in-progress API in 26.x: CRC-pinned, see artifacts/api-crc-*.json) --------------
    def _abf_policies(self) -> list[Any]:
        return [d.policy for d in self._call("abf_policy_dump")]

    def _abf_attachments(self) -> list[Any]:
        return [d.attach for d in self._call("abf_itf_attach_dump")]

    def _converge_abf(self, tag: str, acl_index: int, next_hop: str, sw_if_index: int) -> None:
        policies = self._abf_policies()
        policy = next((p for p in policies if int(p.acl_index) == acl_index), None)
        if policy is not None and path_next_hops(policy) != [next_hop]:
            self._remove_abf(acl_index)
            policy = None
        if policy is None:
            import zlib
            used = {int(p.policy_id) for p in policies}
            policy_id = zlib.crc32(tag.encode()) & 0x7FFFFFFF
            while policy_id in used:
                policy_id = (policy_id + 1) & 0x7FFFFFFF
            self._write("abf_policy_add_del", is_add=True, policy={"policy_id": policy_id, "acl_index": acl_index,
                                                                    "n_paths": 1, "paths": [fib_path_ip4(next_hop)]})
        else:
            policy_id = int(policy.policy_id)
        attached = False
        for attach in self._abf_attachments():
            if int(attach.policy_id) != policy_id:
                continue
            if int(attach.sw_if_index) == sw_if_index and not bool(attach.is_ipv6):
                attached = True
            else:
                self._detach(attach)
        if not attached:
            self._write("abf_itf_attach_add_del", is_add=True,
                        attach={"policy_id": policy_id, "sw_if_index": sw_if_index, "priority": 0, "is_ipv6": False})

    def _detach(self, attach: Any) -> None:
        self._write("abf_itf_attach_add_del", is_add=False,
                    attach={"policy_id": int(attach.policy_id), "sw_if_index": int(attach.sw_if_index),
                            "priority": int(attach.priority), "is_ipv6": bool(attach.is_ipv6)})

    def _remove_abf(self, acl_index: int) -> None:
        """Detach and delete every ABF policy that matches on ``acl_index``."""
        for policy in self._abf_policies():
            if int(policy.acl_index) != acl_index:
                continue
            for attach in self._abf_attachments():
                if int(attach.policy_id) == int(policy.policy_id):
                    self._detach(attach)
            hops = path_next_hops(policy)
            self._write("abf_policy_add_del", is_add=False, policy={"policy_id": int(policy.policy_id), "acl_index": acl_index,
                                                                     "n_paths": len(hops), "paths": [fib_path_ip4(h) for h in hops]})

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
