# ADR-010: Subscriber authorization via per-tenant ACL (D-09, provisional)

## Status

Provisional. Candidate B of D-09 is implemented; candidate A (VRF steering
with SVS) and C (classifier) have **not** been measured. D-09 stays open
until churn and scale are measured (Phase 6 exit).

## Decision

One controller-owned input ACL per tenant sub-interface, tagged
`bsnl:acl/<tenant>`, compiled from desired state (`controller/policy.py`),
first match:

1. pre-auth allowlist (DHCP broadcast and unicast renew, DNS to the gateway
   resolver, portal HTTP/HTTPS/ICMP);
2. protected destinations denied (management LAN, gateway host);
3. intra-tenant deny (R-23 default `block`);
4. one stateless permit per authenticated subscriber /32 to the policy's
   `authenticated_destinations`;
5. explicit deny-all. IPv6 entries are rejected (F-10).

The controller applies a change before answering the portal and reports
`dataplane_enforced` only after VPP confirms the subscriber's rule.
Stateless permits on ingress mean deactivation blocks new and existing flows
immediately; return traffic is not filtered.

Without `--enable-vpp-writes`, the static ACL in `deployment/vpp/bsnl-lab.cli`
stays in force (fail closed). After a VPP restart the static ACL applies until
the next reconcile tick (≤ 30 s), so authenticated subscribers lose access for
up to that long.

## Consequences

- An ACL replace per login: cost grows with authenticated subscribers per
  tenant. Measure replace latency at 1k/10k entries (K-05) before choosing
  between A and B.
- The lab authorizes only `192.0.2.0/24` (VPP's own fixture address): the
  mechanism is observable without any internet path. Widening it requires
  NAT and IPDR (P7).

## Evidence

`tests/test_step5.py`; live: `sudo python3 -m controller.bypass_suite`
(pre-auth) and `--phase authorized --static-ip <ip>` after activation.
