# ADR-010: Subscriber authorization via per-tenant ACL (D-09, provisional)

## Status

Candidate B (this ADR) is implemented and deployed. D-09 was measured on
2026-11-17 (section "D-09 measurement"): B does not meet the Phase 6 churn
criteria beyond ~1k subscribers per tenant; candidate A (SVS) does at 10k.
**Recommendation: adopt A for per-subscriber authorization** (proposal below).
Not adopted yet: it changes the lab's routing model (ADR-011, D-06) and needs
owner approval. C (classifier) was not measured.

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
the controller re-applies the tenant ACL: its 1 s watch loop notices the new
VPP, waits until `bsnl-lab.cli` has finished (the sub-interface has an input
ACL bound) so it never races VPP's startup config, then re-applies. Measured
2026-11-17: authenticated subscribers lose access for 3.8–5.0 s per VPP
restart (was 30–32 s). The VPP af_packet MACs are pinned in `bsnl-lab.cli`;
random MACs per restart had left stale gateway ARP entries on subscribers and
on the host for another 30–50 s.

## Consequences

- An ACL replace per login: cost grows with authenticated subscribers per
  tenant. Measure replace latency at 1k/10k entries (K-05) before choosing
  between A and B.
- The lab authorizes only `192.0.2.0/24` (VPP's own fixture address): the
  mechanism is observable without any internet path. Widening it requires
  NAT and IPDR (P7).

## D-09 measurement (2026-11-17)

Tool: `tools/d09_bench.py` against a throw-away VPP 26.10 on the lab VM
(`tools/d09/`, own sockets, core 2; lab VPP on core 3 untouched), af_packet,
one main thread. Raw data: `artifacts/test-reports/2026-11-17-d09-acl-vs-svs.json`.
Lab-VM numbers are relative evidence, not production capacity.

Per activation, N authenticated subscribers already present (20 samples):

| N | B: controller apply (tenant ACL + ABF ACL), p50 / p95 | B: raw `acl_add_replace` of N rules | B: `acl_dump` | A: `svs_route_add_del` p50 / p95 |
|---|---|---|---|---|
| 100 | 23 / 25 ms | 2.8 ms | 3.5 ms | 0.42 / 0.46 ms |
| 1 000 | 181 / 234 ms | 24.5 ms | 33 ms | 0.44 / 0.58 ms |
| 10 000 | 3 167 / 3 457 ms | 250 ms | 924 ms | 0.48 / 0.77 ms |

B's converged no-op apply alone costs 17 ms / 133 ms / 2.7 s (it dumps and
compares both ACLs). Even a perfect controller would need two N-rule replaces
per login: ~0.5 s at 10k.

Churn (60 s each) while an authenticated probe pings a VPP address every 5 ms
(baseline 0 / 3 999 lost):

| N | target | B achieved, op p95 | B probe loss | A achieved, op p95 | A probe loss |
|---|---|---|---|---|---|
| 1 000 | 10/s | 4.3/s, 308 ms | 0 / 11 984 | 10.0/s, 1.6 ms | 0 / 11 999 |
| 1 000 | 50/s | 4.2/s, 330 ms | 0 / 11 988 | 50.0/s, 1.4 ms | 1 / 11 999 |
| 10 000 | 10/s | 0.3/s, 3.8 s | 0 / 11 979 | 10.0/s, 1.3 ms | 1 / 12 001 |
| 10 000 | 50/s | 0.3/s, 3.8 s | 0 / 11 980 | 50.0/s, 1.5 ms | 0 / 12 001 |

Neither candidate disturbed forwarding for already-authenticated
subscribers (single lost probes at 0.008 % are within noise; not a 10-minute
run). B fails the plan's 10/s and 50/s activation criteria already at 1k.

SVS correctness (R-11), bench, no input ACL: sub-interface in a captive VRF
with no route to the target, target in an internet VRF, cross-VRF return
route. No SVS entry: blocked. `/32 -> internet VRF` for .7: .7 reaches, .8
falls through to the captive VRF (blocked). Adding/removing .8's entry
toggles only .8.

## Proposal: candidate A (not implemented)

- Tenant sub-interface in a per-tenant **captive VRF** whose only routes are
  the portal, the resolver and a default route to the redirector next hop
  (replaces ABF for the HTTP redirect; the host's nft drops everything except
  redirected tcp/80, ADR-015).
- SVS table on the sub-interface; one `svs_route` (/32 -> internet VRF) per
  authenticated subscriber: O(1) per login, no per-subscriber ACL or ABF rules.
- The tenant ACL becomes static: pre-auth allowlist, protected denies,
  intra-tenant deny, `permit <subnet> any`, deny-all (ports to the portal and
  resolver stay restricted; anything else is decided by the VRF).
- Internet VRF needs return routes to the tenant subnet (and NAT in P7).
- MAC enforcement (ADR-016) is unchanged (classifier sessions are O(1)).
- Changes the lab routing model (ADR-011: tenants in VRF 0 until D-06) and
  restart recovery; needs the bypass suite, portal E2E and restart tests again.

## Evidence

`tests/test_step5.py`; live: `sudo python3 -m controller.bypass_suite`
(pre-auth) and `--phase authorized --static-ip <ip>` after activation.
