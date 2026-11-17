# ADR-017: Per-subscriber authorization with Source VRF Select (D-09 = A)

## Status

Adopted for the lab on 2026-11-17 (owner approval in session), deployed and
verified: `artifacts/test-reports/2026-11-17-d09-svs-lab.txt`. Decision basis:
D-09 measurement in ADR-010. Supersedes the per-subscriber ACL rules of
ADR-010 and the ABF steering of ADR-015 for tenants with
`authorization: "svs"`; both remain available with `authorization: "acl"`.

## Decision

- **VRFs.** The tenant sub-interface is in a per-tenant captive VRF
  (`tenant.vrf_id`, lab 101). The internet VRF is `policy.internet_vrf`
  (lab table 0: WAN, the 192.0.2.0/24 target, the portal route).
- **Per subscriber.** An SVS table (`tenant.svs_table_id`, lab 1101) is
  enabled on the sub-interface; each authenticated subscriber has one entry
  `<ip>/32 -> lookup in internet_vrf`. Sources without an entry are forwarded
  in the captive VRF (R-11, verified). Login/logout is one
  `svs_route_add_del` (fast path in `VppApiAdapter.enforce_subscriber`; any
  error falls back to a full apply); reconcile ticks converge the entries from
  `ip_route_dump` of the SVS table.
- **Static tenant ACL** (`compile_tenant_acl(..., authorization="svs")`):
  pre-auth allowlist, protected destinations denied, intra-tenant deny,
  `permit <subnet> -> authenticated_destinations`, `permit <subnet> tcp/80`
  (redirect), deny-all. It never changes per login.
- **Captive VRF routes** (lab fixture `deployment/vpp/bsnl-lab.cli`): portal
  /32, resolver /32 and `0.0.0.0/0`, all attached `via 198.51.100.2
  host-vpp-wan`. The default route replaces ABF for the HTTP redirect: the
  host redirects tcp/80 to the redirector and drops everything else
  (`bsnl-vpp-portal.nft` forward drop; new input chain: subscribers may reach
  only DNS, DHCP and the redirector on the host).
- **Return path** (fixture): table 0 has `10.9.101.0/24 via
  host-vpp-access.101` (attached, so VPP's local source check passes for
  traffic to VPP's own addresses) and `10.9.101.1/32 via ip4-lookup-in-table
  101` (Kea's replies to the relay address). The DHCP proxy is
  `rx-fib-id 101 server-fib-id 0`.
- **Safety checks.** SVS mode is refused unless the captive VRF differs from
  the internet VRF and the SVS table differs from both (the static ACL relies
  on the VRF split). Switching back to `acl` removes SVS state after the
  per-subscriber ACL is written. SVS messages are CRC-pinned; `svs_plugin`
  must be loaded (`startup.conf.lab`).

## Consequences

- Per-login dataplane cost is O(1) (~0.5 ms in VPP; 50 logins/s sustained at
  10k subscribers on the bench). The controller API round trip is ~72 ms p50
  in the lab, dominated by TLS and the per-login Unbound reload (ADR-014),
  which is now the scaling item to batch.
- Pre-auth traffic that VPP used to drop now reaches the gateway host and is
  dropped by nftables; the host's nft rules are part of the pre-auth policy.
- Authenticated HTTP is no longer redirected (lab: no route, P7 adds the
  internet). MAC enforcement (ADR-016) is unchanged.
- The lab tenant is no longer in VRF 0 (ADR-011 updated). Two fixture faults
  were found and fixed during verification: a recursive captive route to
  198.51.100.2 through itself resolved to drop, and a lookup-in-table return
  route made VPP's local source check drop authenticated pings.

## Rollback

Set the policy's `authorization` to `"acl"` and the tenant's `vrf_id` to 0 in
desired state, restore the pre-SVS fixture and nft rules from
`/root/bsnl-d09-svs-20261117T083051.tgz` (and `startup.conf` from
`/root/startup.conf.pre-svs-*` if desired), restart VPP and then the
controller.
