# ADR-015: Pre-auth HTTP redirect with ABF and a host redirector (Phase 6)

## Status

Implemented and verified on the lab VM (2026-11-17,
`artifacts/test-reports/2026-11-17-p6-http-redirect.txt`). Part of D-09
candidate B (ACL plugin + ABF). D-09 stays PROVISIONAL: candidate A (SVS) and
the churn/scale measurements are not done.

## Context

Plan Phase 6 requires that unauthenticated HTTP (tcp/80) to any host is
answered with an HTTP 302 to the portal, while everything else that is not on
the pre-auth allowlist stays dropped (HTTPS, QUIC, DoT, other ports, IPv6).
VPP has no nftables-style REDIRECT. HTTPS cannot be redirected without
interception, which the plan forbids (F-09).

Measured on VPP 26.10 (`show features verbose host-vpp-access.101`): on the
`ip4-unicast` arc `acl-plugin-in-ip4-fa` runs at position 1 and
`abf-input-ip4` at position 12. The tenant input ACL therefore decides first;
ABF only sees packets the ACL permitted.

## Decision

- **VPP, per tenant (controller-owned, `--enable-vpp-writes`):**
  - The tenant input ACL (`bsnl:acl/<tenant>`) gains one rule, *after* the
    protected-prefix and intra-tenant denies and the per-subscriber permits:
    `permit <tenant subnet> -> 0.0.0.0/0 tcp dport 80`. Management LAN and
    gateway host HTTP stay denied.
  - An ABF policy (match ACL tagged `bsnl:abf/<tenant>`, one recursive path
    to `http_redirect.next_hop`, lab `198.51.100.2`) is attached to the
    tenant sub-interface (IPv4). Its ACL `deny` rules mean "do not steer":
    HTTP the pre-auth allowlist already permits (the portal) and HTTP from an
    authenticated subscriber to its `authenticated_destinations`; the final
    `permit <tenant subnet> tcp dport 80` steers the rest.
  - Order of writes: ABF match ACL, ABF policy and attachment first, then the
    tenant ACL with the HTTP permit; on removal the tenant ACL is rewritten
    without the permit before the ABF objects are deleted. The permit never
    exists without the steering, so a failure fails closed.
  - The ABF policy id is derived from the tag (crc32) and the policy is found
    again by its match ACL index; a next-hop change replaces the policy.
  - `applied` (and `dataplane_enforced`) for a subscriber requires both its
    ACL permit and its ABF exemption.
- **Host:** `bsnl-vpp-portal.nft` redirects `br-wan` tcp/80 from the tenant
  subnet (except to the portal) to `:8080`, where
  `bsnl-vpp-redirector.service` (`controller/redirector.py`, stdlib, systemd
  `DynamicUser`) answers every request with `302 Found`,
  `Location: https://wifi.bsnl.co.in/portal/login/`, `Cache-Control:
  no-store`, `Connection: close`. The Location never depends on the request;
  connections are bounded (256) with a 5 s socket timeout; nothing is logged
  per request. A new forward rule drops any other subscriber traffic the host
  would forward (only the portal path is forwarded).
- **API pinning:** ABF messages are "in-progress" in 26.x (not under the
  compatibility process). `abf_policy_add_del`, `abf_policy_dump`,
  `abf_itf_attach_add_del` and `abf_itf_attach_dump` are added to
  `artifacts/api-crc-26.10.json`; the controller refuses to run on a mismatch.
  `vpp_papi` needs the fixed 16-entry `label_stack` in every `fib_path`.

## Consequences

- Login churn now rewrites two ACLs per activation (tenant ACL and ABF match
  ACL). The replace cost at 1k/10k subscribers is part of the open D-09
  measurement.
- HTTPS typed before login fails (connection timeout), as documented in the
  plan's client matrix; OS captive detection relies on split DNS (ADR-014),
  RFC 8910/8908 (option 114) and this redirect.
- In P7, when `authenticated_destinations` becomes the internet, authenticated
  subscribers' HTTP to those destinations is exempt from steering by the same
  rules; HTTP to protected prefixes stays denied.
- The redirector and the nft redirect run on the gateway host (D-18
  co-located option). For pilot, the redirector moves with the portal path
  off the management NIC (ADR-012 exit plan).

## Rollback

Remove `http_redirect` from the tenant policy in desired state and restart the
controller: it rewrites the tenant ACL without the HTTP permit, then deletes
the ABF policy, attachment and match ACL. `systemctl disable --now
bsnl-vpp-redirector`. Host files from before the change:
`/root/bsnl-p6-redirect-20261117T062602.tgz`.
