# ADR-011: Lab tenants share the default FIB (VRF 0)

## Status

Lab decision. D-06 (shared FIB vs VRF-per-tenant) stays open until the R-02
range-overlap inventory exists.

## Context

The live sub-interface `host-vpp-access.101` and the portal route
`10.44.0.0/22 via 198.51.100.2` are in table 0. The earlier desired state set
`vrf_id: 101`. Once controller writes were enabled, the controller would have
moved the sub-interface into an empty VRF 101 and cut subscribers off from DHCP
relay replies, DNS and the portal.

## Decision

The lab desired state uses `vrf_id: 0`. A tenant VRF requires the matching
routes (portal, resolver, upstream) in that VRF first; that is part of D-06.

## Related

The Kea subnet id of the lab tenant is pinned to 101 (`kea_subnet_id`) so the
existing lease file stays valid after the subnet-id rule changed (finding C-7).

## Update 2026-11-17: captive VRF 101 with SVS (ADR-017)

With D-09 decided for SVS, the lab tenant now uses `vrf_id: 101` as a captive
VRF, which is what this ADR required first: the fixture (`bsnl-lab.cli`) adds
the portal, resolver and default routes in VRF 101, the table-0 return routes
and the DHCP proxy for `rx-fib-id 101`. Table 0 is the internet VRF. D-06
(VRF per tenant vs shared, overlapping ranges) remains open for production.
