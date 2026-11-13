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
