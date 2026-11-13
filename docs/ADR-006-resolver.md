# ADR-006: Lab Linux resolver and DHCP captive signalling

## Status

Lab-qualified resolver and existing-portal integration. Subscriber
enforcement and captive redirection policy are not implemented.

## Design

- dnsmasq listens only on `br-wan` at `198.51.100.2`.
- DHCP remains exclusively owned by Kea; dnsmasq DHCP is disabled.
- Kea advertises DNS server `198.51.100.2`.
- Kea advertises DHCPv4 option 114 (`v4-captive-portal`, RFC 8910). From
  remediation step 5 it carries the RFC 8908 Captive Portal API URI
  `https://wifi.bsnl.co.in/portal/captive-api/` (was the HTML login page,
  which RFC 8908 clients cannot parse).
- Captive DNS records come from `config/lab/host-services.json`
  (`captive_hosts`, `portal_address`, `local_names`); nothing is hard-coded.
- `portal.lab` is a local resolver fixture mapped to `198.51.100.2`.
- `wifi.bsnl.co.in` and captive-check hostnames map to the existing portal at
  `10.44.0.209`.
- The Linux bridge path has a persistent return route for `10.9.101.0/24`
  via VPP `198.51.100.1`.

## Verification

The QinQ client path returns `portal.lab A 198.51.100.2` and
`wifi.bsnl.co.in A 10.44.0.209`; Kea advertises option 114 with the existing
portal URL. HTTP `/generate_204` and HTTPS `/portal/login/` both return `200`
from a QinQ subscriber test.

## Deferred

Split-horizon pre-auth/authenticated policy, DNS blocking to unauthorized
resolvers, VPP captive redirection/enforcement, DNSSEC policy, resolver HA and
production scale remain open gates.
