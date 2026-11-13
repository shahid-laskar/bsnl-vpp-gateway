# ADR-005: QinQ tenant DHCP relay to Kea

## Status

Lab-qualified for one tenant using the verified `0x8100/200 + 0x8100/101`
QinQ fixture. This is not a production DHCP scale or failover qualification.

## Design

- VPP DHCP plugin and proxy are enabled.
- VPP relays subscriber traffic with relay address `198.51.100.1` to Kea at
  `198.51.100.2`.
- Kea listens on `br-wan` at `198.51.100.2/24`.
- Kea selects the `10.9.101.0/24` subnet from the relay address and allocates
  `10.9.101.5-10.9.101.105`.
- Kea supplies the tenant gateway `10.9.101.1`, DNS `198.51.100.2`, and
  DHCPv4 option 114 pointing to the lab portal URL.

## Evidence

An isolated QinQ client completed DHCPDISCOVER → DHCPOFFER → DHCPREQUEST →
DHCPACK and received `10.9.101.5/24` with a 300-second lease and default
route `10.9.101.1`. Packet capture decoded option 114 in both OFFER and ACK:
`http://198.51.100.2:8080/portal`.
That capture predates the portal integration. Option 114 later pointed at the
login page and, from remediation step 5, at the RFC 8908 API
`https://wifi.bsnl.co.in/portal/captive-api/`; re-capture with
`sudo python3 -m controller.dhcp_qualification` after reinstalling Kea.

## Deferred

Lease-event enrichment, multi-tenant overlap, DHCP failover, outage/restart
behavior, production scale, and captive-portal enforcement remain open gates.
