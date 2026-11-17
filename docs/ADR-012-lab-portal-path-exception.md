# ADR-012: Lab exception — portal reached through the management NIC

## Status

Accepted **for the VM lab only**. Must not be carried into pilot.

## Context

The existing portal (`10.44.0.209`) sits on the management network
`10.44.0.0/22`. To reach it, VPP routes `10.44.0.0/22` to the Linux host, which
forwards and SNATs subscriber traffic out of `ens18`
(`bsnl-vpp-portal-path.service`, `deployment/nftables/bsnl-vpp-portal.nft`).
FINAL plan P-03 keeps management traffic on a dedicated Linux-owned interface;
this lab path lets subscriber traffic onto that interface.

## Mitigations in place

- The nftables rules only forward `10.9.101.0/24 -> 10.44.0.0/22` and return
  traffic, SNATed to `10.44.0.207`.
- The VPP tenant ACL permits only portal `10.44.0.209` ports 80/443 and ICMP;
  the rest of `10.44.0.0/22` is a protected destination (ADR-010), including
  for authenticated subscribers.

## Update 2026-11-17: no SNAT to the portal

The portal derives the router (second octet of the client address: 10.9.x.x ->
instance 9) and the customer (address range) from the subscriber's own
address, so SNAT to 10.44.0.207 made a portal login from the lab impossible.
`bsnl-vpp-portal.nft` now accepts 10.9.101.0/24 -> 10.44.0.209 without NAT
(other management destinations stay SNATed), and the portal host routes
10.9.101.0/24 via 10.44.0.207. That route was added at runtime
(`ip route add`); it must be made persistent in the portal host's
`/etc/network/interfaces` (owner action) or it is lost on reboot. Rollback:
`/root/portal-path.nft.pre-nosnat-20261117`.

## Exit plan

In pilot the portal is reachable through a service network on the VPP WAN
side (or a dedicated portal VIP). The portal-path unit and the SNAT rule are
then removed.
