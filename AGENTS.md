# Agent handoff: BSNL VPP gateway lab

## Project and access

- Remote project: `/opt/bsnl-vpp-gateway`
- Lab VM: `shahid@10.44.0.207`
- Existing Django captive portal: `10.44.0.209`
- This is a development lab. Do not describe it as production-ready.
- Never expose credentials in documentation, logs, or commits.

## Read these first

1. `README.md`
2. `docs/IMPLEMENTATION_STATUS.md` — authoritative current state and evidence
3. `docs/LAB_RUNBOOK.md` — operational checks
4. Relevant ADRs, especially `ADR-007-portal-integration.md` and
   `ADR-008-preauth-policy.md`
5. Original plan: `/opt/captive-portal/captive-portal-multitenant/docs/vpp/FINAL_IMPLEMENTATION_PLAN.md`

Keep project source files under this directory synchronized with runtime files.
Runtime state is on the VM; don't assume edits in the Django repository alter
the remote gateway.

## Topology and addresses

| Purpose | Address/interface |
|---|---|
| VM management | `ens18`, `10.44.0.207/22`; default gateway `10.44.1.234` |
| Access attachment | `ens19` → `br-access` → veth → VPP `host-vpp-access` |
| WAN attachment | `ens20` → `br-wan` → veth → VPP `host-vpp-wan` |
| QinQ | outer `0x8100` VLAN 200, inner `0x8100` VLAN 101, exact match |
| Subscriber subnet | `10.9.101.0/24`, VPP gateway `10.9.101.1` |
| DHCP pool | `10.9.101.5–10.9.101.105` |
| VPP host-side WAN | `198.51.100.1/24` |
| Linux WAN bridge address | `198.51.100.2/24`; Kea and dnsmasq listen here |
| Existing portal | `10.44.0.209`; hostname `wifi.bsnl.co.in` |

`ens18` must remain Linux-managed and outside VPP/DPDK. Do not bind the VM NICs
to `uio_pci_generic` or `vfio-pci`. VPP uses `af_packet` over existing veth
endpoints. The requested outer TPID `0x88a8` failed in this VM path; use the
documented `0x8100` lab fixture unless explicitly re-qualifying it.

## Current implementation

- VPP 26.10, with DPDK plugin disabled for this VM.
- Persistent Linux bridge/veth and VPP af_packet interfaces.
- L3 and QinQ service interface.
- VPP DHCP proxy to Kea; Kea advertises DNS and RFC 8910 option 114 with
  `https://wifi.bsnl.co.in/portal/login/`.
- dnsmasq maps portal/captive-check names to `10.44.0.209`.
- VPP route to `10.44.0.0/22`; Linux forwarding and scoped SNAT allow
  subscribers to reach the existing portal without a portal-host return route.
- Persistent pre-auth ACL on `host-vpp-access.101`: DHCP, DNS to `198.51.100.2`,
  and HTTP/HTTPS/diagnostic ICMP to the portal are allowed; unmatched IPv4 is
  denied.

Verified from isolated QinQ namespaces: DHCP lease, DNS mapping, portal HTTP
`/generate_204` 200, HTTPS `/portal/login/` 200, portal reachability, and an
unapproved destination denied by the ACL. See implementation status for exact
test details and limits.

## Runtime services and source files

Enabled units include:

```text
vpp
bsnl-vpp-lab-links
bsnl-vpp-afpacket
bsnl-vpp-l3-forwarding
bsnl-vpp-qinq
bsnl-vpp-dhcp-proxy
bsnl-vpp-portal-path
bsnl-vpp-preauth
isc-kea-dhcp4-server
dnsmasq
```

Project-owned service/config templates live under `deployment/`; live configs
are installed under `/etc`, `/usr/local/sbin`, and systemd directories. The
pre-auth policy is lab-specific and currently uses ACL index 1. Its service
reapplies the ACL after the QinQ unit starts.

Useful read-only checks on the VM:

```bash
systemctl is-active vpp bsnl-vpp-lab-links bsnl-vpp-afpacket \
  bsnl-vpp-l3-forwarding bsnl-vpp-qinq bsnl-vpp-dhcp-proxy \
  bsnl-vpp-portal-path bsnl-vpp-preauth isc-kea-dhcp4-server dnsmasq
ip -br addr
ip route
vppctl show interface address
vppctl show acl-plugin interface
vppctl show ip fib 10.44.0.0/22
kea-dhcp4 -t /etc/kea/kea-dhcp4.conf
dnsmasq --test
```

## Next work

1. Implement an authenticated subscriber state and safe dynamic allowlisting.
   Do not grant broad internet access without a defined state source, expiry,
   idempotency, audit, and deactivation path.
2. Inspect the Django portal session lifecycle and define a signed or
   mutually-authenticated event/API from portal to gateway controller.
3. Replace hard-coded ACL index/rules with validated desired state and
   idempotent reconciliation. The current controller is only a dry-run
   skeleton; it is not yet the policy authority.
4. Add negative tests for IPv6, DoH/DoT, QUIC, spoofed source IP/MAC, and
   expired/deactivated subscribers before broadening policy.
5. Complete captive redirect behavior and RFC 8908 API only after an explicit
   design for the existing portal integration.

Do not enable authenticated internet forwarding as an assumed next step.
First map the portal's real session activation/deactivation callbacks and
define how the gateway learns authorization. Preserve VyOS behavior and its
rollback role during VPP development.
