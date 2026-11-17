# ADR-016: MAC/IP source enforcement with a controller-owned classifier chain (Phase 6)

## Status

Implemented and verified on the lab VM (2026-11-17,
`artifacts/test-reports/2026-11-17-p6-mac-enforcement.txt`). The lab tenant
runs `mac_enforcement: "enforce"`. Scale (sessions per tenant, churn) is not
measured.

## Context

Plan Phase 6 requires MAC enforcement per tenant from SubscriberBinding
(enforce / log-only), closing the "commented-out rule" gap of the VyOS
system: a device must not use another subscriber's IPv4 address or an address
it was never leased. Bindings (MAC, IP) come from Kea leases (ADR-013).

The plan names the ACL plugin's MACIP ACLs. Lab results on VPP 26.10
(2026-11-17):

- On the QinQ sub-interface `host-vpp-access.101` (outer and inner TPID
  0x8100, af_packet), a MACIP ACL dropped **all** IPv4, including the bound
  pair (trace: `ip4-inacl ... table_index -1 ... input ACL table-miss
  drops`). MACIP had built only L2/ARP classifier tables keyed from the
  Ethernet header with fixed tag layouts (0x88a8+0x8100 or a single 0x8100).
- On the untagged parent interface the same MACIP ACL worked (bound pair
  passed, unbound address dropped).
- A hand-built classifier table keyed from the Ethernet header never matched
  on the sub-interface at any offset; keyed relative to the IPv4 header
  (`current_data_flag 1`) it matched. With `current_data_offset -16` (22-byte
  L2 header with two tags, source MAC 6 bytes in) MAC + IP matched exactly.

## Decision

- Per enforcing tenant, the controller owns a two-table classifier chain,
  bound as the sub-interface's IPv4 input ACL (`input_acl_set_interface`,
  feature `ip4-inacl`):
  - head: mask = source MAC (IP − 16) + source IPv4 (IP + 12), 2 vectors,
    `current_data_flag 1`, `current_data_offset -16`, 4096 buckets, 16 MiB;
    one session per open binding (MAC, IP) of the tenant inside its subnet;
    miss → tail.
  - tail: mask = source IPv4, one session for `0.0.0.0` (DHCP from clients
    without an address); miss → drop.
  - a hit continues the ip4-unicast arc (ACL plugin and ABF already ran).
- Convergence: sessions are added/removed in place as bindings change; a new
  chain is bound only after its sessions exist; switching back to
  `log_only` unbinds and deletes the chain; an input ACL table the controller
  does not own (recognised by masks and chaining) is never changed.
  `classify_table_info` does not report the current-data flag/offset, so they
  are set at creation and checked in the lab with `show classify tables`.
- The lease watcher calls the reconciler when a binding opens or closes, so
  VPP follows leases within one poll (`--lease-poll-interval`, 1 s).
- `mac_enforcement: "enforce"` without a lease source (`--kea-lease-file`)
  is refused (it would drop every subscriber). Unknown modes are refused.
- Classifier messages are CRC-pinned in `artifacts/api-crc-26.10.json`.

## Consequences

- A new lease is forwarded ~1.1 s after the DHCP ACK (lab, 6 samples,
  1.11–1.12 s): the poll interval plus one apply. OS captive checks issued in
  that second are retried by the OS. Lower `--lease-poll-interval` or a Kea
  hook (lease_cmds / event push) would shorten it; the CSV re-read cost at
  scale is not measured.
- Static addresses without a lease are dropped in enforcing tenants (intended).
  Lab tests now use DHCP leases.
- Not covered: IPv6 (never permitted, F-10); ARP (a device can still answer
  ARP for another IP — VPP learns neighbours from ARP requests — so the
  return direction can be attracted; static neighbours from bindings are a
  follow-up); HTTP steered by ABF to the redirector (ip4-inacl runs after
  ABF), which can only ever receive the 302.
- The offset assumes two VLAN tags on the tenant sub-interface (all tenants
  are QinQ). If the outer TPID changes to 0x88a8 the layout length is the
  same; MACIP should be re-tested then (it may work with 0x88a8 outer tags).
- The portal's MACSecurityPolicy is not yet synchronised to the tenant's
  `mac_enforcement`; the desired-state file sets it.

## Rollback

Set the tenant's `mac_enforcement` to `"log_only"` in desired state and
restart the controller: it unbinds and deletes the chain.
