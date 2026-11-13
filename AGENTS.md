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
  https://wifi.bsnl.co.in/portal/login/.
- dnsmasq maps portal/captive-check names to 10.44.0.209.
- VPP route to 10.44.0.0/22; Linux forwarding and scoped SNAT allow
  subscribers to reach the existing portal without a portal-host return route.
- Persistent pre-auth ACL on host-vpp-access.101: DHCP, DNS to 198.51.100.2,
  and HTTP/HTTPS/diagnostic ICMP to the portal are allowed; unmatched IPv4 is
  denied.
- Subscriber lifecycle control plane supports authenticated activation,
  deactivation, expiry, tenant validation, durable idempotency, conflict
  detection, and audit events.
- Controller API contract v1 (see ADR-007): mTLS with optional client-name
  allowlist, plus HMAC (timestamp + nonce + method + path + Idempotency-Key +
  body hash) when BSNL_VPP_PORTAL_HMAC_SECRET is configured. Responses report
  `dataplane_enforced` (false while the adapter is dry-run).
- Controller request bodies are bounded to 1 MiB; VPP policy writes remain
  disabled because the adapter is still dry-run.

Verified from isolated QinQ namespaces: DHCP lease, DNS mapping, portal HTTP
/generate_204 200, HTTPS /portal/login/ 200, portal reachability, and an
unapproved destination denied by the ACL. See implementation status for exact
test details and limits.

## Runtime services and source files

Enabled units include:

```text
vpp                      # applies deployment/vpp/bsnl-lab.cli via unix { exec }
bsnl-vpp-lab-links       # Linux bridges/veths; vpp.service requires it
bsnl-vpp-portal-path     # lab nftables forward/SNAT to the portal
bsnl-vpp-controller
isc-kea-dhcp4-server
dnsmasq
```

The VPP-side lab fixture (af_packet, L3, QinQ, DHCP proxy, pre-auth ACL index
0) is in `deployment/vpp/bsnl-lab.cli` and is re-applied by VPP on every
restart. The old vppctl oneshot units are retired to `deployment/legacy/`
(they raced vpp.service startup). Install/repair the host with
`sudo sh deployment/bin/bsnl-vpp-lab-install`; check it with
`sudo bsnl-vpp-lab-check` and `sudo sh tests/lab/test_restart_recovery.sh`.

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

## Controller (remediation step 4)

- Store: SQLite only (`controller/store.py`); state, idempotency record and
  audit event of an operation commit in one transaction. Audit rows carry
  `ts`, `actor` (`cert:<CN>` / `token` / `controller` / `config`), `event` and
  `gateway_revision`; `--audit` is a JSONL mirror.
- Topology vs subscribers (`controller/state.py`): the desired-state file owns
  tenants/pools/policies and is merged at boot; subscribers persist across
  restarts and topology edits. Disabling/removing a tenant deactivates its
  subscribers (audited).
- `Reconciler` thread (`--reconcile-interval`, default 30 s): expires
  subscribers, prunes idempotency records (7 days), re-applies desired state.
- A late/replayed activation for a portal session that already ended returns
  409 (`StaleEventError`); a new login must use a new session_id.
- `VppApiAdapter` (`--observe-vpp`, `--enable-vpp-writes`): CRC-checked
  against `artifacts/api-crc-26.10.json` (regenerate with
  `tools/api_crc_snapshot.py` on every VPP upgrade). Writes are off by default.
  `subscriber_policy_enforced` stays false until step 5, so the portal keeps
  sessions out of `fully_active`.
- Decision (lab, until D-06): tenants use VRF 0 (shared FIB). The live
  sub-interface and the portal route are in table 0; the earlier desired state
  said VRF 101, which would have isolated subscribers from the portal once
  writes were enabled. Kea subnet id 101 is pinned (`kea_subnet_id`) to keep
  the existing lease file valid.

## Next work

1. Done (remediation step 2): the Django portal client speaks contract v1;
   cross-repo golden vectors and an mTLS+HMAC E2E run pass.
2. Provision the portal client certificate, BSNL_VPP_ALLOWED_CLIENTS and the
   shared HMAC secret out-of-band; never commit them.
3. Replace the dry-run adapter and hard-coded ACL index/rules with validated,
   idempotent desired-state reconciliation and safe per-subscriber policy.
4. Add negative tests for IPv6, DoH/DoT, QUIC, spoofed source IP/MAC, and
   expired/deactivated subscribers before broadening policy.
5. Complete captive redirect behavior and RFC 8908 API only after an explicit
   design for the existing portal integration.
6. Perform hardware/DPDK, throughput, scale, DHCP-churn, failure-recovery,
   policy, and accounting qualification.

Do not enable authenticated internet forwarding as an assumed next step.
Preserve VyOS behavior and its rollback role during VPP development.
