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
| Linux WAN bridge address | `198.51.100.2/24`; Kea and Unbound listen here |
| Existing portal | `10.44.0.209`; hostname `wifi.bsnl.co.in` |
| Portal return path | portal host route `10.9.101.0/24 via 10.44.0.207` (runtime only; persist it) |

`ens18` must remain Linux-managed and outside VPP/DPDK. Do not bind the VM NICs
to `uio_pci_generic` or `vfio-pci`. VPP uses `af_packet` over existing veth
endpoints. The requested outer TPID `0x88a8` failed in this VM path; use the
documented `0x8100` lab fixture unless explicitly re-qualifying it.

## Current implementation

- VPP 26.10, with DPDK plugin disabled for this VM.
- Persistent Linux bridge/veth and VPP af_packet interfaces.
- L3 and QinQ service interface.
- VPP DHCP proxy to Kea; Kea advertises DNS and RFC 8910 option 114 with
  the RFC 8908 API URI https://wifi.bsnl.co.in/portal/captive-api/.
- Unbound split-horizon DNS (ADR-014): before login, portal and captive-check
  names answer 10.44.0.209 and other names are REFUSED; authenticated
  subscribers get normal recursion. dnsmasq is disabled (rollback only).
- VPP route to 10.44.0.0/22; Linux forwarding and scoped SNAT allow
  subscribers to reach the existing portal without a portal-host return route.
- Subscriber policy on host-vpp-access.101 is the controller-owned tagged ACL
  `bsnl:acl/<tenant>` (writes on since 2026-11-16): pre-auth allowlist (DHCP,
  DNS to 198.51.100.2, portal HTTP/HTTPS/ICMP), protected prefixes, one permit
  per authenticated /32 to the lab target 192.0.2.0/24, deny-all. The static
  ACL 0 from `bsnl-lab.cli` is only in force between a VPP start and the
  controller's re-apply (seconds) or when writes are off.
- Subscriber lifecycle control plane supports authenticated activation,
  deactivation, expiry, tenant validation, durable idempotency, conflict
  detection, and audit events.
- Controller API contract v1 (see ADR-007): mTLS with optional client-name
  allowlist, plus HMAC (timestamp + nonce + method + path + Idempotency-Key +
  body hash) when BSNL_VPP_PORTAL_HMAC_SECRET is configured. The lab has
  `/etc/bsnl-vpp-gateway/controller.env` (root:vpp 0640, never in git) with the
  HMAC secret and `BSNL_VPP_ALLOWED_CLIENTS=bsnl-vpp-portal-client`; every POST
  must be signed. Responses report `dataplane_enforced`, true only when VPP
  confirmed the change.
- Controller request bodies are bounded to 1 MiB.

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
unbound                  # split DNS; dnsmasq disabled since 2026-11-16
```

The VPP-side lab fixture (af_packet, L3, QinQ, DHCP proxy, pre-auth ACL index
0) is in `deployment/vpp/bsnl-lab.cli` and is re-applied by VPP on every
restart. The old vppctl oneshot units are retired to `deployment/legacy/`
(they raced vpp.service startup). Install/repair the host with
`sudo sh deployment/bin/bsnl-vpp-lab-install`; check it with
`sudo bsnl-vpp-lab-check` and `sudo sh tests/lab/test_restart_recovery.sh`.

Useful read-only checks on the VM (vppctl and the API socket need root or
`sudo -u bsnl-vpp`; `shahid` cannot open `/run/vpp/api.sock`):

```bash
sudo bsnl-vpp-lab-check          # one-shot health check (HEALTHY/UNHEALTHY)
systemctl is-active vpp bsnl-vpp-lab-links bsnl-vpp-portal-path \
  bsnl-vpp-controller isc-kea-dhcp4-server unbound
sudo vppctl show interface address
sudo vppctl show acl-plugin interface      # sw_if_index 3: input acl(s): <tagged ACL>
sudo vppctl show acl-plugin acl            # {cli} = static ACL 0, bsnl:acl/... = controller
sudo journalctl -u bsnl-vpp-controller -n 50
kea-dhcp4 -t /etc/kea/kea-dhcp4.conf
sudo unbound-checkconf
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
  `tools/api_crc_snapshot.py` on every VPP upgrade). Writes are off by default
  in code; the lab unit runs with `--enable-vpp-writes` since 2026-11-16
  (controller owns the tenant sub-interface and ACL). After a VPP restart a
  1 s watch loop (`--vpp-watch-interval`) re-applies once `bsnl-lab.cli` has
  finished (`--vpp-startup-settle-seconds`, 10 s max): authenticated
  subscribers are back in 3.8–5.0 s (lab, 2026-11-17).
  `subscriber_policy_enforced` is true only while the last policy apply
  against the current VPP connection succeeded.
- Decision (lab, until D-06): tenants use VRF 0 (shared FIB). The live
  sub-interface and the portal route are in table 0; the earlier desired state
  said VRF 101, which would have isolated subscribers from the portal once
  writes were enabled. Kea subnet id 101 is pinned (`kea_subnet_id`) to keep
  the existing lease file valid.

## Subscriber policy (remediation step 5)

- `controller/policy.py` compiles each tenant's input ACL (first match):
  pre-auth allowlist (DHCP incl. unicast renew, DNS to the gateway resolver,
  portal 80/443/ICMP) -> protected prefixes denied (management LAN, gateway
  host) -> intra-tenant deny -> one permit per authenticated /32 to
  `authenticated_destinations` -> explicit deny-all. IPv4 only.
- With `--enable-vpp-writes`, the controller owns a tagged ACL
  (`bsnl:acl/<tenant>`) and binds it as the sub-interface's only input ACL;
  activation/deactivation is applied before the API responds and
  `dataplane_enforced` is true only when VPP confirms it. Without writes the
  static ACL from `deployment/vpp/bsnl-lab.cli` stays in force (fail closed);
  after a VPP restart that static ACL applies until the watch loop re-applies
  (seconds; `sudo python3 -m tests.lab.restart_policy_recovery`).
- VPP af_packet MACs are pinned in `bsnl-lab.cli` (`hw-addr 02:fe:b5:00:00:01`
  access, `:02` WAN). Do not remove: random MACs per restart left stale ARP
  entries on subscribers and the host for 30–50 s.
- Lab `authenticated_destinations` is `192.0.2.0/24` (VPP's own fixture
  address): authorization is observable (ping 192.0.2.1) but opens no internet
  path. NAT/upstream is step 7; do not widen it before then.
- Option 114 now carries the RFC 8908 API URI
  `https://wifi.bsnl.co.in/portal/captive-api/` (portal endpoint added in the
  portal repo); reinstall the Kea config to apply it.
- Bypass suite: `sudo python3 -m controller.bypass_suite` (pre-auth) and
  `--phase authorized --static-ip <activated ip>`.
- Lab exception (S-2): subscriber->portal traffic is SNATed out of the
  management NIC `ens18` by `bsnl-vpp-portal-path`. Acceptable only in this VM
  lab; production must reach the portal via the WAN/service network.
- Not in this step: SVS (candidate A) comparison for D-09. HTTP redirect and
  MAC enforcement: see below.

## HTTP redirect (Phase 6, ADR-015, 2026-11-17)

- Policy key `http_redirect: {"next_hop": "198.51.100.2"}`. The tenant ACL
  gets `permit <subnet> tcp/80 any` after the protected denies (VPP runs the
  ACL before ABF), and a controller-owned ABF policy (match ACL
  `bsnl:abf/<tenant>`) steers that HTTP to the host. ABF objects are written
  before the permit and removed after it.
- Host: nft prerouting in `bsnl_vpp_portal` redirects it to :8080;
  `bsnl-vpp-redirector.service` (`controller/redirector.py`) answers a fixed
  302 to `https://wifi.bsnl.co.in/portal/login/`. The forward chain now drops
  any other subscriber traffic the host would forward.
- ABF messages are in-progress API in 26.x: CRC-pinned; `vpp_papi` needs the
  full 16-entry `label_stack` in a `fib_path` (missing it crashed the
  controller at boot once; it fails closed).
- Controller POSTs need HMAC since 2026-11-17: use
  `tests/lab/controller_client.py` (activate/deactivate CLI) for lab tests.

## MAC/IP enforcement (Phase 6, ADR-016, 2026-11-17)

- Lab tenant `mac_enforcement: "enforce"`: a controller-owned classifier
  chain is the ip4 input ACL of host-vpp-access.101 (`sudo vppctl show inacl
  type ip4`, `show classify tables`): head = (src MAC at IP-16, src IP) per
  open lease binding, tail = src 0.0.0.0 for DHCP, miss -> drop. The lease
  watcher re-applies on every binding open/close (~1.1 s lease -> first
  packet).
- Not MACIP: VPP 26.10's MACIP dropped all IPv4 on this 0x8100/0x8100 QinQ
  sub-interface (fine on untagged). See ADR-016 for traces.
- Static addresses without a lease are dropped: lab tests use DHCP. The
  bypass suite's authorized phase leases and activates its own address
  (`sudo python3 -m controller.bypass_suite --phase authorized`).
- Rollback: set `log_only` in desired state, restart the controller.

## Lease bindings (Phase 5, P5-T4/T6)

- `controller/leases.py` reads Kea's memfile lease CSVs (no `lease_cmds` hook
  in the lab); `controller/bindings.py` keeps the append-only `bindings` table
  (open/renew/close, never delete) and `LeaseWatcher` polls every second when
  `--kea-lease-file` is given. A source error keeps the bindings unchanged.
- `GET /v1/bindings?tenant_key=&private_ipv4=[&at=]` returns the binding valid
  at a time; the portal uses it for MAC lookup on VPP routers.
- A portal MAC that differs from the binding is audited
  (`subscriber.mac_mismatch`), not rejected, until MACIP enforcement (P6).
- See ADR-013.

## Split DNS (Phase 5, P5-T5)

- Unbound 1.19.2 on 198.51.100.2 (`deployment/bin/bsnl-vpp-unbound-install`,
  `--rollback`). Static config rendered from `config/lab/host-services.json`
  into `deployment/resolver/unbound-bsnl-vpp-lab.conf` (a test keeps them in
  sync).
- `controller/dns_views.py` writes `/etc/unbound/bsnl/authenticated.conf`
  (authenticated /32s), checks with `unbound-checkconf`, then
  `unbound-control reload_keep_cache`; on API state changes and every
  reconcile tick.
- Keep `/etc/unbound/bsnl` at 2755 / files 0644: Unbound's AppArmor profile
  has no dac_override, so tighter modes stop Unbound from starting.
- `unbound-resolvconf.service` is masked: the host keeps systemd-resolved.
- See ADR-014.

## Portal integration (live since 2026-11-17)

- Portal side (`10.44.0.209`): router `vpp-lab-207` (instance_id 9,
  `dataplane_type="vpp"`), customer `vpp-lab` (10.9.101.5–105), test user
  `vpplab1` (password only in `/opt/captive-portal/vpp-secrets/lab-user-password`
  on the portal host). `VPP_CONTROLLER_*` in the portal `.env`; CA, client
  cert and key in `/opt/captive-portal/vpp-secrets` (uid 1000, 0400), mounted
  at `/run/secrets/vpp` in django, workers and beat.
- The portal identifies router and customer from the subscriber's own address
  (second octet = router instance), so traffic to 10.44.0.209 must not be
  SNATed (ADR-012 update).
- Test: `sudo python3 -m tests.lab.portal_e2e --username vpplab1
  --password-file FILE` (copy the password from the portal host into a 0600
  file; it is never passed in argv). The portal rate-limits 5 logins per
  client IP per 5 min; each run gets a fresh lease, so this rarely matters.

## State at handoff (2026-11-17)

- Gateway `main` = `origin/main` (pushed 2026-11-17). Portal `vpp-setup` =
  `origin/vpp-setup`. Old review branches (`fix/step*`, `docs/step6-*`,
  `feat/p5-lease-bindings`) are merged; they can be deleted.
- Live lab runs the `main` build: controller with `--observe-vpp
  --enable-vpp-writes --kea-lease-file ... --unbound-views-file ...`
  (`deployment/systemd/bsnl-vpp-controller.service`), Unbound split DNS,
  pinned VPP MACs. `sudo bsnl-vpp-lab-check` HEALTHY; 121 unit tests pass.
- Rollbacks: writes off -> `/root/bsnl-vpp-controller.service.pre-writes`
  (reinstall, restart controller, then VPP); Unbound ->
  `sudo sh deployment/bin/bsnl-vpp-unbound-install --rollback`; startup CLI
  before MAC pinning -> `/root/bsnl-lab.cli.pre-hwaddr`. Host backups:
  `/root/bsnl-*-install-*.tgz`.
- Lab verification commands (root): `sh tests/lab/test_restart_recovery.sh 5`,
  `python3 -m tests.lab.restart_policy_recovery --runs 5`,
  `python3 -m controller.bypass_suite [--phase authorized --static-ip IP]`,
  `python3 -m controller.dhcp_qualification`.

## Next work (plan order)

1. **Portal -> VPP end to end: DONE 2026-11-17** (see "Portal integration").
   Follow-ups: send the binding MAC with the activation (today the portal
   fetches it asynchronously after activation); persist the portal host
   route; the lab reuses the CN `bsnl-vpp-portal-client` certificate issued
   2026-11-11 by the lab CA (expires 2027-11-11).
2. **Phase 6 remainder:** HTTP redirect (ADR-015) and MAC/IP enforcement
   (ADR-016) DONE 2026-11-17. D-09 MEASURED 2026-11-17: the deployed ACL
   candidate fails churn beyond ~1k subscribers; SVS recommended (ADR-010
   proposal, awaiting approval; bench: `tools/d09/`). Left: ARP protection
   (static neighbours from bindings), portal MACSecurityPolicy -> tenant mode
   sync, SVS migration if approved, Unbound reload batching at churn (ADR-014 limits), captive detection on
   real Android/iOS/Windows clients.
3. **Phase 5 leftovers:** VPP neighbour table as secondary MAC source; D-19
   resolver scale measurement.
4. **Phase 7 (NAT44-ED + IPDR)** only after D-16 (IPDR legal fields) has an
   owner. Until then do not widen `authenticated_destinations` beyond
   192.0.2.0/24 and do not enable authenticated internet forwarding.
5. Later: hardware/DPDK, throughput, scale, HA, accounting qualification.

## Gotchas learned on this lab

- `/etc/unbound/bsnl` must stay 2755 with 0644 files (Unbound AppArmor has no
  dac_override); 0750 stopped Unbound (~1 min DNS outage on 2026-11-16).
- VPP has no TCP stack (session layer off): TCP to VPP's own addresses is
  punted and dropped without RST. Use ICMP to 192.0.2.1 as authorized-path
  evidence.
- tcpdump on QinQ frames needs `vlan and vlan and (...)` filters and
  `--immediate-mode`, or captures are empty/intermittent.
- `/usr/local/sbin/bsnl-vpp-lab-check` is a copy; reinstall it from the repo
  after changing `deployment/bin/bsnl-vpp-lab-check` (a stale copy still
  checked dnsmasq).
- Runs under sudo leave root-owned `__pycache__` in worktrees; delete them with
  sudo before `git worktree remove`.
- Lab Kea has no `lease_cmds` hook; `/var/lib/kea` is `_kea 0750`.
- Remote files must have LF line endings.
- Some repo files were root-owned (early installs); chowned to shahid on
  2026-11-17. If an edit fails with EACCES, check `find . ! -user shahid`.

Preserve VyOS behavior and its rollback role during VPP development.
