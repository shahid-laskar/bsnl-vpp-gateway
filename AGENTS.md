# Agent handoff: BSNL VPP gateway lab

Last updated: 2026-11-17, end of session. Code pushed at gateway 3238f03 /
portal c82ba0f; the handoff-doc commits on top may not be pushed yet (check
`git status -sb` in both repos).

## Project and access

- Remote project: `/opt/bsnl-vpp-gateway` (git `main`), lab VM `shahid@10.44.0.207`.
- Existing Django captive portal: `shahid@10.44.0.209`,
  `/opt/captive-portal/captive-portal-multitenant` (git `vpp-setup`).
- This is a development lab. Do not describe it as production-ready.
- Never expose credentials in documentation, logs, or commits. The user gives
  the SSH/sudo password per session; do not store it. Both repos' `origin`
  URLs embed a GitHub token: never print it (mask push output with
  `sed -E 's#//[^@/]+@#//***@#g'`).

## Read these first

1. This file (state, next work, gotchas).
2. `docs/IMPLEMENTATION_STATUS.md`: gate-by-gate status with evidence.
3. `docs/LAB_RUNBOOK.md`: install, checks, lab tests.
4. ADRs: 007 (portal contract), 010 (D-09 measurement), 011 (VRFs),
   012 (portal path), 013 (lease bindings), 014 (split DNS), 015 (HTTP
   redirect), 016 (MAC/IP enforcement), 017 (SVS authorization).
5. Portal side: `docs/vpp/REMEDIATION_STATUS.md` and `AGENTS.md` in the portal
   repo; plan: `docs/vpp/FINAL_IMPLEMENTATION_PLAN.md` there.

## Topology and addresses

| Purpose | Address/interface |
|---|---|
| VM management | `ens18`, `10.44.0.207/22`; default gateway `10.44.1.234` |
| Access attachment | `ens19` → `br-access` → veth → VPP `host-vpp-access` |
| WAN attachment | `ens20` → `br-wan` → veth → VPP `host-vpp-wan` |
| QinQ | outer `0x8100` VLAN 200, inner `0x8100` VLAN 101, exact match |
| Subscriber subnet | `10.9.101.0/24`, VPP gateway `10.9.101.1`, captive VRF 101 |
| DHCP pool | `10.9.101.5–10.9.101.105` (Kea subnet id 101, pinned) |
| VPP WAN | `198.51.100.1/24` (table 0 = internet VRF) |
| Linux WAN bridge | `198.51.100.2/24`: Kea, Unbound, redirector :8080 |
| Authorized lab target | `192.0.2.1/24` on `host-vpp-access` (table 0); ICMP only (no TCP stack) |
| Existing portal | `10.44.0.209`, `wifi.bsnl.co.in`; reached via the host and `ens18` (ADR-012) |
| Portal return path | portal host route `10.9.101.0/24 via 10.44.0.207` (runtime only; owner must persist it) |

`ens18` stays Linux-managed, outside VPP/DPDK. VPP uses `af_packet` (DPDK
plugin disabled). Outer TPID `0x88a8` failed in this VM path; the lab uses
`0x8100` (ADR-004).

## How the dataplane works now

Pre-auth subscriber (no SVS entry):

1. MAC/IP check (ADR-016): a controller-owned classifier chain on
   `host-vpp-access.101` (`ip4-inacl`) permits only (MAC, IP) pairs of open
   DHCP lease bindings plus source 0.0.0.0 (DHCP); everything else is dropped.
   ~1.1 s from DHCP ACK to first forwarded packet (1 s lease poll).
2. Static tenant ACL `bsnl:acl/<tenant>`: pre-auth allowlist (DHCP incl.
   unicast renew, DNS to 198.51.100.2, portal 80/443/ICMP) → protected
   prefixes denied (10.44.0.0/22, 198.51.100.0/24) → intra-tenant deny →
   subnet → 192.0.2.0/24 → subnet tcp/80 → deny-all.
3. Forwarding in captive VRF 101 (fixture `bsnl-lab.cli`): portal /32,
   resolver /32, default → 198.51.100.2 (all attached via `host-vpp-wan`).
   On the host, nftables (`bsnl-vpp-portal.nft`) redirects tcp/80 (not to the
   portal) to `bsnl-vpp-redirector` (fixed 302 to
   `https://wifi.bsnl.co.in/portal/login/`), forwards portal traffic out
   `ens18` (no SNAT to .209), and drops everything else (forward drop; input
   chain allows subscribers only DNS, DHCP and :8080).
4. DNS: Unbound split views (ADR-014): portal and captive-check names answer
   10.44.0.209, other names REFUSED.

Authenticated subscriber: one SVS entry `<ip>/32 → table 0` in SVS table
1101 (ADR-017), so lookups happen in table 0 (lab: only 192.0.2.0/24 is
reachable; no NAT/internet until P7). Unbound puts the /32 in the
authenticated view. Login/logout = one `svs_route_add_del` (VPP ~1 ms; API
round trip ~72 ms p50, mostly TLS + Unbound reload).

Return path (fixture): table 0 `10.9.101.0/24 via host-vpp-access.101`
(attached) and `10.9.101.1/32 via ip4-lookup-in-table 101` (Kea replies to
the relay address). DHCP proxy: `rx-fib-id 101 server-fib-id 0`.

The earlier ACL candidate (per-subscriber ACL permits + ABF HTTP redirect,
ADR-010/015) is still in the code as policy `authorization: "acl"` (tenant
`vrf_id: 0`): rollback only. D-09 measurement showed it fails churn beyond
~1k subscribers.

## Controller

- `controller/main.py` unit `deployment/systemd/bsnl-vpp-controller.service`:
  `--serve --listen 10.44.0.207 --port 8787` (mTLS), `--observe-vpp
  --enable-vpp-writes`, `--kea-lease-file`, `--unbound-views-file`.
  Secrets: `/etc/bsnl-vpp-gateway/controller.env` (root:vpp 0640, not in git):
  HMAC secret + `BSNL_VPP_ALLOWED_CLIENTS=bsnl-vpp-portal-client`. Every POST
  must be signed: lab tools use `tests/lab/controller_client.py`.
- Store: SQLite (`controller/store.py`), state + idempotency + audit in one
  transaction; audit JSONL mirror.
- Reconciler: 30 s ticks + 1 s VPP watch loop (re-applies within seconds of a
  VPP restart, after `bsnl-lab.cli` finished). Lease watcher polls Kea every
  1 s and triggers a re-apply when a binding opens/closes (MAC enforcement).
- `VppApiAdapter` refuses to run on an API CRC mismatch against
  `artifacts/api-crc-26.10.json` (regenerate with `tools/api_crc_snapshot.py`
  after any VPP upgrade or new message use). It owns: tenant sub-interface
  (tag/MTU/VRF), tenant ACL, ABF (acl mode only), classifier chain, SVS table,
  enablement and entries.
- `policy.py` (ACL compile + enforcer), `svs.py`, `mac_enforcement.py`,
  `redirector.py`, `bindings.py`/`leases.py`, `dns_views.py`.
- Responses report `dataplane_enforced`, true only when VPP confirmed it.

## Portal integration (live since 2026-11-17)

- Portal: router `vpp-lab-207` (instance_id 9, `dataplane_type="vpp"`),
  customer `vpp-lab` (10.9.101.5–105), test user `vpplab1` (password only in
  `/opt/captive-portal/vpp-secrets/lab-user-password` on .209).
  `VPP_CONTROLLER_*` in the portal `.env`; certs in
  `/opt/captive-portal/vpp-secrets`, mounted at `/run/secrets/vpp`.
- The portal identifies router (second octet) and customer from the
  subscriber's own address: never SNAT subscriber traffic to the portal.
- Only the django container mounts the portal repo; Celery workers/beat run
  baked images (rebuilt 2026-11-17; old images tagged `:pre-20261117`).

## State at handoff (2026-11-17)

- Gateway `main` code at 3238f03, portal `vpp-setup` at c82ba0f (both pushed),
  plus handoff-doc commits.
  169 gateway unit tests pass (`PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q
  -p no:cacheprovider tests`); portal 190 tests (3 skipped) in the django
  container.
- Live lab = `main`: SVS authorization, MAC enforcement `enforce`, HTTP
  redirect via captive VRF, Unbound split DNS, portal integration.
  `sudo bsnl-vpp-lab-check` HEALTHY.
- Last full lab verification: `artifacts/test-reports/2026-11-17-d09-svs-lab.txt`
  (DHCP 6/6, bypass suite 21/21 pre-auth and 22/22 authorized, portal E2E
  9/9, VPP restarts recover in 3.75–4.95 s).
- Rollbacks (details in ADR-015/016/017 and IMPLEMENTATION_STATUS): host
  backups `/root/bsnl-*.tgz`, `/root/startup.conf.pre-svs-*`,
  `/root/bsnl-lab.cli.pre-hwaddr`, `/root/portal-path.nft.pre-nosnat-20261117`,
  `/root/bsnl-vpp-controller.service.pre-writes`; Unbound:
  `sudo sh deployment/bin/bsnl-vpp-unbound-install --rollback`.

## Next work (plan order)

1. **Unbound reload batching** (ADR-014 limits): every login/logout rewrites
   and reloads the authenticated view; it now dominates the per-login cost
   and will not survive 50 logins/s. Batch/coalesce reloads (or switch to
   `unbound-control local_data`/view updates without reload) and measure with
   `tools/d09_bench.py`-style churn.
2. **ARP protection** (ADR-016 limit): a device can still answer ARP for
   another subscriber's IP. Static VPP neighbours from lease bindings and/or
   disabling ARP learning on the tenant sub-interface.
3. **Portal follow-ups:** resolve the binding MAC before activating on VPP
   routers (today it arrives after activation, so the controller's MAC
   mismatch audit never fires); sync the portal's MACSecurityPolicy to the
   tenant's `mac_enforcement`.
4. **Captive detection on real clients** (Android, iOS/macOS, Windows,
   Linux NetworkManager): needs physical/VM clients on the QinQ access path.
5. **Phase 5 leftovers:** VPP neighbour table as secondary MAC source; D-19
   resolver scale.
6. **Phase 7 (NAT44-ED + IPDR)** only after D-16 has an owner. Until then do
   not widen `authenticated_destinations` beyond 192.0.2.0/24 or add an
   internet route to table 0.
7. Later: hardware/DPDK, 0x88a8 re-qualification (re-test MACIP then),
   throughput, HA, D-06 (VRF per tenant vs shared, overlapping ranges).

Owner actions (not code): persist the .209 route, revoke the GitHub tokens in
`origin` URLs, `DEBUG=False` on the portal, remove/implement the beat task
`reconcile-security-runtime`, D-15/D-16 owners (portal REMEDIATION_STATUS).

## Working on this lab (from the Windows workstation)

- Access: PuTTY `plink -batch -hostkey <SHA256 fp> -pw <pw> shahid@<host>`
  (no sshpass/paramiko). Host keys: .207
  `SHA256:AhkuRMZPjiZiypx7PKDhufFg7q2b/76+hkFCSW7VSv0`, .209
  `SHA256:2FS9szo9/12x9Gjk5OFNi2cUUNjgOwYopDmj0omGHAE`.
- sudo: `echo <pw> | sudo -S -p '' <cmd>`. A heredoc on the same command
  steals stdin from sudo: write scripts to a file first, then sudo them.
- Work in a git worktree (`git worktree add -b <branch> ~/wt/<name> main`),
  test there, commit, then `git merge --ff-only` in `/opt/bsnl-vpp-gateway`
  and install/restart. Before `git worktree remove`, delete root-owned
  `__pycache__` with sudo. Lab tests run as root from the worktree:
  `sudo env PYTHONDONTWRITEBYTECODE=1 python3 -m ...`.
- Remote files must be LF. Writing Python through bash heredocs into Python
  string literals turned `"\\x00"` into real NUL bytes once: prefer script
  files and the editor.
- Commit messages: pass as a file (`git commit -F`), end with the
  Co-Authored-By line the session specifies.

## Lab tests (root, from the repo)

```bash
sudo bsnl-vpp-lab-check                                   # HEALTHY/UNHEALTHY
sudo python3 -m controller.dhcp_qualification             # lease, option 114, DNS, portal
sudo python3 -m controller.bypass_suite                   # pre-auth (21 checks)
sudo python3 -m controller.bypass_suite --phase authorized   # leases, activates (signed), deactivates (22)
sudo python3 -m tests.lab.portal_e2e --username vpplab1 --password-file FILE   # real portal login
sudo python3 -m tests.lab.restart_policy_recovery --runs 3   # outage per VPP restart
sudo python3 -m tests.lab.controller_client activate|deactivate --ip IP
sudo sh tools/d09/run-bench-vpp.sh start|stop             # throw-away bench VPP (core 2), tools/d09_bench.py
```

Static addresses without a DHCP lease are dropped (MAC enforcement): tests
use DHCP. The portal rate-limits 5 logins per client IP per 5 min.

## Gotchas learned on this lab

- `svs_plugin.so` (and acl/abf/dhcp/af_packet/ping) must be enabled in
  `deployment/vpp/startup.conf.lab` (plugin allow-list); a missing plugin
  makes the controller refuse to start (CRC check).
- Captive VRF routes must be attached (`via 198.51.100.2 host-vpp-wan`): a
  recursive route to 198.51.100.2 through itself resolved to drop. The
  table-0 return route must be attached (`via host-vpp-access.101`): a
  lookup-in-table route made `ip4-receive` drop traffic to VPP's own
  addresses (source check).
- VPP 26.10 MACIP drops all IPv4 on this 0x8100/0x8100 sub-interface (works
  untagged); hence the classifier chain keyed relative to the IP header
  (`current_data_flag 1`, MAC at -16).
- ACL plugin runs before ABF (12) and `ip4-inacl` (19) on ip4-unicast; SVS
  runs first.
- `vpp_papi` needs the full 16-entry `label_stack` in a `fib_path`.
- VPP has no TCP stack: TCP to VPP's own addresses gets no RST; use ICMP to
  192.0.2.1 as authorized-path evidence.
- `/etc/unbound/bsnl` must stay 2755 with 0644 files (AppArmor).
- tcpdump on QinQ frames: `vlan and vlan and (...)` and `--immediate-mode`.
- `/usr/local/sbin/bsnl-vpp-lab-check` is a copy: reinstall after changing
  `deployment/bin/bsnl-vpp-lab-check`.
- Lab Kea has no `lease_cmds` hook; `/var/lib/kea` is `_kea 0750`.
- `shahid` cannot open `/run/vpp/api.sock`; vppctl needs sudo.
- The lab VPP runs on core 3; the D-09 bench VPP on core 2.

Preserve VyOS behavior and its rollback role during VPP development.
