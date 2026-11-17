# BSNL VPP Gateway — Implementation Status

Updated: 2026-11-17 end of session (remediation steps 1–6, Phase 5, portal E2E, Phase 6 HTTP redirect + MAC/IP enforcement, D-09 = SVS; all on `main`, pushed, live in the lab).
Plan: `/opt/captive-portal/captive-portal-multitenant/docs/vpp/FINAL_IMPLEMENTATION_PLAN.md`.

This is a **development lab** on Ubuntu VM `10.44.0.207` (VPP 26.10 over
`af_packet`, DPDK disabled). Nothing here is a production, performance or
compliance claim.

## How to read this file

Every gate row carries one status and links its evidence (FINAL plan P-15).

| Status | Meaning |
|---|---|
| **VERIFIED** | Observed on the lab VM; evidence file or command output linked. |
| **TESTED** | Implemented and covered by automated tests against fakes; not yet exercised on the live VM. |
| **READY-TO-RUN** | Implemented; needs a root-run lab procedure (command given) to become VERIFIED. |
| **OPEN** | Not implemented or not decided. |
| **DEFERRED-HW** | Needs the hardwired NIC / production-candidate host. |

Evidence lives in `artifacts/` (this repo) and
`docs/vpp/evidence/` (portal repo). Test reports are regenerated per change.

## Current runtime state (2026-11-17)

- Dataplane: VPP applies `deployment/vpp/bsnl-lab.cli` at start-up (no
  oneshot races); af_packet MACs pinned. 5-cycle restart test passes, fixture
  healthy 2–3 s after `systemctl restart vpp`
  (`artifacts/test-reports/2026-11-16-restart-recovery-5.txt`).
- Controller: unit from `main` with `--observe-vpp --enable-vpp-writes`,
  Kea lease sync and Unbound view sync. It owns the tenant sub-interface,
  the static tenant ACL, the SVS table and entries, and the MAC/IP
  classifier chain; static ACL 0 is unbound while it runs. After a VPP restart it
  re-applies within ~2.5 s of VPP's startup config; authenticated subscribers
  are back in 3.8–5.0 s
  (`artifacts/test-reports/2026-11-17-restart-policy-recovery.txt`).
- Pre-auth HTTP redirect (ADR-015, 2026-11-17): `bsnl-vpp-redirector` on
  198.51.100.2:8080 behind an nft redirect; with SVS the captive VRF default
  route brings the traffic to the host (ABF only in `authorization: acl`).
- Authorization (ADR-017, 2026-11-17): SVS; tenant in captive VRF 101,
  SVS table 1101, static tenant ACL; ABF unused in this mode.
- MAC/IP enforcement (ADR-016, 2026-11-17): lab tenant `mac_enforcement:
  enforce`; classifier chain on host-vpp-access.101 follows lease bindings.
- Resolver: Unbound 1.19.2 split-horizon views (ADR-014); dnsmasq disabled,
  config kept for rollback.
- Portal integration (2026-11-17): `/etc/bsnl-vpp-gateway/controller.env`
  (root:vpp 0640, not in git) sets `BSNL_VPP_ALLOWED_CLIENTS=bsnl-vpp-portal-client`
  and the HMAC secret; the portal has a lab router `vpp-lab-207` (instance 9,
  `dataplane_type="vpp"`) and customer `vpp-lab` (10.9.101.5–105). A real
  password login from a QinQ namespace reaches `fully_active` with
  `dataplane_enforced: true` (3/3 runs,
  `artifacts/test-reports/2026-11-17-portal-e2e.txt`). Portal traffic is no
  longer SNATed; the portal host routes 10.9.101.0/24 via 10.44.0.207 (ADR-012).
  No subscriber internet path (P7).
- Backups and rollbacks: `/root/bsnl-p5-install-20261116T111529.tgz`,
  `/root/bsnl-unbound-install-20261116T113548.tgz`,
  `/root/bsnl-vpp-controller.service.pre-writes`,
  `/root/bsnl-lab.cli.pre-hwaddr`, `/root/portal-path.nft.pre-nosnat-20261117`,
  `/root/bsnl-p6-redirect-20261117T062602.tgz`, `/root/bsnl-d09-svs-20261117T083051.tgz`,
  `/root/startup.conf.pre-svs-*` (rollback to ACL mode: ADR-017).

## Branches

Everything is on gateway `main` and portal `vpp-setup`, both pushed to
`origin` (2026-11-17). The older review branches are merged.

## Phase gates

### P0 — Governance and prerequisites

| Gate | Status | Evidence / next action |
|---|---|---|
| Repository with version manifest | VERIFIED | `versions.lock.yaml` (re-captured 2026-11-13) |
| CI, branch protection | OPEN | No CI runner configured; run the pytest and Django suites before each merge |
| Secret scan, rotated credentials (B-05) | OPEN | **Both repos' `origin` URLs embed GitHub tokens in plain text — revoke them.** Run gitleaks on both repos |
| Live VyOS inventory (P0-T3) | OPEN | Owner needed |
| D-15 (10 Gbps definition), D-16 (IPDR legal fields) owners | OPEN | Owner and date needed; they block P2 and P7 |

### P1 — Django adapter contract (portal repo)

| Gate | Status | Evidence |
|---|---|---|
| Contract frozen, no attribute passthrough | TESTED | `apps/network_control/adapters/base.py`; `tests/test_adapter_contract.py` |
| Contract suite against fake, kernel/VyOS and VPP adapters | TESTED | `test_adapter_contract.py` (portal), `docs/vpp/evidence/2026-11-13-django-tests.txt` |
| Zero direct dataplane-client use outside adapters | TESTED (allowlist) | `test_dataplane_boundary.py`; 3 guarded VyOS-only provisioning modules allowlisted |
| Every router path dataplane-aware | TESTED | `NetworkControlService.for_router`, `dataplane.py`; skip/guard tests |
| `dataplane_type` in DB (migration `portal.0004`) | VERIFIED (2026-11-17) | applied on the dev portal; Celery workers and beat rebuilt from `vpp-setup` 2026-11-17 |
| R-21 Redis broker eviction | TESTED (config) | `volatile-lru` in compose files; takes effect when Redis is recreated |
| R-22 NOC/admin source-IP | TESTED | middleware uses nginx `X-Real-IP`; spoofing test |
| Usage-counter semantics doc (P1-T7) | OPEN | |

### P2 — Platform

| Gate | Status | Evidence |
|---|---|---|
| Pinned packages recorded | VERIFIED | `versions.lock.yaml` |
| Management NIC outside VPP | VERIFIED | `deployment/vpp/startup.conf.lab` (no `dpdk {}`), topology |
| VPP restart returns to forwarding (≤ 30 s) | VERIFIED (2026-11-16) | 5/5 cycles, fixture healthy 2–3 s after restart, DHCP qualification green each cycle; `artifacts/test-reports/2026-11-16-restart-recovery-5.txt` |
| Bundled DPDK version, NIC qualification, PDR/NDR | DEFERRED-HW | DPDK plugin disabled in the VM |

### P3 — Controller

| Gate | Status | Evidence |
|---|---|---|
| Desired-state schema v2 + validation | TESTED | `config/schema/desired-state.schema.json`, `test_phase3.py` |
| API contract v1, mTLS + HMAC (nonce, replay) | VERIFIED (loopback) | `artifacts/test-reports/2026-11-13-contract-e2e.txt` |
| Portal -> controller with a real login (mTLS client allowlist + HMAC) | VERIFIED (2026-11-17) | `tests/lab/portal_e2e.py`: DHCP lease, pre-auth target blocked, portal password login, portal reports activated 0.64–1.04 s after login, 192.0.2.1 reachable 1.29–1.66 s, blocked again 1.51 s after logout; audit actor `cert:bsnl-vpp-portal-client`; `artifacts/test-reports/2026-11-17-portal-e2e.txt` |
| Atomic store, audit with actor/ts/revision | TESTED | `controller/store.py`, `test_step4.py` |
| Topology merged at boot; subscribers survive restart | TESTED | `controller/state.py`, `test_step4.py` |
| Expiry enforced while serving | TESTED | `Reconciler`, `test_reconciler_expires_sessions_while_running` |
| Second apply makes zero VPP writes | TESTED | `test_create_then_second_apply_makes_zero_writes` |
| VPP restart restores desired state | VERIFIED (2026-11-17) | 1 s watch loop re-applies tag/MTU/ACL as soon as VPP's startup config has finished (never races `bsnl-lab.cli`); VPP MACs pinned. An authenticated subscriber's ping to the authorized target is back 3.8–5.0 s after `systemctl restart vpp` (5/5; was 30–32 s). `tests/test_restart_recovery.py`, `tests/lab/restart_policy_recovery.py`, `artifacts/test-reports/2026-11-17-restart-policy-recovery.txt` |
| Refuse on API CRC mismatch | TESTED | `artifacts/api-crc-26.10.json`, `test_crc_mismatch_refuses_to_operate` |
| Live CRC check against running VPP | VERIFIED (2026-11-16) | running controller reports `"api_crc_ok": true`, `artifacts/test-reports/2026-11-16-p5-lab-bindings.txt`; command: | `sudo -u bsnl-vpp python3 -m controller.main --observe-vpp --port-map access0=host-vpp-access --desired-state config/lab/desired-state.json --store /tmp/obs.sqlite3 --audit /tmp/obs.jsonl` → expect `"api_crc_ok": true` |

### P4 — Interfaces and QinQ

| Gate | Status | Evidence |
|---|---|---|
| Exact-match QinQ, negative tag cases | VERIFIED (2026-11-11) | ADR-004; manual namespace tests |
| 0x88a8 outer TPID | OPEN | ADR-004: failed on af_packet; re-test on hardware |
| Controller-owned sub-interfaces (adopt, repair, tag, orphan cleanup) | TESTED | `controller/interfaces.py`, `test_step4.py` |
| Routing model | DECIDED (lab) | ADR-011 (updated 2026-11-17): tenant in captive VRF 101, internet VRF 0 (ADR-017); D-06 (VRF per tenant vs shared) still open for production |
| 1 000 tenant create/delete without leaks | OPEN | |

### P5 — DHCP / DNS

| Gate | Status | Evidence |
|---|---|---|
| DORA via VPP DHCP proxy → Kea | VERIFIED (2026-11-11) | ADR-005; `controller/dhcp_qualification.py` |
| Option 114 = RFC 8908 API URI | VERIFIED (2026-11-16) | Kea reinstalled; OFFER/ACK carry `https://wifi.bsnl.co.in/portal/captive-api/`; `dhcp_qualification` all 5 checks pass (its capture filter now matches QinQ frames); `artifacts/test-reports/2026-11-16-p5-lab-bindings.txt` |
| Lease → SubscriberBinding history (P5-T4) | VERIFIED (2026-11-16) | ADR-013; 4 lab DORAs opened 4 bindings, an expired lease closed at its expiry (`lease_expired`), `/v1/bindings` returns current and historical bindings over mTLS; `artifacts/test-reports/2026-11-16-p5-lab-bindings.txt` |
| MAC from bindings for VPP routers (P5-T6) | VERIFIED (2026-11-17) | portal worker logs `MAC ... from VPP lease binding` and stores it on the session. It is fetched asynchronously and lands after activation, so the activate call carries no MAC (mismatch audit never fires): OPEN. VPP neighbour table as secondary source: OPEN |
| Lease → binding latency p95 ≤ 2 s | VERIFIED (lab, 4 samples) | 0.59–1.64 s (audit ts − lease CLTT), `artifacts/test-reports/2026-11-16-p5-lab-bindings.txt`; not a load test |
| Split DNS by authentication state (P5-T5) | VERIFIED (2026-11-16) | ADR-014: Unbound views; pre-auth captive answers + REFUSED for other names, authenticated /32 view with real answers, controller-driven reload (57–59 ms incl. activation); bypass suite DNS checks; `artifacts/test-reports/2026-11-16-p5-split-dns.txt` |
| Resolver choice D-19, scale | PROVISIONAL | Unbound chosen for the lab; throughput and reload cost at churn not measured |

### P6 — Captive policy

| Gate | Status | Evidence |
|---|---|---|
| Controller-owned tenant ACL (`--enable-vpp-writes`) | VERIFIED (2026-11-16) | tagged ACL `bsnl:acl/<tenant>` (12 rules) bound as the only input ACL; static ACL 0 unbound; `artifacts/test-reports/2026-11-16-vpp-writes-enabled.txt` |
| Pre-auth allowlist incl. DHCP unicast renew | VERIFIED (2026-11-16) | bypass suite pre-auth 14/14 with writes on; `artifacts/test-reports/2026-11-16-vpp-writes-enabled.txt` |
| Per-subscriber authorization enforced before API reply | VERIFIED (2026-11-16) | activate/deactivate return `dataplane_enforced: true` in 67–85 ms (incl. DNS view reload); permit present/absent in VPP; authorized bypass suite passes; same IP is pre-auth again after logout; `artifacts/test-reports/2026-11-16-vpp-writes-enabled.txt` |
| Protected destinations (management LAN, gateway host) | VERIFIED (2026-11-16) | bypass suite, both phases |
| Bypass suite: DoT, foreign DNS, spoofed source, IPv6 RA/ND | VERIFIED (2026-11-16) | both phases pass. In the authorized phase the DoT probe is informational: VPP runs no TCP stack, so permitted TCP to its own address is punted and dropped without RST (trace: acl permit → ip4-receive → punt); ICMP is the authorized-path evidence |
| RFC 8908 Captive Portal API | TESTED | portal `GET /portal/captive-api/`; live after django restart |
| HTTP redirector + ABF for tcp/80 | VERIFIED (2026-11-17) | ADR-015: tenant ACL permits tenant tcp/80 after the protected denies; controller-owned ABF policy (`bsnl:abf/<tenant>`, CRC-pinned) steers it to 198.51.100.2, nft redirects to `bsnl-vpp-redirector` (302 to the portal login). Bypass suite 17/17 in both phases (HTTP to any host -> 302; authorized subscriber's HTTP to its destinations not redirected; management LAN HTTP blocked), portal E2E 8/8, 3 VPP restarts recover in 4.95 s with ABF re-created; `artifacts/test-reports/2026-11-17-p6-http-redirect.txt` |
| MAC/IP source enforcement | VERIFIED (2026-11-17) | ADR-016: controller-owned classifier chain (ip4-inacl) from open lease bindings; lab tenant `enforce`. MACIP ACLs dropped all IPv4 on the 0x8100/0x8100 sub-interface (works untagged), so not used. Unleased in-subnet source and spoofed MAC for a leased IP dropped in both phases; lease -> first forwarded packet 1.11-1.12 s; survives VPP restarts; `artifacts/test-reports/2026-11-17-p6-mac-enforcement.txt`. ARP not filtered (follow-up) |
| D-09 mechanism | DECIDED: SVS (2026-11-17) | ADR-010: B (deployed) per-login cost 0.18 s at 1k, 3.2 s at 10k subscribers, max 4.3 / 0.3 activations/s; A (SVS) 0.4-0.8 ms flat to 10k, 50/s sustained, R-11 fall-through verified on a bench VPP. Adopted (ADR-017) and verified in the lab: DHCP 6/6, bypass 21/21 + 22/22, portal E2E 9/9, restarts 3.75-4.95 s, API activate 72 ms p50. `artifacts/test-reports/2026-11-17-d09-acl-vs-svs.json`, `2026-11-17-d09-svs-lab.txt` |

### P7–P12

NAT/IPDR, QoS/accounting, the VPP adapter end to end with portal QoS,
performance, HA, security operations and migration are **not started**.
Do not open an internet path for subscribers before P7 (NAT, IPDR attribution).

## Known lab exceptions

- ADR-012: subscriber→portal traffic leaves through management NIC `ens18`
  (not SNATed to the portal since 2026-11-17; the portal host has a runtime
  route 10.9.101.0/24 via 10.44.0.207 that is not yet persistent).
- The portal dev instance runs with Django `DEBUG = True` (exposes debug pages);
  turn it off.
