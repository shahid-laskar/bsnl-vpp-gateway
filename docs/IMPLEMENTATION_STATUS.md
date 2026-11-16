# BSNL VPP Gateway — Implementation Status

Updated: 2026-11-16 (remediation steps 1–6 and Phase 5 P5-T4/T5/T6 on `main`; lab runs done).
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

## Current runtime state (2026-11-16)

- The lab dataplane was **down** from 2026-11-13 06:35 UTC (vppctl oneshot
  units raced the VPP restart; Kea config made unreadable by the host-service
  applier). Fixed in remediation step 1 and reinstalled by the operator with
  `deployment/bin/bsnl-vpp-lab-install`; `bsnl-vpp-lab-check` passed all
  dataplane checks afterwards (its one false failure was a check bug, fixed).
- The 5-cycle restart test (`tests/lab/test_restart_recovery.sh`) has **not
  yet passed** end to end (stopped on that false failure): **READY-TO-RUN**.
- 2026-11-16: the controller unit from `main` is installed and running in
  observe mode (`--observe-vpp`, API CRCs OK against VPP 26.10; writes were
  turned **on** later the same day, see below)
  with Kea lease sync (`SupplementaryGroups=_kea`, `--kea-lease-file`). Kea was
  reinstalled from the repo: option 114 now carries the RFC 8908 API URI.
  Backup of the replaced files: `/root/bsnl-p5-install-20261116T111529.tgz`.
- 2026-11-16: the resolver is **Unbound 1.19.2** with split-horizon views
  (ADR-014); dnsmasq is disabled (config kept for rollback). Backup:
  `/root/bsnl-unbound-install-20261116T113548.tgz`.

## Branches

Remediation steps 1–6 and Phase 5 lease bindings (P5-T4/T6) are merged:
gateway `main`, portal `vpp-setup` (merge commit `a14bd2a`). Not pushed.

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
| `dataplane_type` in DB (migration `portal.0004`) | OPEN | **Not applied on the dev portal** — apply before any VPP router or container restart |
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
| Atomic store, audit with actor/ts/revision | TESTED | `controller/store.py`, `test_step4.py` |
| Topology merged at boot; subscribers survive restart | TESTED | `controller/state.py`, `test_step4.py` |
| Expiry enforced while serving | TESTED | `Reconciler`, `test_reconciler_expires_sessions_while_running` |
| Second apply makes zero VPP writes | TESTED | `test_create_then_second_apply_makes_zero_writes` |
| VPP restart restores desired state | VERIFIED, with a gap | Controller reconnects (broken-pipe fix, `tests/test_vpp_reconnect.py`) and re-applies tag/MTU/ACL on the next reconcile tick: measured 2 s, 29 s, 30 s. Until then the static ACL applies, so authenticated subscribers lose access for up to the reconcile interval (fail closed). Open: re-apply right after a VPP restart; `artifacts/test-reports/2026-11-16-vpp-writes-enabled.txt` |
| Refuse on API CRC mismatch | TESTED | `artifacts/api-crc-26.10.json`, `test_crc_mismatch_refuses_to_operate` |
| Live CRC check against running VPP | VERIFIED (2026-11-16) | running controller reports `"api_crc_ok": true`, `artifacts/test-reports/2026-11-16-p5-lab-bindings.txt`; command: | `sudo -u bsnl-vpp python3 -m controller.main --observe-vpp --port-map access0=host-vpp-access --desired-state config/lab/desired-state.json --store /tmp/obs.sqlite3 --audit /tmp/obs.jsonl` → expect `"api_crc_ok": true` |

### P4 — Interfaces and QinQ

| Gate | Status | Evidence |
|---|---|---|
| Exact-match QinQ, negative tag cases | VERIFIED (2026-11-11) | ADR-004; manual namespace tests |
| 0x88a8 outer TPID | OPEN | ADR-004: failed on af_packet; re-test on hardware |
| Controller-owned sub-interfaces (adopt, repair, tag, orphan cleanup) | TESTED | `controller/interfaces.py`, `test_step4.py` |
| Routing model | DECIDED (lab) | ADR-011: shared FIB (VRF 0) until D-06 |
| 1 000 tenant create/delete without leaks | OPEN | |

### P5 — DHCP / DNS

| Gate | Status | Evidence |
|---|---|---|
| DORA via VPP DHCP proxy → Kea | VERIFIED (2026-11-11) | ADR-005; `controller/dhcp_qualification.py` |
| Option 114 = RFC 8908 API URI | VERIFIED (2026-11-16) | Kea reinstalled; OFFER/ACK carry `https://wifi.bsnl.co.in/portal/captive-api/`; `dhcp_qualification` all 5 checks pass (its capture filter now matches QinQ frames); `artifacts/test-reports/2026-11-16-p5-lab-bindings.txt` |
| Lease → SubscriberBinding history (P5-T4) | VERIFIED (2026-11-16) | ADR-013; 4 lab DORAs opened 4 bindings, an expired lease closed at its expiry (`lease_expired`), `/v1/bindings` returns current and historical bindings over mTLS; `artifacts/test-reports/2026-11-16-p5-lab-bindings.txt` |
| MAC from bindings for VPP routers (P5-T6) | TESTED (portal) / VERIFIED (controller API) | `GET /v1/bindings`; portal `resolve_subscriber_mac`. VPP neighbour table as secondary source: OPEN |
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
| HTTP redirector + ABF for tcp/80 | OPEN | |
| MACIP enforcement | OPEN | lab stays `log_only` |
| D-09 mechanism | PROVISIONAL | ADR-010: ACL (candidate B); SVS (A) not measured |

### P7–P12

NAT/IPDR, QoS/accounting, the VPP adapter end to end with portal QoS,
performance, HA, security operations and migration are **not started**.
Do not open an internet path for subscribers before P7 (NAT, IPDR attribution).

## Known lab exceptions

- ADR-012: subscriber→portal traffic is SNATed out of management NIC `ens18`.
- The portal dev instance runs with Django `DEBUG = True` (exposes debug pages);
  turn it off.
