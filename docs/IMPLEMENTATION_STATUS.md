# BSNL VPP Gateway — Implementation Status

Updated: 2026-11-13 (after the audit and remediation steps 1–6).
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

## Current runtime state (2026-11-13)

- The lab dataplane was **down** from 2026-11-13 06:35 UTC (vppctl oneshot
  units raced the VPP restart; Kea config made unreadable by the host-service
  applier). Fixed in remediation step 1 and reinstalled by the operator with
  `deployment/bin/bsnl-vpp-lab-install`; `bsnl-vpp-lab-check` passed all
  dataplane checks afterwards (its one false failure was a check bug, fixed).
- The 5-cycle restart test (`tests/lab/test_restart_recovery.sh`) has **not
  yet passed** end to end (stopped on that false failure): **READY-TO-RUN**.
- The running controller is the step-3 build (system Python, SQLite, mTLS,
  dry-run). Steps 4–5 code is committed but **not installed**; VPP writes are
  off.

## Branches (not pushed, not merged)

| Repo | Branch chain | Head |
|---|---|---|
| `bsnl-vpp-gateway` | `fix/step1-lab-dataplane` → `fix/step2-controller-contract` → `fix/step4-controller-correctness` → `fix/step5-subscriber-policy` → `docs/step6-status-evidence` | see `git log` |
| `captive-portal-multitenant` | `vpp-setup` → `fix/step2-vpp-contract` → `fix/step3-dataplane-aware` → `fix/step5-captive-api` → `docs/step6-status-evidence` | see `git log` |

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
| VPP restart returns to forwarding (≤ 30 s) | READY-TO-RUN | `sudo sh tests/lab/test_restart_recovery.sh 5` |
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
| VPP restart restores desired state | TESTED (fake) / READY-TO-RUN | `test_vpp_restart_is_restored_and_drift_repaired` |
| Refuse on API CRC mismatch | TESTED | `artifacts/api-crc-26.10.json`, `test_crc_mismatch_refuses_to_operate` |
| Live CRC check against running VPP | READY-TO-RUN | `sudo -u bsnl-vpp python3 -m controller.main --observe-vpp --port-map access0=host-vpp-access --desired-state config/lab/desired-state.json --store /tmp/obs.sqlite3 --audit /tmp/obs.jsonl` → expect `"api_crc_ok": true` |

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
| Option 114 = RFC 8908 API URI | READY-TO-RUN | Kea template updated; reinstall Kea config, then `sudo python3 -m controller.dhcp_qualification` |
| Lease → SubscriberBinding, MAC from leases (P5-T4/T6) | OPEN | VPP routers currently skip MAC lookup |
| Split DNS by authentication state (P5-T5) | OPEN | dnsmasq is a single-view lab fixture (ADR-006) |

### P6 — Captive policy

| Gate | Status | Evidence |
|---|---|---|
| Pre-auth allowlist incl. DHCP unicast renew | TESTED / READY-TO-RUN | `controller/policy.py`; `sudo python3 -m controller.bypass_suite` |
| Per-subscriber authorization enforced before API reply | TESTED | `test_step5.py` (`dataplane_enforced`) |
| Protected destinations (management LAN, gateway host) | TESTED / READY-TO-RUN | bypass suite |
| Bypass suite: DoT, foreign DNS, spoofed source, IPv6 RA/ND | READY-TO-RUN | `controller/bypass_suite.py` |
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
