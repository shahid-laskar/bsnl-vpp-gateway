# BSNL VPP Gateway

Lab implementation of the portal repo's `docs/vpp/FINAL_IMPLEMENTATION_PLAN.md`
on an Ubuntu VM (VPP 26.10 over `af_packet`, DPDK disabled).

| Role | Guest interface | Ownership |
|---|---|---|
| Management | `ens18` | Linux / SSH / controller |
| Subscriber access | `ens19` | Linux bridge, VPP `af_packet` |
| Upstream/WAN | `ens20` | Linux bridge, VPP `af_packet` |

Contents:

- `controller/`: desired state, contract-v1 API (mTLS + HMAC), SQLite store
  and audit, subscriber lifecycle, CRC-pinned VPP adapter, QinQ provisioning,
  subscriber authorization with SVS (ADR-017; ACL candidate kept for
  rollback), MAC/IP enforcement from DHCP lease bindings (ADR-016), captive
  HTTP redirector (ADR-015), lease bindings, split-DNS views, host-service
  rendering, lab qualification and bypass tools.
- `tests/`: unit tests against an in-memory VPP fake; `tests/lab/`: root-run
  lab tests (portal E2E, restart recovery, signed controller client).
- `tools/`: API CRC snapshot; `d09_bench.py` + `d09/` (throw-away bench VPP).
- `deployment/`: VPP startup profile and `bsnl-lab.cli`, systemd units, Kea,
  Unbound split DNS (dnsmasq kept for rollback), nftables, install and
  health-check scripts.
- `config/`: JSON schemas (desired state, API v1), golden contract vectors,
  lab topology, desired state and host-service settings.
- `artifacts/`: API CRC snapshot and test reports.

Status, evidence and open gates: [`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md).
Operations: [`docs/LAB_RUNBOOK.md`](docs/LAB_RUNBOOK.md). Decisions: `docs/ADR-*.md`.

Not production-ready: no NAT/IPDR, QoS, HA, performance or hardware
qualification yet.
