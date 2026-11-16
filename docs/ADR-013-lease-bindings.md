# ADR-013: Lease → SubscriberBinding history and MAC lookup (P5-T4, P5-T6)

## Status

Implemented and tested against fixtures (2026-11-16). Not yet installed on the
lab VM; the controller unit needs `SupplementaryGroups=_kea` (see below).

## Context

VyOS supplies the portal with a client's MAC from its ARP table or DHCP
leases. The VPP lab has neither path, so the portal skipped MAC lookup for VPP
routers. The FINAL plan (section 5.3) also requires an append-only
SubscriberBinding history so that an IP can be attributed to a device "as of"
an event time (IPDR enrichment, Phase 7).

The lab Kea 3.0.5 has no `lease_cmds` hook (`isc-kea-hooks` is not
installed) and stores leases in the memfile backend.

## Decision

- **Source (lab):** the controller reads Kea's memfile lease CSVs
  (`controller/leases.py`) every second (`--kea-lease-file`,
  `--lease-poll-interval`). Rows are replayed the way Kea loads them: last row
  per address wins, `valid_lifetime 0` deletes, and the LFC file set is
  honoured (`.completed` + current, else `.2`, `.1`, current). Only state-0,
  unexpired leases with a MAC are active.
- **Mapping:** lease `subnet_id` → enabled tenant via `kea_subnet_id` (the same
  rule the Kea renderer uses); the address must lie in the tenant subnet.
- **History:** table `bindings` in the controller SQLite store
  (`controller/bindings.py`). A binding opens at the lease's CLTT when a
  (tenant, IP, MAC) lease is first seen; renewals move `lease_expire` only; it
  closes with `lease_expired` (at the lease expiry, even if detected later),
  `lease_released` (at detection) or `mac_changed` (at the new lease's CLTT).
  Consecutive bindings for one IP never overlap. Rows are never deleted.
  Opens and closes are audited (`actor: kea-lease-sync`).
- **Fail safe:** a lease-source error (missing file, permission) keeps all
  bindings unchanged; it is never read as "no leases".
- **API:** `GET /v1/bindings?tenant_key=&private_ipv4=[&at=RFC3339]`
  (transport-authenticated like the other GETs) returns the binding valid at
  `at` (default now) or `null`. Schema `bindingResponse`; golden vector
  `config/contract/golden/binding.json`.
- **Activation cross-check:** if the portal sends a MAC that differs from the
  open binding, `subscriber.mac_mismatch` is audited and the activation
  proceeds (all tenants are effectively `log_only` until MACIP enforcement,
  Phase 6).
- **Portal (P5-T6):** VPP routers resolve MAC through this endpoint instead of
  skipping the lookup (portal repo, `vpp_authorization.resolve_subscriber_mac`).

## Consequences and limits

- Polling the whole memfile costs O(lease-file size) per second: fine for the
  lab, not for production. Production should use Kea hooks (push on
  `lease4_committed`/`lease4_release`/`lease4_expire`, or `lease_cmds` with
  paging); the binding history and API are independent of the source.
- The VPP neighbour table as a secondary MAC source (P5-T6) is not
  implemented; leases are the only source.
- Static-IP clients (no lease) have no binding.
- Latency target (lease → binding p95 ≤ 2 s) is met by design (1 s poll) and
  by `test_watcher_picks_up_a_new_lease_within_one_poll`; it still needs lab
  evidence from a real DORA.

## Install (root, lab VM)

```bash
sudo install -m 0644 deployment/systemd/bsnl-vpp-controller.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl restart bsnl-vpp-controller
sudo -u bsnl-vpp -g _kea head -1 /var/lib/kea/kea-leases4.csv   # readable?
```

Then run a DORA (`sudo python3 -m controller.dhcp_qualification`) and query
`/v1/bindings` for the leased address.
