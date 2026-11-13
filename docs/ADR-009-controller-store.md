# ADR-009: Controller store is SQLite (decision D-20, lab)

## Status

Provisional for the lab (D-20). Re-confirm with a crash-consistency test before
pilot.

## Decision

The controller keeps desired state, idempotency records and the audit log in
one SQLite database in WAL mode (`synchronous=FULL`). Every operation runs in a
single `BEGIN IMMEDIATE` transaction covering the state change, its
idempotency record and its audit event (`controller/store.py`). The JSON file
backend of earlier phases was removed because it could not make those three
writes atomic.

Topology (tenants, pools, policies) is owned by the desired-state file and
merged at boot; subscribers are owned by the API (`controller/state.py`).
Idempotency records are pruned after 7 days. `--audit` is a best-effort JSONL
mirror; the SQLite `audit` table is authoritative.

## Consequences

- One writer at a time (`BEGIN IMMEDIATE`); adequate for lab event rates, to be
  measured against P0-T3 peak login rates before pilot.
- If the store is lost, the controller rebuilds topology from the file and
  needs Django to resend active sessions (resync API: open).

## Evidence

`tests/test_step4.py` (rollback of all three records on failure, restart
keeps subscribers, topology edit keeps subscribers).
