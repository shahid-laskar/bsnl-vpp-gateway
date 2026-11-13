"""Controller durable store: SQLite in WAL mode (decision D-20, lab).

One ``transaction()`` covers the desired state, the idempotency record and the
audit event of an operation, so a crash can never leave a state change without
its idempotency record (which would re-apply on retry) or without its audit
event. Connections are always closed (``sqlite3``'s context manager only
commits). The JSON file backend of earlier phases was removed; it could not be
made atomic across these three records.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

IDEMPOTENCY_TTL = timedelta(days=7)

SCHEMA = (
    "CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK (id=1), payload TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS idempotency (idempotency_key TEXT PRIMARY KEY, request_hash TEXT NOT NULL, result TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT '1970-01-01T00:00:00+00:00')",
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def request_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(payload).hexdigest()


class StoreTransaction:
    def __init__(self, connection: sqlite3.Connection, audit_mirror: Path | None) -> None:
        self.connection = connection
        self._mirror = audit_mirror
        self.audit_events: list[dict[str, Any]] = []

    def read(self) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT payload FROM state WHERE id=1").fetchone()
        return json.loads(row[0]) if row else None

    def write(self, state: dict[str, Any]) -> None:
        payload = json.dumps(state, indent=2, sort_keys=True)
        self.connection.execute("INSERT INTO state(id,payload) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", (payload,))

    def get_idempotency(self, key: str) -> dict[str, str] | None:
        row = self.connection.execute("SELECT request_hash, result FROM idempotency WHERE idempotency_key=?", (key,)).fetchone()
        return {"request_hash": row[0], "result": row[1]} if row else None

    def put_idempotency(self, key: str, fingerprint: str, result: dict[str, Any]) -> None:
        self.connection.execute(
            "INSERT INTO idempotency(idempotency_key,request_hash,result,created_at) VALUES(?,?,?,?)",
            (key, fingerprint, json.dumps(result, sort_keys=True), utcnow().isoformat()),
        )

    def append_audit(self, event: dict[str, Any]) -> None:
        record = {"ts": utcnow().isoformat(), **event}
        self.connection.execute("INSERT INTO audit(payload) VALUES(?)", (json.dumps(record, sort_keys=True),))
        self.audit_events.append(record)


class DesiredStateStore:
    def __init__(self, path: str | Path, audit_mirror: str | Path | None = None) -> None:
        self.path = Path(path)
        self.audit_mirror = Path(audit_mirror) if audit_mirror else None
        self._initialised = False

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, isolation_level=None, timeout=30)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        if not self._initialised:
            for statement in SCHEMA:
                connection.execute(statement)
            columns = {row[1] for row in connection.execute("PRAGMA table_info(idempotency)")}
            if "created_at" not in columns:  # upgrade a step-2 database in place
                connection.execute("ALTER TABLE idempotency ADD COLUMN created_at TEXT NOT NULL DEFAULT '1970-01-01T00:00:00+00:00'")
            self._initialised = True
        return connection

    @contextmanager
    def transaction(self) -> Iterator[StoreTransaction]:
        """Serialised read-modify-write; commits only if the block succeeds."""
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            txn = StoreTransaction(connection, self.audit_mirror)
            try:
                yield txn
            except BaseException:
                connection.execute("ROLLBACK")
                raise
            connection.execute("COMMIT")
        self._mirror_audit(txn.audit_events)

    def _mirror_audit(self, events: list[dict[str, Any]]) -> None:
        """Best-effort JSONL copy for operators; the SQLite table is authoritative."""
        if not events or self.audit_mirror is None:
            return
        try:
            self.audit_mirror.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_mirror.open("a", encoding="utf-8") as handle:
                for event in events:
                    handle.write(json.dumps(event, sort_keys=True) + "\n")
        except OSError:
            pass

    # Convenience single-statement helpers -------------------------------------------------
    def read(self) -> dict[str, Any] | None:
        with self.transaction() as txn:
            return txn.read()

    def write(self, state: dict[str, Any]) -> None:
        with self.transaction() as txn:
            txn.write(state)

    def append_audit(self, event: dict[str, Any]) -> None:
        with self.transaction() as txn:
            txn.append_audit(event)

    def audit_events(self) -> list[dict[str, Any]]:
        with closing(self._connect()) as connection:
            return [json.loads(row[0]) for row in connection.execute("SELECT payload FROM audit ORDER BY id")]

    def prune_idempotency(self, now: datetime | None = None) -> int:
        cutoff = ((now or utcnow()) - IDEMPOTENCY_TTL).isoformat()
        with self.transaction() as txn:
            return txn.connection.execute("DELETE FROM idempotency WHERE created_at < ?", (cutoff,)).rowcount
