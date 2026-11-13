from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Any


class DesiredStateStore:
    """Crash-safe JSON or SQLite-WAL state store.

    JSON is retained for compatibility with the lab fixture. SQLite is the
    Phase 3 production-shaped store and is selected by a .sqlite3 path.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.sqlite = self.path.suffix in {".sqlite", ".sqlite3", ".db"}

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK (id=1), payload TEXT NOT NULL)")
        connection.execute("CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL)")
        connection.commit()
        return connection

    def read(self) -> dict[str, Any] | None:
        if self.sqlite:
            with self._connect() as connection:
                row = connection.execute("SELECT payload FROM state WHERE id=1").fetchone()
            return json.loads(row[0]) if row else None
        if not self.path.exists():
            return None
        with self.path.open(encoding="utf-8") as handle:
            return json.load(handle)

    def write(self, state: dict[str, Any]) -> None:
        if self.sqlite:
            payload = json.dumps(state, indent=2, sort_keys=True)
            with self._connect() as connection:
                connection.execute("INSERT INTO state(id,payload) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", (payload,))
                connection.commit()
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(state, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def append_audit(self, event: dict[str, Any]) -> None:
        if self.sqlite:
            with self._connect() as connection:
                connection.execute("INSERT INTO audit(payload) VALUES(?)", (json.dumps(event, sort_keys=True),))
                connection.commit()
            return
        audit_path = self.path.with_suffix(self.path.suffix + ".audit.jsonl")
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        with audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
