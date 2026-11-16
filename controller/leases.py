"""Kea DHCPv4 lease source (plan P5-T4, lab).

The lab Kea has no ``lease_cmds`` hook (the ``isc-kea-hooks`` package is not
installed), so leases are read from the memfile backend the same way Kea itself
loads them at start-up:

* the CSV files are append-only logs; the last row for an address wins;
* a row with ``valid_lifetime == 0`` means the lease was deleted;
* during lease-file cleanup (LFC) the set of files changes, and Kea's load
  order is ``.completed`` + current file if a ``.completed`` exists, otherwise
  ``.2``, ``.1`` and then the current file.

Only rows in state 0 (default/assigned) whose expiry is still in the future
are reported as active. A read error raises ``LeaseSourceError``; the caller
must then keep the existing bindings rather than treat the error as "no
leases" (which would close every binding).
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

LEASE_STATE_DEFAULT = 0


class LeaseSourceError(RuntimeError):
    pass


@dataclass(frozen=True)
class Lease:
    address: str
    mac: str
    client_id: str
    valid_lifetime: int
    expire: int
    subnet_id: int
    hostname: str
    state: int

    @property
    def cltt(self) -> int:
        """Client last transmission time: when the lease was last granted or renewed."""
        return self.expire - self.valid_lifetime

    def active_at(self, now: float) -> bool:
        return self.state == LEASE_STATE_DEFAULT and self.valid_lifetime > 0 and self.expire > now and bool(self.mac)


def normalise_mac(value: str) -> str:
    parts = value.strip().lower().replace("-", ":").split(":")
    if len(parts) != 6 or not all(len(p) == 2 and all(c in "0123456789abcdef" for c in p) for p in parts):
        return ""
    return ":".join(parts)


def memfile_load_order(lease_file: Path) -> list[Path]:
    completed = lease_file.with_name(lease_file.name + ".completed")
    if completed.exists():
        candidates = [completed, lease_file]
    else:
        candidates = [lease_file.with_name(lease_file.name + ".2"), lease_file.with_name(lease_file.name + ".1"), lease_file]
    return [path for path in candidates if path.exists()]


def parse_rows(lines: Iterable[str]) -> Iterable[Lease]:
    header: list[str] | None = None
    for raw in lines:
        line = raw.rstrip("\r\n")
        if not line:
            continue
        fields = line.split(",")  # Kea escapes commas inside values as "&#x2c"
        if header is None or fields[0] == "address":
            header = fields
            continue
        row = dict(zip(header, fields))
        try:
            address = str(ipaddress.IPv4Address(row["address"]))
            yield Lease(
                address=address,
                mac=normalise_mac(row.get("hwaddr", "")),
                client_id=row.get("client_id", ""),
                valid_lifetime=int(row["valid_lifetime"]),
                expire=int(row["expire"]),
                subnet_id=int(row["subnet_id"]),
                hostname=row.get("hostname", "").replace("&#x2c", ","),
                state=int(row.get("state") or 0),
            )
        except (KeyError, ValueError):
            continue  # Kea skips malformed rows too; never fail the whole read


class KeaMemfileLeaseSource:
    def __init__(self, lease_file: str | Path = "/var/lib/kea/kea-leases4.csv") -> None:
        self.lease_file = Path(lease_file)

    def current(self) -> dict[str, Lease]:
        """Latest row per address across the memfile set (deleted rows removed)."""
        files = memfile_load_order(self.lease_file)
        if self.lease_file not in files:
            raise LeaseSourceError(f"lease file {self.lease_file} not found or not readable")
        latest: dict[str, Lease] = {}
        for path in files:
            try:
                with path.open(encoding="utf-8", errors="replace") as handle:
                    for lease in parse_rows(handle):
                        if lease.valid_lifetime == 0:
                            latest.pop(lease.address, None)
                        else:
                            latest[lease.address] = lease
            except FileNotFoundError:
                continue  # LFC rotated it away between listing and opening
            except OSError as exc:
                raise LeaseSourceError(f"cannot read {path}: {exc}") from exc
        return latest

    def active(self, now: float) -> list[Lease]:
        return [lease for lease in self.current().values() if lease.active_at(now)]
