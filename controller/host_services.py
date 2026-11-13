from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
from collections.abc import Callable, Sequence
from typing import Any


class HostServiceValidationError(ValueError):
    pass


@dataclass(frozen=True)
class HostServicePlan:
    tenant_key: str
    subnet: ipaddress.IPv4Network
    gateway: ipaddress.IPv4Address
    pool_start: ipaddress.IPv4Address
    pool_end: ipaddress.IPv4Address
    relay_address: ipaddress.IPv4Address
    dns_address: ipaddress.IPv4Address
    lease_lifetime_seconds: int
    portal_url: str

    @property
    def dhcp_key(self) -> str:
        return f"service/dhcp/{self.tenant_key}"

    @property
    def dns_key(self) -> str:
        return f"service/dns/{self.tenant_key}"


def host_service_plan(tenant: dict[str, Any], services: dict[str, Any]) -> HostServicePlan:
    try:
        network = ipaddress.ip_interface(tenant["gateway_ip"])
        subnet = network.network
        gateway = network.ip
        dhcp = tenant["dhcp_ranges"][0]
        pool_start = ipaddress.ip_address(dhcp["start"])
        pool_end = ipaddress.ip_address(dhcp["end"])
        relay = ipaddress.ip_address(services["relay_address"])
        dns = ipaddress.ip_address(services["dns_address"])
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise HostServiceValidationError(f"invalid DHCP/DNS service fields: {exc}") from exc
    values = (gateway, pool_start, pool_end)
    if any(value.version != 4 or value not in subnet for value in values):
        raise HostServiceValidationError("gateway and DHCP pool must be IPv4 addresses inside tenant subnet")
    if pool_start > pool_end or int(gateway) in range(int(pool_start), int(pool_end) + 1):
        raise HostServiceValidationError("DHCP pool is invalid or contains the gateway")
    lifetime = int(services.get("lease_lifetime_seconds", 300))
    if not 60 <= lifetime <= 86400:
        raise HostServiceValidationError("lease_lifetime_seconds must be between 60 and 86400")
    portal_url = services.get("portal_url", "")
    if not isinstance(portal_url, str) or not portal_url.startswith("https://"):
        raise HostServiceValidationError("portal_url must use HTTPS")
    return HostServicePlan(tenant["tenant_key"], subnet, gateway, pool_start, pool_end, relay, dns, lifetime, portal_url)


def host_service_plans(desired_state: dict[str, Any], services: dict[str, Any]) -> list[HostServicePlan]:
    return [host_service_plan(tenant, services) for tenant in desired_state.get("tenants", []) if tenant.get("admin_state", "enabled") == "enabled"]


def render_kea_subnet(plan: HostServicePlan) -> dict[str, Any]:
    return {
        "id": int(plan.tenant_key.rsplit("/", 1)[-1]) if plan.tenant_key.rsplit("/", 1)[-1].isdigit() else int.from_bytes(hashlib.sha256(plan.tenant_key.encode()).digest()[:4], "big") & 0x7FFFFFFF,
        "subnet": str(plan.subnet),
        "relay": {"ip-addresses": [str(plan.relay_address)]},
        "pools": [{"pool": f"{plan.pool_start}-{plan.pool_end}"}],
        "option-data": [
            {"name": "routers", "data": str(plan.gateway)},
            {"name": "domain-name-servers", "data": str(plan.dns_address), "always-send": True},
            {"name": "v4-captive-portal", "data": plan.portal_url, "always-send": True},
        ],
    }


def render_dns_records(plan: HostServicePlan, captive_hosts: list[str]) -> dict[str, str]:
    return {host: str(plan.dns_address if host == "portal.lab" else "10.44.0.209") for host in captive_hosts}


def render_kea_config(plans: list[HostServicePlan], interface: str = "br-wan") -> str:
    subnets = [render_kea_subnet(plan) for plan in plans]
    document = {"Dhcp4": {
        "interfaces-config": {"interfaces": [interface]},
        "control-socket": {"socket-type": "unix", "socket-name": "kea4-ctrl-socket"},
        "lease-database": {"type": "memfile", "name": "/var/lib/kea/kea-leases4.csv", "lfc-interval": 60},
        "valid-lifetime": plans[0].lease_lifetime_seconds if plans else 300,
        "renew-timer": 150,
        "rebind-timer": 240,
        "subnet4": subnets,
        "loggers": [{"name": "kea-dhcp4", "output-options": [{"output": "/var/log/kea/kea-dhcp4.log"}], "severity": "INFO"}],
    }}
    return json.dumps(document, indent=2) + "\n"


def render_dnsmasq_config(plans: list[HostServicePlan], captive_hosts: list[str]) -> str:
    if not plans:
        raise HostServiceValidationError("at least one enabled tenant is required for dnsmasq")
    dns_address = str(plans[0].dns_address)
    lines = [
        "interface=br-wan",
        "bind-interfaces",
        f"listen-address={dns_address}",
        "no-dhcp-interface=br-wan",
        "cache-size=1000",
        "domain-needed",
        "bogus-priv",
    ]
    for host, address in render_dns_records(plans[0], captive_hosts).items():
        lines.append(f"address=/{host}/{address}")
    lines.append("log-queries")
    return "\n".join(lines) + "\n"


DEFAULT_BACKUP_DIR = Path("/var/lib/bsnl-vpp-gateway/backups")
DEFAULT_NEW_FILE_MODE = 0o644


class AtomicConfigApplier:
    """Write a validated config with a recoverable backup and atomic replace.

    The replacement keeps the existing target's owner, group and mode. Daemons
    such as Kea 3.0 run unprivileged (``_kea``) and fail to start if their
    config silently becomes ``root:root 0600`` (the ``NamedTemporaryFile``
    default). Backups are written to ``backup_dir`` and never next to the
    target, because a ``.bak`` inside a ``conf-dir`` such as ``/etc/dnsmasq.d``
    is loaded by the daemon as live configuration.
    """

    def __init__(self, validator=None, backup_dir: str | Path = DEFAULT_BACKUP_DIR):
        self.validator = validator or (lambda path: None)
        self.backup_dir = Path(backup_dir)

    def backup_path(self, target_path: Path) -> Path:
        flattened = str(target_path).strip("/").replace("/", "__")
        return self.backup_dir / f"{flattened}.bak"

    def apply(self, target: str | Path, content: str) -> Path | None:
        target_path = Path(target)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        backup = None
        existing = target_path.stat() if target_path.exists() else None
        if existing is not None:
            self.backup_dir.mkdir(parents=True, exist_ok=True)
            backup = self.backup_path(target_path)
            shutil.copy2(target_path, backup)
        with tempfile.NamedTemporaryFile("w", dir=target_path.parent, prefix=f".{target_path.name}.", delete=False) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
            temporary = Path(handle.name)
        try:
            if existing is not None:
                os.chmod(temporary, stat.S_IMODE(existing.st_mode))
                if (existing.st_uid, existing.st_gid) != (os.geteuid(), os.getegid()):
                    os.chown(temporary, existing.st_uid, existing.st_gid)
            else:
                os.chmod(temporary, DEFAULT_NEW_FILE_MODE)
            self.validator(temporary)
            temporary.replace(target_path)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        return backup


class ServiceReconciler:
    """Apply one host-service config and roll back if daemon reload fails."""

    def __init__(self, runner: Callable[[Sequence[str]], None] | None = None, backup_dir: str | Path = DEFAULT_BACKUP_DIR):
        self.runner = runner or self._subprocess_runner
        self.backup_dir = Path(backup_dir)

    def apply_and_reload(self, target: str | Path, content: str, validate: Sequence[str], reload: Sequence[str]) -> Path | None:
        target_path = Path(target)
        def validate_temp(path: Path) -> None:
            command = [f"{item}{path}" if item.endswith("=") else item for item in validate]
            if not any(item.endswith("=") for item in validate):
                command.append(str(path))
            self.runner(command)
        applier = AtomicConfigApplier(validate_temp, self.backup_dir)
        backup = applier.apply(target_path, content)
        try:
            self.runner(list(reload))
        except Exception:
            if backup is not None:
                shutil.copy2(backup, target_path)
                try:
                    self.runner(list(reload))
                except Exception:
                    pass
            raise
        return backup

    @staticmethod
    def _subprocess_runner(command: Sequence[str]) -> None:
        import subprocess
        subprocess.run(command, check=True, capture_output=True, text=True)
