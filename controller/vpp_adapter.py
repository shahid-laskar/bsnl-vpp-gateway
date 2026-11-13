"""VPP binary-API adapter (plan P3-T2, P3-T8; audit finding C-8).

- Connects over the binary-API socket with ``vpp_papi`` (from the same FD.io
  release as VPP, F-11).
- At connect time compares VPP's live message table with the pinned snapshot
  ``artifacts/api-crc-<release>.json`` and refuses to operate on any mismatch
  (renamed/changed message => different name_crc).
- ``capabilities()`` is truthful: interface writes and subscriber policy
  enforcement are reported separately. Subscriber policy is not implemented
  until remediation step 5, so ``subscriber_policy_enforced`` stays False and
  the portal keeps sessions out of ``fully_active``.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Callable

from .interfaces import VppInterfaceProvisioner, phase4_object_keys
from .validation import validate_desired_state

LOG = logging.getLogger("bsnl_vpp.vpp_adapter")
DEFAULT_SNAPSHOT = Path(__file__).resolve().parent.parent / "artifacts" / "api-crc-26.10.json"


class CrcMismatchError(RuntimeError):
    pass


def load_snapshot(path: str | Path = DEFAULT_SNAPSHOT) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as handle:
        snapshot = json.load(handle)
    if not snapshot.get("messages"):
        raise ValueError(f"CRC snapshot {path} lists no messages")
    return snapshot


def _default_client_factory(socket: str) -> Any:
    from vpp_papi import VPPApiClient
    return VPPApiClient(server_address=socket, use_socket=True, async_thread=False)


class VppApiAdapter:
    def __init__(self, socket: str = "/run/vpp/api.sock", snapshot_path: str | Path = DEFAULT_SNAPSHOT,
                 enable_writes: bool = False, port_map: dict[str, str] | None = None,
                 client_factory: Callable[[str], Any] = _default_client_factory) -> None:
        self.socket = socket
        self.snapshot = load_snapshot(snapshot_path)
        self.enable_writes = enable_writes
        self.port_map = port_map or {}
        self._factory = client_factory
        self.client: Any = None
        self.connected = False
        self.crc_ok = False
        self.vpp_version: str | None = None
        self.error: str | None = None
        self.last_apply_writes: list[str] = []

    # Connection --------------------------------------------------------------------------
    def connect(self) -> None:
        self.disconnect()
        try:
            client = self._factory(self.socket)
            client.connect("bsnl-vpp-controller")
        except Exception as exc:  # socket missing, permission, VPP down
            self.error = f"connect failed: {type(exc).__name__}: {exc}"
            LOG.error(self.error)
            return
        self.client, self.connected = client, True
        try:
            self.vpp_version = str(getattr(client.api.show_version(), "version", "")).rstrip("\x00")
        except Exception as exc:
            self.vpp_version = None
            LOG.warning("show_version failed: %s", exc)
        missing = list(client.validate_message_table(list(self.snapshot["messages"].values())))
        if missing:
            self.crc_ok = False
            self.error = f"API CRC mismatch against {self.snapshot.get('vpp_release')}: {sorted(missing)}"
            LOG.error("%s; refusing to operate on this VPP", self.error)
            self.disconnect(keep_error=True)
            raise CrcMismatchError(self.error)
        self.crc_ok, self.error = True, None

    def disconnect(self, keep_error: bool = False) -> None:
        if self.client is not None:
            try:
                self.client.disconnect()
            except Exception:
                pass
        self.client, self.connected = None, False
        if not keep_error:
            self.error = None

    def ensure_connected(self) -> bool:
        """Reconnect after a VPP restart; returns True when usable."""
        if self.connected and self.crc_ok:
            try:
                self.client.api.control_ping()
                return True
            except Exception as exc:
                LOG.warning("VPP API ping failed, reconnecting: %s", exc)
        try:
            self.connect()
        except CrcMismatchError:
            return False
        return self.connected and self.crc_ok

    # Contract ----------------------------------------------------------------------------
    def capabilities(self) -> dict[str, Any]:
        usable = self.connected and self.crc_ok
        return {
            "mode": "vpp-papi",
            "socket": self.socket,
            "vpp_connected": self.connected,
            "vpp_version": self.vpp_version,
            "api_crc_snapshot": self.snapshot.get("vpp_release"),
            "api_crc_ok": self.crc_ok,
            "writes_enabled": bool(self.enable_writes and usable),
            "managed_objects": ["qinq_subinterface", "address", "vrf"],
            "subscriber_policy_enforced": False,
            "intra_tenant_policy_enforced": False,
            "error": self.error,
        }

    def observed_state(self) -> dict[str, Any]:
        if not (self.connected and self.crc_ok):
            return {"mode": "vpp-papi", "vpp_connected": self.connected, "api_crc_ok": self.crc_ok, "error": self.error, "objects": []}
        provisioner = VppInterfaceProvisioner(self.client.api, enable_writes=False, port_map=self.port_map)
        return {"mode": "vpp-papi", "vpp_connected": True, "api_crc_ok": True, "vpp_version": self.vpp_version, **provisioner.observe()}

    def apply(self, desired_state: dict[str, Any]) -> list[str]:
        validate_desired_state(desired_state)
        if not self.enable_writes:
            self.last_apply_writes = []
            return phase4_object_keys(desired_state, self.port_map)
        if not self.ensure_connected():
            raise RuntimeError(f"VPP API unavailable: {self.error}")
        provisioner = VppInterfaceProvisioner(self.client.api, enable_writes=True, port_map=self.port_map)
        keys = provisioner.apply(desired_state)
        self.last_apply_writes = list(provisioner.writes)
        return keys
