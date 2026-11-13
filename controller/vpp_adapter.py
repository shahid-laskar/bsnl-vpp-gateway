from __future__ import annotations

from typing import Any

from .keys import desired_object_keys
from .validation import validate_desired_state


class VppApiAdapter:
    """Phase 3 VPP connection/observation adapter.

    Object mutation is intentionally disabled until Phase 4 interface
    reconciliation is qualified.
    """

    def __init__(self, socket: str = "/run/vpp/api.sock", expected_crcs: dict[str, str] | None = None) -> None:
        self.socket = socket
        self.expected_crcs = expected_crcs or {}
        self.client = None
        self.connected = False
        self.error = None

    def connect(self) -> None:
        try:
            from vpp_papi import VPPApiClient
            self.client = VPPApiClient(use_socket=True, async_thread=False)
            self.client.connect("bsnl-vpp-controller")
            self.connected = True
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"
            self.connected = False

    def observed_state(self) -> dict[str, Any]:
        return {"mode": "vpp-papi", "vpp_connected": self.connected, "socket": self.socket, "error": self.error, "objects": []}

    def capabilities(self) -> dict[str, Any]:
        return {"mode": "vpp-papi", "writes_enabled": False, "phase": 3, "socket": self.socket, "crc_pinned": bool(self.expected_crcs)}

    def apply(self, desired_state: dict[str, Any]) -> list[str]:
        validate_desired_state(desired_state)
        if not self.connected:
            raise RuntimeError("VPP API is not connected")
        raise NotImplementedError("VPP object writes are enabled in Phase 4")

    def planned_object_keys(self, desired_state: dict[str, Any]) -> list[str]:
        validate_desired_state(desired_state)
        return desired_object_keys(desired_state)
