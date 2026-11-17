"""Signed lab client for the controller API (mTLS + HMAC, ADR-007). Run as root.

Uses the lab client certificate and, when ``controller.env`` sets
``BSNL_VPP_PORTAL_HMAC_SECRET`` (the lab does since 2026-11-17), signs every
POST exactly like the portal does; unsigned POSTs are then rejected with 401.

    sudo python3 -m tests.lab.controller_client activate --ip 10.9.101.50 [--minutes 30]
    sudo python3 -m tests.lab.controller_client deactivate --ip 10.9.101.50
"""
from __future__ import annotations

import argparse
import http.client
import json
import secrets
import ssl
import time
import uuid
from datetime import datetime, timedelta, timezone

from controller.contract import sign

TENANT = "lab-vpp-01/host-vpp-access/0x8100/200/101"
TLS = "/etc/bsnl-vpp-gateway/tls"
ENV = "/etc/bsnl-vpp-gateway/controller.env"


def hmac_secret(path: str = ENV) -> str | None:
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except FileNotFoundError:
        return None
    for line in lines:
        if line.startswith("BSNL_VPP_PORTAL_HMAC_SECRET="):
            return line.partition("=")[2].strip() or None
    return None


def post(path: str, body: dict, host: str = "10.44.0.207", port: int = 8787) -> dict:
    raw = json.dumps(body).encode()
    headers = {"Content-Type": "application/json", "Idempotency-Key": body["operation_id"]}
    secret = hmac_secret()
    if secret:
        timestamp, nonce = str(int(time.time())), secrets.token_hex(16)
        headers.update({"X-BSNL-Timestamp": timestamp, "X-BSNL-Nonce": nonce,
                        "X-BSNL-Signature": sign(secret, timestamp, nonce, "POST", path, headers["Idempotency-Key"], raw)})
    context = ssl.create_default_context(cafile=f"{TLS}/ca.crt")
    context.check_hostname = False  # lab server cert; the CA is still verified
    context.load_cert_chain(f"{TLS}/client.crt", f"{TLS}/client.key")
    connection = http.client.HTTPSConnection(host, port, context=context, timeout=10)
    connection.request("POST", path, body=raw, headers=headers)
    response = connection.getresponse()
    payload = json.loads(response.read() or b"{}")
    connection.close()
    if response.status != 200:
        raise RuntimeError(f"{path} -> HTTP {response.status}: {payload}")
    return payload


def activate(ip: str, minutes: float = 60, session_id: str | None = None, **kw) -> dict:
    session_id = session_id or f"lab-{uuid.uuid4().hex[:12]}"
    expiry = (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()
    return post("/v1/subscribers/activate", {"operation_id": f"{session_id}-a", "subscriber": {
        "session_key": f"{TENANT}/{ip}", "tenant_key": TENANT, "subscriber_id": "lab-test", "session_id": session_id,
        "private_ipv4": ip, "mac": None, "valid_until": expiry}}, **kw)


def deactivate(ip: str, operation_id: str | None = None, **kw) -> dict:
    return post("/v1/subscribers/deactivate", {"operation_id": operation_id or f"lab-{uuid.uuid4().hex[:12]}-d",
                                               "session_key": f"{TENANT}/{ip}", "reason": "logout"}, **kw)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=("activate", "deactivate"))
    parser.add_argument("--ip", required=True)
    parser.add_argument("--minutes", type=float, default=60)
    args = parser.parse_args()
    reply = activate(args.ip, args.minutes) if args.action == "activate" else deactivate(args.ip)
    print(json.dumps({k: reply.get(k) for k in ("session_key", "authorized", "changed", "dataplane_enforced", "gateway_revision")}))
    return 0 if reply.get("dataplane_enforced") else 1


if __name__ == "__main__":
    raise SystemExit(main())
