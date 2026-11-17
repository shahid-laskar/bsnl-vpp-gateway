"""Lab test: how long an authenticated subscriber loses access when VPP restarts.

Run as root on the lab VM from the repo, with the controller running with
``--enable-vpp-writes``:

    sudo python3 -m tests.lab.restart_policy_recovery [--runs 3]

It activates a test subscriber through the controller API (mTLS with the lab
client certificate), puts that address in a throw-away QinQ namespace, and
pings the authorized lab target every 0.2 s while restarting VPP. For each
restart it reports when VPP's own startup config had bound its static ACL
(VPP is back, subscriber still blocked) and when the ping worked again (the
controller re-applied the tenant ACL). The subscriber is deactivated and the
namespace removed on exit.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import time
import uuid
from datetime import datetime, timedelta, timezone

from controller.dhcp_qualification import cleanup, run, setup_namespace, try_run
from tests.lab.controller_client import post

TENANT = "lab-vpp-01/host-vpp-access/0x8100/200/101"


def api(path: str, body: dict, host: str, port: int) -> dict:
    # Signed with the controller HMAC secret when one is configured (2026-11-17).
    return post(path, body, host, port)


def vppctl(*args: str) -> str:
    return try_run("vppctl", *args, timeout=5).stdout.replace("\r", "")


def static_acl_bound() -> bool:
    """bsnl-lab.cli's last command binds ACL 0 ("{cli}") to the sub-interface."""
    return "input acl(s): 0" in vppctl("show", "acl-plugin", "interface")


def ping(nsx: tuple[str, ...], target: str) -> bool:
    return try_run(*nsx, "ping", "-n", "-c", "1", "-W", "1", target, timeout=5).returncode == 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--ip", default="10.9.101.50", help="static subscriber address for the test namespace")
    parser.add_argument("--target", default="192.0.2.1", help="authorized-only destination")
    parser.add_argument("--api-host", default="10.44.0.207")
    parser.add_argument("--api-port", type=int, default=8787)
    parser.add_argument("--max-wait", type=float, default=60)
    args = parser.parse_args()

    ns, host_if = "bsnl-rr", "bsnlrr-host0"
    session_key = f"{TENANT}/{args.ip}"
    session_id = f"restart-test-{uuid.uuid4().hex[:12]}"
    report: dict[str, object] = {"ip": args.ip, "target": args.target, "runs": []}
    cleanup(ns, host_if)
    activated = False
    try:
        nsx = setup_namespace(ns, host_if, "br-access", 200, 101)
        qinq_if = "eth0.200.101"
        run(*nsx, "ip", "addr", "add", f"{args.ip}/24", "dev", qinq_if)
        run(*nsx, "ip", "route", "add", "default", "via", "10.9.101.1")
        report["preauth_blocked"] = not ping(nsx, args.target)

        expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        reply = api("/v1/subscribers/activate", {"operation_id": f"{session_id}-a", "subscriber": {
            "session_key": session_key, "tenant_key": TENANT, "subscriber_id": "restart-test", "session_id": session_id,
            "private_ipv4": args.ip, "mac": None, "valid_until": expiry}}, args.api_host, args.api_port)
        activated = True
        report["activation_enforced"] = reply.get("dataplane_enforced")
        report["authorized_before"] = ping(nsx, args.target)

        for number in range(1, args.runs + 1):
            start = time.monotonic()
            subprocess.run(["systemctl", "restart", "vpp"], check=True, timeout=60)
            restarted = time.monotonic() - start
            static_at = authorized_at = None
            while time.monotonic() - start < args.max_wait:
                now = time.monotonic() - start
                if static_at is None and static_acl_bound():
                    static_at = now
                if ping(nsx, args.target):
                    authorized_at = time.monotonic() - start
                    break
                time.sleep(0.2)
            result = {
                "run": number,
                "systemctl_restart_s": round(restarted, 2),
                "static_acl_bound_s": None if static_at is None else round(static_at, 2),
                "authorized_again_s": None if authorized_at is None else round(authorized_at, 2),
            }
            if static_at is not None and authorized_at is not None:
                result["controller_lag_s"] = round(authorized_at - static_at, 2)
            report["runs"].append(result)
            print(json.dumps(result), flush=True)
            time.sleep(3)
    finally:
        if activated:
            try:
                report["deactivation_enforced"] = api("/v1/subscribers/deactivate", {"operation_id": f"{session_id}-d", "session_key": session_key, "reason": "logout"},
                                                      args.api_host, args.api_port).get("dataplane_enforced")
                report["blocked_after_deactivation"] = not ping(nsx, args.target)
            except Exception as exc:
                report["deactivation_error"] = f"{type(exc).__name__}: {exc}"
        cleanup(ns, host_if)

    runs = report["runs"]
    report["ok"] = bool(
        report.get("preauth_blocked") and report.get("activation_enforced") and report.get("authorized_before")
        and len(runs) == args.runs and all(r["authorized_again_s"] is not None for r in runs)
        and report.get("deactivation_enforced") and report.get("blocked_after_deactivation"))
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
