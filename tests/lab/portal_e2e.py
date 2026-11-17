"""Portal -> VPP end-to-end login from a QinQ subscriber namespace (run as root).

    sudo python3 -m tests.lab.portal_e2e --username vpplab1 --password-file FILE

What it proves (remediation "next work" 1, ADR-007):

1. A subscriber behind br-access (QinQ 200/101) gets a DHCP lease and, before
   login, cannot reach the lab authorized target (192.0.2.1).
2. A real password login on the existing Django portal (10.44.0.209), which
   identifies router and customer from the subscriber's own address, makes the
   portal call the controller (mTLS + HMAC). The portal reports the session
   activated only when the controller answered ``dataplane_enforced: true``.
3. The authorized target becomes reachable; after logout it is blocked again.

The password is read from a file so it never appears in argv or logs.
Exit status 0 only when every expectation holds.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import time
import urllib.parse
from pathlib import Path

from controller.dhcp_qualification import cleanup, setup_namespace, try_run, wait_forwarded


def ping_once(nsx, target: str) -> bool:
    return try_run(*nsx, "ping", "-c", "1", "-W", "1", target, timeout=5).returncode == 0


def wait_for(predicate, timeout: float, interval: float = 0.5) -> float | None:
    """Seconds until predicate() is true, or None on timeout."""
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if predicate():
            return round(time.monotonic() - start, 2)
        time.sleep(interval)
    return None


class PortalClient:
    """curl inside the subscriber namespace with a cookie jar (Django session + CSRF)."""

    def __init__(self, nsx, host: str, address: str, jar: Path, insecure: bool) -> None:
        self.nsx, self.host, self.jar = nsx, host, jar
        self.base = f"https://{host}"
        self.common = ["curl", "-sS", "--max-time", "15", "-c", str(jar), "-b", str(jar),
                       "--resolve", f"{host}:443:{address}", "-w", "\n%{http_code}"] + (["-k"] if insecure else [])

    def _run(self, *args: str) -> tuple[int, str]:
        result = try_run(*self.nsx, *self.common, *args, timeout=25)
        if result.returncode != 0:
            return -result.returncode, result.stderr.strip()
        body, _, code = result.stdout.rpartition("\n")
        return int(code), body

    def csrf_token(self) -> str:
        for line in self.jar.read_text().splitlines() if self.jar.exists() else []:
            fields = line.split("\t")
            if len(fields) == 7 and fields[5] == "csrftoken":
                return fields[6]
        return ""

    def get(self, path: str) -> tuple[int, str]:
        return self._run(self.base + path)

    def post(self, path: str, form: dict[str, str] | None = None, *, data_file: Path | None = None) -> tuple[int, str]:
        args = ["-X", "POST", "-H", f"X-CSRFToken: {self.csrf_token()}", "-H", f"Referer: {self.base}/portal/login/"]
        if data_file is not None:
            args += ["--data-binary", f"@{data_file}"]
        for key, value in (form or {}).items():
            args += ["--data-urlencode", f"{key}={value}"]
        return self._run(*args, self.base + path)


def as_json(body: str) -> dict:
    try:
        value = json.loads(body)
    except ValueError:
        return {"unparsed": body[:200]}
    return value if isinstance(value, dict) else {"value": value}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password-file", required=True, type=Path)
    parser.add_argument("--portal-host", default="wifi.bsnl.co.in")
    parser.add_argument("--portal", default="10.44.0.209")
    parser.add_argument("--authorized-target", default="192.0.2.1")
    parser.add_argument("--activation-timeout", type=float, default=30)
    parser.add_argument("--insecure", action="store_true", help="skip portal TLS verification (lab certificate)")
    parser.add_argument("--keep-session", action="store_true", help="do not log out at the end")
    parser.add_argument("--namespace", default="bsnl-e2e")
    parser.add_argument("--host-if", default="bsnle-host0")
    parser.add_argument("--outer-vlan", type=int, default=200)
    parser.add_argument("--inner-vlan", type=int, default=101)
    args = parser.parse_args()

    ns, host_if = args.namespace, args.host_if
    qinq_if = f"eth0.{args.outer_vlan}.{args.inner_vlan}"
    work = Path(f"/run/{ns}")
    checks: dict[str, dict] = {}

    def expect(name, ok, **detail):
        checks[name] = {"ok": bool(ok), **detail}
        return bool(ok)

    cleanup(ns, host_if)
    work.mkdir(mode=0o700, exist_ok=True)
    # The password reaches curl through a root-only file, never argv.
    form = work / "login.form"
    password = args.password_file.read_text().strip()
    try:
        nsx = setup_namespace(ns, host_if, "br-access", args.outer_vlan, args.inner_vlan)
        try_run(*nsx, "dhclient", "-1", "-pf", str(work / "dhclient.pid"), "-lf", str(work / "leases"), qinq_if, timeout=40)
        fields = try_run(*nsx, "ip", "-4", "-o", "addr", "show", "dev", qinq_if).stdout.split()
        address = next((f.split("/")[0] for f in fields if "/" in f and f.startswith("10.")), "")
        mac = try_run(*nsx, "cat", f"/sys/class/net/{qinq_if}/address").stdout.strip()
        if not expect("dhcp_lease", address, address=address, mac=mac):
            raise RuntimeError("no DHCP lease")

        # MAC enforcement (ADR-016): the lease is forwarded once the controller programmed it.
        expect("forwarded_after_lease", (first := wait_forwarded(nsx, args.portal, 10)) is not None, seconds=first)
        expect("preauth_target_blocked", not ping_once(nsx, args.authorized_target))

        portal = PortalClient(nsx, args.portal_host, args.portal, work / "cookies", args.insecure)
        code, body = portal.get("/portal/login/")
        expect("login_page", code == 200 and portal.csrf_token(), http=code,
               customer_resolved="Customer not found" not in body)

        form.touch(mode=0o600)
        form.write_text(urllib.parse.urlencode({"username": args.username, "password": password}))
        started = time.monotonic()
        code, body = portal.post("/portal/login/", data_file=form)
        form.unlink()
        login = as_json(body)
        if not expect("login_accepted", code == 200 and login.get("success") is True, http=code,
                      response={k: login.get(k) for k in ("success", "error", "error_code", "redirect") if k in login}):
            raise RuntimeError("login rejected")

        status: dict = {}

        def activated() -> bool:
            nonlocal status
            _, raw = portal.get("/portal/session/activation-status/")
            status = as_json(raw)
            return status.get("activated") is True

        activated_after = wait_for(activated, args.activation_timeout)
        expect("portal_reports_activated", activated_after is not None, seconds_after_login=activated_after,
               status={k: status.get(k) for k in ("activated", "authenticated", "error") if k in status})
        reachable_after = wait_for(lambda: ping_once(nsx, args.authorized_target), args.activation_timeout)
        expect("authorized_target_reachable", reachable_after is not None,
               seconds_after_login=None if reachable_after is None else round(time.monotonic() - started, 2))

        if not args.keep_session:
            code, body = portal.post("/portal/logout/")
            expect("logout_accepted", code == 200 and as_json(body).get("success") is True, http=code)
            blocked_after = wait_for(lambda: not ping_once(nsx, args.authorized_target), args.activation_timeout)
            expect("target_blocked_after_logout", blocked_after is not None, seconds_after_logout=blocked_after)
    except (subprocess.CalledProcessError, RuntimeError, OSError) as exc:
        expect("harness", False, error=str(exc))
    finally:
        form.unlink(missing_ok=True)
        if not args.keep_session:
            cleanup(ns, host_if)
            for leftover in work.glob("*"):
                leftover.unlink()
            work.rmdir()

    report = {"checks": checks, "ok": all(c["ok"] for c in checks.values())}
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
