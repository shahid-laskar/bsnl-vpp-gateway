"""Temporary QinQ subscriber qualification for the VM lab (run as root).

Creates a throw-away network namespace behind ``br-access`` with a
double-tagged interface, obtains a DHCP lease through VPP's DHCP proxy and,
optionally, checks DNS, portal HTTP and the pre-auth deny path. Every
process started inside the namespace is killed and the namespace and veth are
removed on exit, even on failure. Earlier versions left ``dhclient`` daemons
running (``dhclient -1`` forks into the background after a lease), which kept
the namespace alive and consumed Kea leases.

Exit status is 0 only when every requested check passes.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import tempfile
import time
from pathlib import Path


def run(*args: str, timeout: float = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=timeout)


def try_run(*args: str, timeout: float = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=False, text=True, capture_output=True, timeout=timeout)


def namespace_pids(ns: str) -> list[int]:
    result = try_run("ip", "netns", "pids", ns)
    return [int(item) for item in result.stdout.split() if item.isdigit()]


def kill_namespace_processes(ns: str) -> None:
    for sig in (signal.SIGTERM, signal.SIGKILL):
        pids = namespace_pids(ns)
        if not pids:
            return
        for pid in pids:
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                pass
        time.sleep(0.5)


def cleanup(ns: str, host_if: str) -> None:
    kill_namespace_processes(ns)
    try_run("ip", "netns", "del", ns)
    try_run("ip", "link", "del", host_if)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a temporary QinQ DHCP/portal qualification")
    parser.add_argument("--namespace", default="bsnl-qual")
    parser.add_argument("--host-if", default="bsnlq-host0", help="bridge-side veth name (max 15 bytes)")
    parser.add_argument("--bridge", default="br-access")
    parser.add_argument("--outer-vlan", type=int, default=200)
    parser.add_argument("--inner-vlan", type=int, default=101)
    parser.add_argument("--dhcp-timeout", type=float, default=30)
    parser.add_argument("--dns-server", default="198.51.100.2")
    parser.add_argument("--dns-name", default="wifi.bsnl.co.in")
    parser.add_argument("--expect-dns", default="10.44.0.209")
    parser.add_argument("--http-url", default="http://wifi.bsnl.co.in/generate_204")
    parser.add_argument("--deny-probe", default="198.51.100.1", help="address that the pre-auth ACL must block")
    parser.add_argument("--portal-url", default="https://wifi.bsnl.co.in/portal/login/", help="expected RFC 8910 option 114 value")
    parser.add_argument("--dhcp-only", action="store_true", help="skip DNS/HTTP/deny checks")
    parser.add_argument("--keep-capture", action="store_true")
    args = parser.parse_args()
    if len(args.host_if.encode()) > 15:
        parser.error("--host-if must be at most 15 bytes")

    ns, host_if, client_if = args.namespace, args.host_if, "eth0"
    outer_if = f"{client_if}.{args.outer_vlan}"
    qinq_if = f"{outer_if}.{args.inner_vlan}"
    checks: dict[str, dict[str, object]] = {}
    report: dict[str, object] = {"namespace": ns, "checks": checks}

    cleanup(ns, host_if)  # remove leftovers from an interrupted earlier run
    work = Path(tempfile.mkdtemp(prefix="bsnl-vpp-qual-"))
    lease, pidfile, capture = work / "leases", work / "dhclient.pid", work / "dhcp.pcap"
    try:
        run("ip", "netns", "add", ns)
        run("ip", "link", "add", host_if, "type", "veth", "peer", "name", client_if, "netns", ns)
        run("ip", "link", "set", host_if, "master", args.bridge)
        run("ip", "link", "set", host_if, "mtu", "1600", "up")
        nsx = ("ip", "netns", "exec", ns)
        run(*nsx, "ip", "link", "set", "lo", "up")
        run(*nsx, "ip", "link", "set", client_if, "mtu", "1600", "up")
        run(*nsx, "ip", "link", "add", "link", client_if, "name", outer_if, "type", "vlan", "id", str(args.outer_vlan), "protocol", "802.1Q")
        run(*nsx, "ip", "link", "set", outer_if, "mtu", "1550", "up")
        run(*nsx, "ip", "link", "add", "link", outer_if, "name", qinq_if, "type", "vlan", "id", str(args.inner_vlan), "protocol", "802.1Q")
        run(*nsx, "ip", "link", "set", qinq_if, "mtu", "1500", "up")

        tcpdump = subprocess.Popen(["tcpdump", "-ni", host_if, "-c", "8", "-w", str(capture), "udp port 67 or udp port 68"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        started = time.monotonic()
        try:
            dhcp = try_run(*nsx, "dhclient", "-v", "-1", "-pf", str(pidfile), "-lf", str(lease), qinq_if, timeout=args.dhcp_timeout + 5)
        finally:
            tcpdump.send_signal(signal.SIGINT)
            try:
                tcpdump.wait(timeout=5)
            except subprocess.TimeoutExpired:
                tcpdump.kill()
        addresses = json.loads(try_run(*nsx, "ip", "-4", "-json", "addr", "show", "dev", qinq_if).stdout or "[]")
        leased = [a["local"] for item in addresses for a in item.get("addr_info", []) if a.get("family") == "inet"]
        capture_text = try_run("tcpdump", "-nn", "-vv", "-r", str(capture)).stdout if capture.exists() else ""
        checks["dhcp_lease"] = {"ok": dhcp.returncode == 0 and bool(leased), "addresses": leased, "seconds": round(time.monotonic() - started, 2)}
        # tcpdump -vv prints option 114's value; the portal URL is the evidence.
        checks["dhcp_option_114"] = {"ok": args.portal_url in capture_text, "expected": args.portal_url}
        report["dhcp_log"] = dhcp.stderr[-2000:]

        if leased and not args.dhcp_only:
            dns = try_run(*nsx, "dig", "+short", "+time=3", "+tries=2", f"@{args.dns_server}", args.dns_name)
            answers = dns.stdout.split()
            checks["dns"] = {"ok": args.expect_dns in answers, "answers": answers}
            http = try_run(*nsx, "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "10", "--resolve", f"{args.dns_name}:80:{args.expect_dns}", args.http_url)
            checks["portal_http"] = {"ok": http.stdout.strip() in {"200", "204", "302"}, "status": http.stdout.strip() or http.stderr.strip()}
            probe = try_run(*nsx, "ping", "-c", "3", "-W", "1", args.deny_probe)
            checks["preauth_deny"] = {"ok": probe.returncode != 0, "probe": args.deny_probe}
    finally:
        cleanup(ns, host_if)
        if not args.keep_capture:
            for item in work.iterdir():
                item.unlink()
            work.rmdir()
        else:
            report["work_dir"] = str(work)

    report["ok"] = bool(checks) and all(item["ok"] for item in checks.values())
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
