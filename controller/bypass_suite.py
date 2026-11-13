"""Captive-policy bypass suite for the VM lab (FINAL plan 8.2; run as root).

    sudo python3 -m controller.bypass_suite                      # pre-auth phase
    sudo python3 -m controller.bypass_suite --phase authorized \\
         --static-ip 10.9.101.50                                 # after activating 10.9.101.50

Creates a throw-away QinQ subscriber namespace behind br-access and probes
what the tenant ACL must block or allow. "Blocked" is evidenced by a timeout
(the ACL drops silently); "reachable" by an ICMP echo reply or a TCP RST
(connection refused), which proves packets got through the ACL.

Exit status 0 only when every expectation holds.
"""
from __future__ import annotations

import argparse
import json
import subprocess

from .dhcp_qualification import cleanup, setup_namespace, try_run

TIMEOUT, REFUSED = 28, 7  # curl exit codes


def tcp(nsx, address, port):
    result = try_run(*nsx, "curl", "-sS", "-o", "/dev/null", "--max-time", "3", f"http://{address}:{port}/", timeout=10)
    return {28: "timeout", 7: "refused", 0: "open"}.get(result.returncode, f"curl-{result.returncode}")


def ping(nsx, address, source=None):
    args = ["ping", "-c", "2", "-W", "1"] + (["-I", source] if source else []) + [address]
    return try_run(*nsx, *args, timeout=10).returncode == 0


def dns(nsx, server, name="wifi.bsnl.co.in"):
    return try_run(*nsx, "dig", "+short", "+time=2", "+tries=1", f"@{server}", name, timeout=10).returncode == 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--phase", choices=("preauth", "authorized"), default="preauth")
    parser.add_argument("--static-ip", help="use this address instead of DHCP (must be the activated subscriber in --phase authorized)")
    parser.add_argument("--gateway", default="10.9.101.1")
    parser.add_argument("--prefix-len", type=int, default=24)
    parser.add_argument("--portal", default="10.44.0.209")
    parser.add_argument("--resolver", default="198.51.100.2")
    parser.add_argument("--authorized-target", default="192.0.2.1", help="lab authenticated_destinations target")
    parser.add_argument("--management-probe", default="10.44.1.234")
    parser.add_argument("--namespace", default="bsnl-bypass")
    parser.add_argument("--host-if", default="bsnlb-host0")
    parser.add_argument("--outer-vlan", type=int, default=200)
    parser.add_argument("--inner-vlan", type=int, default=101)
    args = parser.parse_args()

    ns, host_if = args.namespace, args.host_if
    qinq_if = f"eth0.{args.outer_vlan}.{args.inner_vlan}"
    checks: dict[str, dict] = {}

    def expect(name, ok, **detail):
        checks[name] = {"ok": bool(ok), **detail}

    cleanup(ns, host_if)
    try:
        nsx = setup_namespace(ns, host_if, "br-access", args.outer_vlan, args.inner_vlan)
        if args.static_ip:
            try_run(*nsx, "ip", "addr", "add", f"{args.static_ip}/{args.prefix_len}", "dev", qinq_if)
            try_run(*nsx, "ip", "route", "add", "default", "via", args.gateway)
        else:
            try_run(*nsx, "dhclient", "-1", "-pf", f"/run/{ns}.pid", "-lf", f"/run/{ns}.leases", qinq_if, timeout=40)
        address = try_run(*nsx, "ip", "-4", "-o", "addr", "show", "dev", qinq_if).stdout.split()
        expect("address_configured", any("/" in a and a.startswith("10.") for a in address), interface=" ".join(address[3:4]))

        # Allowed in every phase (pre-auth essentials)
        expect("dns_gateway_resolver", dns(nsx, args.resolver))
        expect("portal_https_reachable", tcp(nsx, args.portal, 443) in {"open", "refused"}, result=tcp(nsx, args.portal, 443))

        # Blocked in every phase (protected or never-allowed)
        expect("management_lan_blocked", not ping(nsx, args.management_probe))
        result = tcp(nsx, args.resolver, 22)
        expect("gateway_host_ssh_blocked", result == "timeout", result=result)
        expect("foreign_resolver_blocked", not dns(nsx, args.authorized_target))
        result = tcp(nsx, args.authorized_target, 853)
        authorized = args.phase == "authorized"
        # In the authorized phase the lab target is permitted, so TCP is refused
        # by VPP (no listener) rather than timing out.
        expect("dot_853_to_target", result == ("refused" if authorized else "timeout"), result=result)
        expect("authorized_target_icmp", ping(nsx, args.authorized_target) == authorized, expected_reachable=authorized)

        # Spoofed source outside the tenant subnet is never forwarded
        try_run(*nsx, "ip", "addr", "add", "10.9.250.5/32", "dev", qinq_if)
        expect("spoofed_source_blocked", not ping(nsx, args.portal, source="10.9.250.5"))

        # IPv6: no router advertisement, no global address, no reply to all-nodes
        try_run(*nsx, "sysctl", "-qw", f"net.ipv6.conf.{qinq_if.replace('.', '/')}.disable_ipv6=0")
        try_run(*nsx, "sleep", "4", timeout=10)
        routes6 = try_run(*nsx, "ip", "-6", "route", "show", "default").stdout.strip()
        expect("ipv6_no_default_route", routes6 == "", routes=routes6)
        # The namespace answers its own all-nodes ping; any *other* responder
        # (VPP with IPv6 enabled) would appear in the IPv6 neighbour table.
        try_run(*nsx, "ping", "-6", "-c", "2", "-W", "1", f"ff02::1%{qinq_if}", timeout=10)
        neighbours6 = try_run(*nsx, "ip", "-6", "neigh", "show", "dev", qinq_if).stdout.strip()
        expect("ipv6_gateway_silent", neighbours6 == "", neighbours=neighbours6)
    except subprocess.CalledProcessError as exc:
        expect("harness", False, error=f"{exc.cmd}: {exc.stderr}")
    finally:
        cleanup(ns, host_if)

    report = {"phase": args.phase, "checks": checks, "ok": all(c["ok"] for c in checks.values())}
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
