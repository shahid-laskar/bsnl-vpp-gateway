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
import re
import subprocess

from .dhcp_qualification import cleanup, lab_mac_mode, setup_namespace, try_run, wait_forwarded

TIMEOUT, REFUSED = 28, 7  # curl exit codes


def tcp(nsx, address, port):
    result = try_run(*nsx, "curl", "-sS", "-o", "/dev/null", "--max-time", "3", f"http://{address}:{port}/", timeout=10)
    return {28: "timeout", 7: "refused", 0: "open"}.get(result.returncode, f"curl-{result.returncode}")


def http_redirect(nsx, address):
    """(curl status, Location) of a plain HTTP GET; status "302" when the redirector answered."""
    result = try_run(*nsx, "curl", "-sS", "-o", "/dev/null", "--max-time", "4", "-w", "%{http_code} %{redirect_url}",
                     f"http://{address}/", timeout=10)
    if result.returncode:
        return {28: "timeout", 7: "refused"}.get(result.returncode, f"curl-{result.returncode}"), ""
    code, _, location = result.stdout.strip().partition(" ")
    return code, location


def ping(nsx, address, source=None):
    args = ["ping", "-c", "2", "-W", "1"] + (["-I", source] if source else []) + [address]
    return try_run(*nsx, *args, timeout=10).returncode == 0


def dns(nsx, server, name="wifi.bsnl.co.in"):
    return try_run(*nsx, "dig", "+short", "+time=2", "+tries=1", f"@{server}", name, timeout=10).returncode == 0


def lookup(nsx, server, name):
    """(rcode, [A records]) from the subscriber's point of view."""
    out = try_run(*nsx, "dig", "+time=2", "+tries=1", "+noall", "+comments", "+answer", f"@{server}", name, "A", timeout=10).stdout
    return parse_dig(out)


def parse_dig(out):
    """Header status (TIMEOUT if none) and A records of ``dig +comments +answer``."""
    match = re.search(r"status: ([A-Z]+)", out)
    answers = []
    for line in out.splitlines():
        fields = line.split()  # NAME TTL CLASS TYPE RDATA
        if len(fields) == 5 and not line.startswith(";") and fields[3] == "A":
            answers.append(fields[4])
    return (match.group(1) if match else "TIMEOUT"), answers


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--phase", choices=("preauth", "authorized"), default="preauth")
    parser.add_argument("--static-ip", help="use this address instead of DHCP (log_only tenants only: with MAC "
                        "enforcement an address without a lease is dropped). Default: DHCP, and in --phase authorized "
                        "the leased address is activated through the controller and deactivated at the end")
    parser.add_argument("--mac-enforcement", choices=("auto", "enforce", "log_only"), default="auto",
                        help="expected tenant mode (auto: config/lab/desired-state.json)")
    parser.add_argument("--unbound-probe-ip", default="10.9.101.250", help="in-subnet address outside the DHCP pool")
    parser.add_argument("--gateway", default="10.9.101.1")
    parser.add_argument("--prefix-len", type=int, default=24)
    parser.add_argument("--portal", default="10.44.0.209")
    parser.add_argument("--resolver", default="198.51.100.2")
    parser.add_argument("--portal-name", default="wifi.bsnl.co.in")
    parser.add_argument("--captive-check-name", default="captive.apple.com")
    parser.add_argument("--other-name", default="example.com")
    parser.add_argument("--authorized-target", default="192.0.2.1", help="lab authenticated_destinations target")
    parser.add_argument("--management-probe", default="10.44.1.234")
    parser.add_argument("--http-probe", default="203.0.113.10", help="arbitrary HTTP destination (TEST-NET-3)")
    parser.add_argument("--portal-login-url", default="https://wifi.bsnl.co.in/portal/login/")
    parser.add_argument("--namespace", default="bsnl-bypass")
    parser.add_argument("--host-if", default="bsnlb-host0")
    parser.add_argument("--outer-vlan", type=int, default=200)
    parser.add_argument("--inner-vlan", type=int, default=101)
    args = parser.parse_args()

    ns, host_if = args.namespace, args.host_if
    qinq_if = f"eth0.{args.outer_vlan}.{args.inner_vlan}"
    checks: dict[str, dict] = {}
    mac_mode = lab_mac_mode(args.outer_vlan, args.inner_vlan) if args.mac_enforcement == "auto" else args.mac_enforcement
    activated_ip = None

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
        leased = next((a.split("/")[0] for a in address if "/" in a and a.startswith("10.")), None)
        # Lease -> first forwarded packet (MAC enforcement programs VPP from the binding).
        first_packet = wait_forwarded(nsx, args.portal, 10)
        expect("forwarded_after_address", first_packet is not None, seconds=first_packet)
        if args.phase == "authorized" and not args.static_ip and leased:
            from tests.lab.controller_client import activate
            reply = activate(leased, minutes=10)
            activated_ip = leased
            expect("activation_enforced", reply.get("dataplane_enforced") is True, address=leased)

        # Allowed in every phase (pre-auth essentials)
        expect("dns_gateway_resolver", dns(nsx, args.resolver))
        authorized = args.phase == "authorized"

        # Split DNS (P5-T5, ADR-014). The portal name always points at the
        # portal; captive-check names only before authentication; other names
        # are refused before authentication (no DNS tunnelling).
        status, answers = lookup(nsx, args.resolver, args.portal_name)
        expect("dns_portal_name", answers == [args.portal], status=status, answers=answers)
        status, answers = lookup(nsx, args.resolver, args.captive_check_name)
        expect("dns_captive_check_name", (args.portal not in answers and status == "NOERROR" and bool(answers)) if authorized else answers == [args.portal],
               status=status, answers=answers, expected="real address" if authorized else args.portal)
        status, answers = lookup(nsx, args.resolver, args.other_name)
        expect("dns_other_name", (status == "NOERROR" and bool(answers)) if authorized else status == "REFUSED",
               status=status, answers=answers, expected="resolved" if authorized else "REFUSED")
        expect("portal_https_reachable", tcp(nsx, args.portal, 443) in {"open", "refused"}, result=tcp(nsx, args.portal, 443))

        # HTTP redirect (Phase 6, ADR-015): plain HTTP to any host gets a 302 to
        # the portal, in both phases for destinations outside the subscriber's
        # authenticated_destinations; never for the management LAN.
        code, location = http_redirect(nsx, args.http_probe)
        expect("http_redirected_to_portal", code == "302" and location == args.portal_login_url, result=code, location=location)
        code, location = http_redirect(nsx, args.authorized_target)
        if authorized:
            # Not steered; VPP has no TCP stack, so the permitted SYN gets no answer.
            expect("http_authorized_target_not_redirected", code != "302", result=code)
        else:
            expect("http_authorized_target_redirected_preauth", code == "302" and location == args.portal_login_url, result=code)
        code, _ = http_redirect(nsx, args.management_probe)
        expect("http_management_lan_blocked", code == "timeout", result=code)

        # MAC/IP source enforcement (ADR-016): an in-subnet address without a
        # lease, and the leased address from another MAC, are dropped when the
        # tenant enforces; with log_only the ACL alone decides (portal ICMP ok).
        enforced = mac_mode == "enforce"
        try_run(*nsx, "ip", "addr", "add", f"{args.unbound_probe_ip}/32", "dev", qinq_if)
        reachable = ping(nsx, args.portal, source=args.unbound_probe_ip)
        expect("mac_unleased_source", reachable != enforced, mode=mac_mode, reachable=reachable)
        try_run(*nsx, "ip", "addr", "del", f"{args.unbound_probe_ip}/32", "dev", qinq_if)
        if leased and not args.static_ip:
            original = try_run(*nsx, "cat", f"/sys/class/net/{qinq_if}/address").stdout.strip()
            try_run(*nsx, "ip", "link", "set", "dev", qinq_if, "address", "02:5b:00:00:00:01")
            reachable = ping(nsx, args.portal)
            expect("mac_spoofed_for_leased_ip", reachable != enforced, mode=mac_mode, reachable=reachable)
            try_run(*nsx, "ip", "link", "set", "dev", qinq_if, "address", original)
            expect("mac_restored_forwarded", wait_forwarded(nsx, args.portal, 10) is not None)

        # Blocked in every phase (protected or never-allowed)
        expect("management_lan_blocked", not ping(nsx, args.management_probe))
        result = tcp(nsx, args.resolver, 22)
        expect("gateway_host_ssh_blocked", result == "timeout", result=result)
        expect("foreign_resolver_blocked", not dns(nsx, args.authorized_target))
        result = tcp(nsx, args.authorized_target, 853)
        if authorized:
            # Informational only: the ACL permits it (VPP trace 2026-11-16:
            # acl 1 rule 11 permit), but VPP runs no TCP stack (session layer
            # off), so TCP to its own address is punted and dropped without a
            # RST; a timeout cannot tell permit from deny here.
            # authorized_target_icmp is the authorized-path evidence.
            expect("dot_853_to_target", True, result=result, informational="VPP has no TCP stack; see authorized_target_icmp")
        else:
            expect("dot_853_to_target", result == "timeout", result=result)
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
        if activated_ip:
            try:
                from tests.lab.controller_client import deactivate
                deactivate(activated_ip)
            except Exception as exc:  # report, but always clean up the namespace
                expect("deactivation", False, error=f"{type(exc).__name__}: {exc}")
        cleanup(ns, host_if)

    report = {"phase": args.phase, "mac_enforcement": mac_mode, "checks": checks, "ok": all(c["ok"] for c in checks.values())}
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
