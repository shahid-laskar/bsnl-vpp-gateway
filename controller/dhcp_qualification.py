from __future__ import annotations

import argparse
import json
from pathlib import Path
import signal
import subprocess
import tempfile


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=True, text=True, capture_output=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a temporary QinQ DHCP qualification")
    parser.add_argument("--namespace", default="phase5-qinq-client")
    parser.add_argument("--outer-vlan", type=int, default=200)
    parser.add_argument("--inner-vlan", type=int, default=101)
    args = parser.parse_args()
    ns = args.namespace
    # Linux interface names are limited to 15 bytes.
    host_if = "p5q-host0"
    client_if = "eth0"
    outer_if = f"{client_if}.{args.outer_vlan}"
    qinq_if = f"{outer_if}.{args.inner_vlan}"
    with tempfile.TemporaryDirectory(prefix="bsnl-vpp-dhcp-") as work:
        lease = Path(work) / "leases"
        capture = Path(work) / "dhcp.pcap"
        try:
            run("ip", "netns", "add", ns)
            run("ip", "link", "add", host_if, "type", "veth", "peer", "name", client_if, "netns", ns)
            run("ip", "link", "set", host_if, "master", "br-access")
            run("ip", "link", "set", host_if, "mtu", "1600", "up")
            run("ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up")
            run("ip", "netns", "exec", ns, "ip", "link", "set", client_if, "mtu", "1600", "up")
            run("ip", "netns", "exec", ns, "ip", "link", "add", "link", client_if, "name", outer_if, "type", "vlan", "id", str(args.outer_vlan), "protocol", "802.1Q")
            run("ip", "netns", "exec", ns, "ip", "link", "set", outer_if, "mtu", "1550", "up")
            run("ip", "netns", "exec", ns, "ip", "link", "add", "link", outer_if, "name", qinq_if, "type", "vlan", "id", str(args.inner_vlan), "protocol", "802.1Q")
            run("ip", "netns", "exec", ns, "ip", "link", "set", qinq_if, "mtu", "1500", "up")
            capture_handle = subprocess.Popen(["tcpdump", "-ni", "br-access", "-c", "8", "-w", str(capture), "udp port 67 or udp port 68"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                dhcp = run("ip", "netns", "exec", ns, "dhclient", "-v", "-1", "-lf", str(lease), qinq_if)
            finally:
                capture_handle.send_signal(signal.SIGINT)
                capture_handle.wait(timeout=5)
            address = run("ip", "netns", "exec", ns, "ip", "-4", "-json", "addr", "show", "dev", qinq_if).stdout
            routes = run("ip", "netns", "exec", ns, "ip", "-4", "-json", "route").stdout
            capture_text = run("tcpdump", "-nn", "-vv", "-r", str(capture)).stdout
            lease_text = lease.read_text() if lease.exists() else ""
            print(json.dumps({"dhclient": dhcp.stdout, "addresses": json.loads(address), "routes": json.loads(routes), "dhcp_capture": capture_text, "lease_data": lease_text, "capture": str(capture), "lease_file": str(lease)}, indent=2))
        finally:
            subprocess.run(["ip", "netns", "del", ns], check=False, capture_output=True, text=True)
            subprocess.run(["ip", "link", "del", host_if], check=False, capture_output=True, text=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
