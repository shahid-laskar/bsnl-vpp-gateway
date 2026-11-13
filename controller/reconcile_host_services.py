from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .config import load_json
from .host_services import ServiceReconciler, host_service_plans, render_dnsmasq_config, render_kea_config


def main() -> int:
    parser = argparse.ArgumentParser(description="Render or apply BSNL VPP host-service configuration")
    parser.add_argument("--desired-state", required=True)
    parser.add_argument("--services", required=True, help="JSON file containing relay_address, dns_address, portal_url, and lease_lifetime_seconds")
    parser.add_argument("--kea-target", default="/etc/kea/kea-dhcp4.conf")
    parser.add_argument("--dnsmasq-target", default="/etc/dnsmasq.d/bsnl-vpp-lab.conf")
    parser.add_argument("--backup-dir", default="/var/lib/bsnl-vpp-gateway/backups")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    desired: dict[str, Any] = load_json(args.desired_state)
    services: dict[str, Any] = load_json(args.services)
    plans = host_service_plans(desired, services)
    kea = render_kea_config(plans)
    dnsmasq = render_dnsmasq_config(plans, services.get("captive_hosts", ["portal.lab", "wifi.bsnl.co.in"]))
    if not args.apply:
        print(json.dumps({"mode": "dry-run", "kea_bytes": len(kea), "dnsmasq_bytes": len(dnsmasq), "tenants": len(plans)}, indent=2))
        return 0
    reconciler = ServiceReconciler(backup_dir=args.backup_dir)
    reconciler.apply_and_reload(args.kea_target, kea, ["kea-dhcp4", "-t"], ["systemctl", "reload", "isc-kea-dhcp4-server"])
    reconciler.apply_and_reload(args.dnsmasq_target, dnsmasq, ["dnsmasq", "--test", "--conf-file="], ["systemctl", "reload", "dnsmasq"])
    print(json.dumps({"mode": "applied", "tenants": len(plans)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
