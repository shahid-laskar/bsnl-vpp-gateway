from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .config import load_json
from .host_services import ServiceReconciler, host_service_plans, render_dnsmasq_config, render_kea_config, render_unbound_config


def main() -> int:
    parser = argparse.ArgumentParser(description="Render or apply BSNL VPP host-service configuration")
    parser.add_argument("--desired-state", required=True)
    parser.add_argument("--services", required=True, help="JSON file: relay_address, dns_address, portal_url, portal_address, captive_hosts, local_names, lease_lifetime_seconds")
    parser.add_argument("--kea-target", default="/etc/kea/kea-dhcp4.conf")
    parser.add_argument("--dnsmasq-target", default="/etc/dnsmasq.d/bsnl-vpp-lab.conf")
    parser.add_argument("--unbound-target", default="/etc/unbound/unbound.conf.d/bsnl-vpp-lab.conf")
    parser.add_argument("--backup-dir", default="/var/lib/bsnl-vpp-gateway/backups")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    desired: dict[str, Any] = load_json(args.desired_state)
    services: dict[str, Any] = load_json(args.services)
    plans = host_service_plans(desired, services)
    kea = render_kea_config(plans)
    resolver = services.get("resolver", "dnsmasq")
    if resolver not in {"dnsmasq", "unbound"}:
        raise SystemExit(f"services.resolver must be dnsmasq or unbound, got {resolver!r}")
    dns = render_unbound_config(plans, services) if resolver == "unbound" else render_dnsmasq_config(plans, services)
    if not args.apply:
        print(json.dumps({"mode": "dry-run", "kea_bytes": len(kea), "resolver": resolver, "resolver_bytes": len(dns), "tenants": len(plans)}, indent=2))
        return 0
    reconciler = ServiceReconciler(backup_dir=args.backup_dir)
    reconciler.apply_and_reload(args.kea_target, kea, ["kea-dhcp4", "-t"], ["systemctl", "reload", "isc-kea-dhcp4-server"])
    if resolver == "unbound":
        # The rendered file is a complete config on its own (it includes the
        # controller's per-subscriber file), so checking the candidate file
        # validates both. Restart: the listening interface may change.
        reconciler.apply_and_reload(args.unbound_target, dns, ["unbound-checkconf"], ["systemctl", "restart", "unbound"])
    else:
        reconciler.apply_and_reload(args.dnsmasq_target, dns, ["dnsmasq", "--test", "--conf-file="], ["systemctl", "reload", "dnsmasq"])
    print(json.dumps({"mode": "applied", "resolver": resolver, "tenants": len(plans)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
