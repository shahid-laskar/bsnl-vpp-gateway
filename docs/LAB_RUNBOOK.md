# Lab runbook

`ens18` is management-only. The VPP service override clears the package's
`uio_pci_generic` preload and the lab profile disables `dpdk_plugin.so`. Do not
bind VM NICs to `vfio-pci`.

```text
hypervisor bridge -> ens19 -> br-access -> access-vpp <-> vpp-access -> VPP host-vpp-access
hypervisor bridge -> ens20 -> br-wan    -> wan-vpp    <-> vpp-wan    -> VPP host-vpp-wan
hypervisor bridge -> ens18 -> management / SSH only
```

Tenant fixture: exact-match QinQ outer `0x8100`/200, inner `0x8100`/101,
`10.9.101.0/24`, gateway `10.9.101.1`, pool `10.9.101.5-105`, VRF 0 (ADR-011).

## What runs where

| Unit / file | Role |
|---|---|
| `bsnl-vpp-lab-links` | Linux bridges and veths; `vpp.service` requires it |
| `vpp` + `/etc/vpp/bsnl-lab.cli` | VPP applies af_packet, L3 fixture, QinQ, DHCP proxy and the static pre-auth ACL itself at every start (no vppctl race) |
| `bsnl-vpp-portal-path` | Lab nftables: forward to the portal (no SNAT to .209, ADR-012), pre-auth HTTP redirect to :8080 and drop of any other forwarded subscriber traffic (ADR-015) |
| `bsnl-vpp-redirector` | Captive HTTP redirector on 198.51.100.2:8080: 302 to the portal login for HTTP that VPP's ABF policy steers to the host (ADR-015) |
| `isc-kea-dhcp4-server` | DHCP on `br-wan` |
| `unbound` + `/etc/unbound/unbound.conf.d/bsnl-vpp-lab.conf` | Split-horizon DNS on 198.51.100.2 (ADR-014); per-subscriber views in `/etc/unbound/bsnl/authenticated.conf`, written by the controller. dnsmasq is disabled (rollback only) |
| `bsnl-vpp-controller` | API on 10.44.0.207:8787 (mTLS + HMAC), store `/var/lib/bsnl-vpp-gateway/controller.sqlite3`; secrets in `/etc/bsnl-vpp-gateway/controller.env`; reads Kea leases (`SupplementaryGroups=_kea`) into the `bindings` table every second (ADR-013) |

The old vppctl oneshot units are in `deployment/legacy/` and must not be
installed.

## Install or repair the host

```bash
cd /opt/bsnl-vpp-gateway
sudo sh deployment/bin/bsnl-vpp-lab-install     # backs up, cleans test leftovers, installs, restarts, checks
sudo bsnl-vpp-lab-check                         # read-only health check (--wait 30 to poll)
sudo sh tests/lab/test_restart_recovery.sh 5    # restart VPP 5x; fixture + subscriber checks each time
sudo python3 -m tests.lab.restart_policy_recovery --runs 5   # authenticated subscriber outage per VPP restart (writes on)
sudo sh deployment/bin/bsnl-vpp-unbound-install            # dnsmasq -> Unbound split DNS (done 2026-11-16)
sudo sh deployment/bin/bsnl-vpp-unbound-install --rollback # back to dnsmasq
```

## Controller modes

| Mode | Flags | Effect |
|---|---|---|
| Dry-run | (none) | validates and plans; no VPP access |
| Observe | `--observe-vpp --port-map access0=host-vpp-access` | connects read-only, checks API CRCs, reports observed state |
| Enforce (lab default since 2026-11-16) | add `--enable-vpp-writes` | owns tenant sub-interfaces, the tenant ACL and (with `http_redirect`) the ABF policy; refuses to start on CRC mismatch. Back out: remove the flag, reinstall the unit, restart the controller and then VPP (re-applies the static ACL) |

Check the live CRCs before enabling writes:

```bash
sudo -u bsnl-vpp python3 -m controller.main --observe-vpp --port-map access0=host-vpp-access \
  --desired-state config/lab/desired-state.json --store /tmp/obs.sqlite3 --audit /tmp/obs.jsonl
```

After a VPP upgrade, regenerate and review `artifacts/api-crc-<release>.json`
with `tools/api_crc_snapshot.py` before restarting the controller.

## Subscriber checks (root)

```bash
sudo python3 -m controller.dhcp_qualification          # lease, option 114, DNS, portal HTTP, deny probe
sudo python3 -m controller.bypass_suite                # pre-auth negatives (works with the static ACL too)
sudo python3 -m controller.bypass_suite --phase authorized   # leases, activates (signed) and deactivates its own address
# --static-ip only works for log_only tenants: with MAC enforcement (ADR-016) an address without a lease is dropped
sudo python3 -m tests.lab.portal_e2e --username vpplab1 --password-file FILE        # real portal login
```

Authenticated lab subscribers can reach only `192.0.2.0/24` (VPP's own fixture
address). Do not widen `authenticated_destinations` before NAT and IPDR (P7).

## Useful read-only commands

```bash
systemctl is-active vpp bsnl-vpp-lab-links bsnl-vpp-portal-path bsnl-vpp-redirector isc-kea-dhcp4-server unbound bsnl-vpp-controller
sudo vppctl show abf policy; sudo vppctl show abf attach host-vpp-access.101
sudo vppctl show inacl type ip4; sudo vppctl show classify tables   # MAC/IP chain (ADR-016)
sudo vppctl show interface address
sudo vppctl show acl-plugin acl
sudo vppctl show acl-plugin interface
sudo vppctl show ip fib 10.44.0.0/22
sudo kea-dhcp4 -t /etc/kea/kea-dhcp4.conf && sudo unbound-checkconf
cat /etc/unbound/bsnl/authenticated.conf          # authenticated /32s (controller-generated)
sudo unbound-control list_local_zones | head      # global zones; view_list_local_zones captive
sudo nft list table ip bsnl_vpp_portal
journalctl -u bsnl-vpp-controller -n 50
sudo sqlite3 /var/lib/bsnl-vpp-gateway/controller.sqlite3 "SELECT private_ipv4, mac, datetime(valid_from,'unixepoch'), datetime(valid_to,'unixepoch'), close_reason FROM bindings ORDER BY id DESC LIMIT 20"
```

## Hardware transition

When physical NICs arrive: inventory PCI/NUMA/firmware, enable IOMMU, qualify
the driver, create a separate versioned DPDK profile and re-test the 0x88a8
TPID (ADR-004). Do not modify the VM profile in place or claim throughput from
it.
