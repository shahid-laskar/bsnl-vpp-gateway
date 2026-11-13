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
| `bsnl-vpp-portal-path` | Lab nftables forward/SNAT to the portal (ADR-012) |
| `isc-kea-dhcp4-server`, `dnsmasq` | DHCP and captive DNS on `br-wan` |
| `bsnl-vpp-controller` | API on 10.44.0.207:8787 (mTLS + HMAC), store `/var/lib/bsnl-vpp-gateway/controller.sqlite3`; secrets in `/etc/bsnl-vpp-gateway/controller.env` |

The old vppctl oneshot units are in `deployment/legacy/` and must not be
installed.

## Install or repair the host

```bash
cd /opt/bsnl-vpp-gateway
sudo sh deployment/bin/bsnl-vpp-lab-install     # backs up, cleans test leftovers, installs, restarts, checks
sudo bsnl-vpp-lab-check                         # read-only health check (--wait 30 to poll)
sudo sh tests/lab/test_restart_recovery.sh 5    # restart VPP 5x; fixture + subscriber checks each time
```

## Controller modes

| Mode | Flags | Effect |
|---|---|---|
| Dry-run | (none) | validates and plans; no VPP access |
| Observe | `--observe-vpp --port-map access0=host-vpp-access` | connects read-only, checks API CRCs, reports observed state |
| Enforce | add `--enable-vpp-writes` | owns tenant sub-interfaces and the tenant ACL; refuses to start on CRC mismatch |

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
sudo python3 -m controller.bypass_suite --phase authorized --static-ip 10.9.101.50   # after activating .50
```

Authenticated lab subscribers can reach only `192.0.2.0/24` (VPP's own fixture
address). Do not widen `authenticated_destinations` before NAT and IPDR (P7).

## Useful read-only commands

```bash
systemctl is-active vpp bsnl-vpp-lab-links bsnl-vpp-portal-path isc-kea-dhcp4-server dnsmasq bsnl-vpp-controller
sudo vppctl show interface address
sudo vppctl show acl-plugin acl
sudo vppctl show acl-plugin interface
sudo vppctl show ip fib 10.44.0.0/22
sudo kea-dhcp4 -t /etc/kea/kea-dhcp4.conf && sudo dnsmasq --test
sudo nft list table ip bsnl_vpp_portal
journalctl -u bsnl-vpp-controller -n 50
```

## Hardware transition

When physical NICs arrive: inventory PCI/NUMA/firmware, enable IOMMU, qualify
the driver, create a separate versioned DPDK profile and re-test the 0x88a8
TPID (ADR-004). Do not modify the VM profile in place or claim throughput from
it.
