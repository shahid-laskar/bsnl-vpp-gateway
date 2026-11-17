#!/bin/sh
# Start/stop the D-09 bench VPP and its probe namespace (root). Lab VPP is untouched.
set -eu
case "${1:-}" in
  start)
    ip link add bvpp0 type veth peer name bvpp1
    ip link set bvpp0 up
    ip netns add bsnl-bench
    ip link set bvpp1 netns bsnl-bench
    nsx="ip netns exec bsnl-bench"
    $nsx ip link set lo up
    $nsx ip link set bvpp1 mtu 1600 up
    $nsx ip link add link bvpp1 name bvpp1.200 type vlan id 200 protocol 802.1Q
    $nsx ip link set bvpp1.200 mtu 1550 up
    $nsx ip link add link bvpp1.200 name bvpp1.200.101 type vlan id 101 protocol 802.1Q
    $nsx ip link set bvpp1.200.101 up
    $nsx ip addr add 10.9.101.7/16 dev bvpp1.200.101
    $nsx ip route add 192.0.2.0/24 via 10.9.0.1
    install -d -m 0755 /run/vpp-bench
    d=$(cd "$(dirname "$0")" && pwd)
    sed "s#/opt/bsnl-vpp-gateway/tools/d09/setup.cli#$d/setup.cli#" "$d/startup.conf" > /run/vpp-bench/startup.conf
    systemd-run --unit=bsnl-vpp-bench --collect /usr/bin/vpp -c /run/vpp-bench/startup.conf
    for i in $(seq 1 30); do [ -S /run/vpp-bench/api.sock ] && break; sleep 0.5; done
    sleep 1
    vppctl -s /run/vpp-bench/cli.sock show interface address
    ;;
  stop)
    systemctl stop bsnl-vpp-bench 2>/dev/null || true
    ip netns del bsnl-bench 2>/dev/null || true
    ip link del bvpp0 2>/dev/null || true
    rm -rf /run/vpp-bench
    ;;
  *) echo "usage: $0 start|stop" >&2; exit 2 ;;
esac
