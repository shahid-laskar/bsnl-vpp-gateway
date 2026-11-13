#!/bin/sh
# Lab acceptance test for plan Step 1 / FINAL plan P2-T7: after a VPP restart
# the dataplane fixture must be back within 30 s and a QinQ subscriber must get
# DHCP (with option 114), DNS, portal HTTP, and be denied elsewhere.
# Run as root on the lab VM:  sh tests/lab/test_restart_recovery.sh [runs]
set -eu
runs="${1:-5}"
repo="$(cd "$(dirname "$0")/../.." && pwd)"
i=1
while [ "$i" -le "$runs" ]; do
  echo "=== run $i/$runs: restarting vpp"
  start=$(date +%s)
  systemctl restart vpp
  "$repo/deployment/bin/bsnl-vpp-lab-check" --wait 30
  echo "fixture healthy after $(( $(date +%s) - start )) s"
  (cd "$repo" && python3 -m controller.dhcp_qualification)
  i=$((i + 1))
done
echo "PASS: $runs restart cycles"
