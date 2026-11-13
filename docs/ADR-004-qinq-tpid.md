# ADR-004: QinQ TPID qualification in the VM lab

## Status

Open research item R-04. The active lab fixture uses `0x8100` outer and inner
tags because this is the form that forwards on VPP 26.10 `af_packet` in the
Ubuntu VM.

## Evidence

- Linux capture showed the requested `0x88a8/200` outer tag followed by
  `0x8100/101` inner tag.
- A VPP `dot1ad 200 inner-dot1q 101 exact-match` subinterface did not receive
  those packets; VPP counted them as `ethernet-input: unknown vlan`.
- A `dot1q 200 inner-dot1q 101 exact-match` subinterface forwarded
  `0x8100/200` + `0x8100/101` traffic with 0% loss after ARP warm-up.
- `dot1q` did not accept the captured `0x88a8` outer-tag traffic either.

## Consequence

The lab does not claim `0x88a8` support. Re-test R-04 with the hardwire NIC,
native VPP driver/DPDK path, VLAN offload disabled and enabled, and packet
captures at the physical ingress before selecting the production TPID.
