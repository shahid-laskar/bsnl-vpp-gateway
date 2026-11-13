# BSNL VPP Gateway

Lab implementation for `docs/vpp/FINAL_IMPLEMENTATION_PLAN.md`, deployed on
an Ubuntu VM with three hypervisor-backed Linux bridge attachments.

| Role | Guest interface | Ownership |
|---|---|---|
| Management | `ens18` | Linux / SSH / controller |
| Subscriber access | `ens19` | Linux bridge attachment, VPP `af_packet` |
| Upstream/WAN | `ens20` | Linux bridge attachment, VPP `af_packet` |

The management interface is never listed in a VPP DPDK device stanza. Physical
NIC binding, IOMMU/VFIO, hugepages, CPU isolation, RSS, and production DPDK
tuning are deferred until hardwired NICs are integrated.

The completed lab gates include persistent af_packet attachment, L3
forwarding, exact-match QinQ, DHCP relay to Kea, RFC 8910 DHCP option 114,
and a Linux resolver fixture on `br-wan`, plus a lab pre-auth ACL. The existing
HTTP/HTTPS captive portal is integrated; subscriber enforcement and the
controller/Django session workflow are not implemented yet.

For the complete implementation record, configuration inventory, validation
evidence, and production transition gates, see
[`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md).

Operational procedures are in [`docs/LAB_RUNBOOK.md`](docs/LAB_RUNBOOK.md).
