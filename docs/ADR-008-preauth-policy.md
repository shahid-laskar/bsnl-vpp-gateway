# ADR-008: Lab pre-authentication policy

## Status

Superseded in part by ADR-010 (controller-owned tenant ACL). The static ACL
below is now the fail-closed boot default, applied by VPP itself from
`deployment/vpp/bsnl-lab.cli` (ACL index 0); the `bsnl-vpp-preauth` unit was
retired in remediation step 1.

Originally: lab-qualified for one QinQ tenant. This is an allowlist boundary for the
development path, not the final subscriber authorization implementation.

## Policy

The VPP ACL plugin is attached inbound to `host-vpp-access.101`. The ACL
permits only:

- DHCP client traffic to the relay (`UDP 68 -> 67`, broadcast destination).
- DNS to `198.51.100.2` over UDP and TCP port 53.
- HTTP and HTTPS to the existing portal `10.44.0.209`.
- ICMP to the existing portal `10.44.0.209` for lab diagnostics.

Unmatched subscriber traffic is denied by the ACL's implicit default deny. A
probe to the unapproved VPP WAN-side gateway `198.51.100.1` was rejected while
portal and DNS probes succeeded.

## Persistence

The policy is applied by:

```text
bsnl-vpp-preauth.service
/usr/local/sbin/bsnl-vpp-preauth
```

The service recreates ACL index 1 and attaches it after the QinQ service is
available. It is intentionally scoped to the lab interface and tenant.

## Deferred

Authenticated subscriber allowlisting, per-subscriber MAC/IP binding,
session-driven ACL updates, HTTP redirect behaviour, IPv6 blocking, QUIC/DoH
policy, and controller/Django API integration remain open. The ACL must not be
treated as production policy until those gates and negative tests are complete.
