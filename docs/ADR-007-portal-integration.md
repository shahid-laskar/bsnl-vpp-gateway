# ADR-007: Reuse the existing captive portal

## Status

Lab-qualified. The VPP gateway reuses the existing development portal at
`10.44.0.209`; no second portal service is deployed on the VPP VM.

## Existing portal endpoint

- HTTP portal host: `wifi.bsnl.co.in` at `10.44.0.209:80`.
- HTTPS portal host: `wifi.bsnl.co.in` at `10.44.0.209:443`.
- Portal route tested: `/portal/login/`.
- HTTP captive detection endpoint tested: `/generate_204`.

The HTTP endpoint returned `200`, and the HTTPS portal returned `200` when
requested with the correct `wifi.bsnl.co.in` host and certificate name.

## VPP lab path

The router-coded subscriber range is `10.9.101.0/24`, with gateway
`10.9.101.1`. VPP routes the management prefix `10.44.0.0/22` through the
Linux WAN-side address `198.51.100.2`.

The VPP VM enables IPv4 forwarding and applies narrowly scoped lab NAT:

```text
10.9.101.0/24 -> 10.44.0.0/22 via ens18
SNAT source -> 10.44.0.207
```

SNAT is used so the existing portal host does not require a route back to the
temporary VPP subscriber range.

## DNS and DHCP signalling

dnsmasq maps `wifi.bsnl.co.in` and the configured captive-check hostnames to
`10.44.0.209`. Kea advertises:

```text
https://wifi.bsnl.co.in/portal/login/
```

through DHCPv4 option 114. The resolver remains a lab fixture; it is not yet a
complete authenticated/unauthenticated split-horizon policy.

## Validation

From a double-tagged QinQ namespace on `host-vpp-access.101`:

- `10.44.0.209` responded to ICMP with 0% loss.
- HTTP `wifi.bsnl.co.in/generate_204` returned `200`.
- HTTPS `wifi.bsnl.co.in/portal/login/` returned `200`.
- DNS returned `wifi.bsnl.co.in A 10.44.0.209`.

## Deferred

VPP captive redirection/enforcement, authenticated subscriber policy, portal
session callbacks to the VPP controller, and production firewall policy remain
open work. The current NAT path is lab-only.

## Portal-to-controller event contract (v1)

Source of truth: `config/schema/api-v1.schema.json` (request/response JSON
Schema) and `controller/contract.py` (session-key rule and HMAC canonical
form). Golden vectors in `config/contract/golden/` are copied byte-for-byte
into the portal repo (`apps/network_control/tests/vpp_contract_golden/`); both
test suites check against them.

Endpoints: `POST /v1/subscribers/activate` and `POST /v1/subscribers/deactivate`.

- Activate body: `{operation_id, subscriber: {session_key, tenant_key,
  subscriber_id, session_id, private_ipv4, mac, valid_until}}`. Unknown fields
  are rejected. `valid_until` must carry a UTC offset.
- Deactivate body: `{operation_id, session_key, reason}`.
- `session_key` must equal `tenant_key + "/" + private_ipv4` (FINAL plan 5.3),
  and the address must be a usable host in the tenant's `gateway_ip` subnet.
- Every response carries `contract_version: "v1"` and `dataplane_enforced`.
  The portal marks a session `fully_active` only when `dataplane_enforced` is
  true; while the VPP adapter is dry-run it is always false.

Authentication is layered; HMAC is added on top, never instead:

1. Transport: mTLS with a CA-signed client certificate. When
   `BSNL_VPP_ALLOWED_CLIENTS` (comma-separated CN/SAN names) is set, the
   certificate must match it. A bearer token (`BSNL_VPP_CONTROLLER_TOKEN`) is
   accepted only on non-TLS listeners (tests, local tooling).
2. Request integrity, when `BSNL_VPP_PORTAL_HMAC_SECRET` is set (required
   before connecting the portal). Headers: `X-BSNL-Timestamp` (Unix seconds,
   within 300 s), `X-BSNL-Nonce` (32-64 lowercase hex, fresh per request),
   `X-BSNL-Signature` = `sha256=` + hex HMAC-SHA256 over the lines
   `v1`, timestamp, nonce, method, path, Idempotency-Key, and the hex SHA-256 of
   the exact body, joined with `\n` (newline). Nonces are remembered for 600 s, so a
   captured request cannot be replayed, re-targeted or re-keyed. A retry
   carries a fresh nonce and is de-duplicated by its Idempotency-Key.

`GET /v1/capabilities` and `GET /v1/observed-state` require transport
authentication; only `GET /health` is anonymous.

Secrets live in `/etc/bsnl-vpp-gateway/controller.env` (root-owned, 0640),
never in source, documentation or audit events. The portal side reads
`VPP_CONTROLLER_*` settings from its environment and refuses to call the
controller without the HMAC secret.
