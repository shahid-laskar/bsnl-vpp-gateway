# ADR-014: Split-horizon DNS with Unbound views (P5-T5, D-19 lab)

## Status

Implemented and verified on the lab VM (2026-11-16,
`artifacts/test-reports/2026-11-16-p5-split-dns.txt`). Supersedes the
dnsmasq resolver of ADR-006 for the lab. D-19 (resolver choice) is
PROVISIONAL: throughput and scale are not measured.

## Context

P5-T5 requires DNS answers that depend on the client's authentication state.
Unauthenticated clients get captive answers for OS connectivity-check names
and must not reach other resolvers; authenticated clients get normal
recursion. dnsmasq answers every client the same way and recursed every name
for unauthenticated clients, which also allowed DNS tunnelling before login.

## Decision

- **Software:** Unbound 1.19.2 from the Ubuntu 24.04 archive (pinned with
  `apt-mark hold`, recorded in `versions.lock.yaml`), full recursion from the
  root servers, DNSSEC validation on (package default). Listens only on
  `198.51.100.2`; the host itself keeps systemd-resolved
  (`unbound-resolvconf.service` is masked).
- **Views:** every tenant subnet is mapped to view `captive`
  (`access-control-view`). In that view:
  - the portal name (host of `captive_api_url`) and `local_names` answer
    locally, and the OS captive-check names (`captive_hosts`) answer with the
    portal address, all with TTL `captive_ttl_seconds` (5 s) so stale captive
    answers expire quickly after login;
  - every other name is **REFUSED** (`preauth_dns_default: refuse`), which
    closes recursive-DNS tunnelling before authentication. Names in
    `preauth_resolve_domains` (empty in the lab: the portal pages load no
    third-party hosts) resolve normally.
- **Authenticated subscribers:** the controller writes
  `/etc/unbound/bsnl/authenticated.conf` with one
  `access-control-view: <ip>/32 authenticated` line per authenticated
  subscriber of an enabled tenant (longest prefix wins). The
  `authenticated` view has no overrides, so captive-check names resolve to
  their real addresses and the OS sees the portal as closed. The portal name
  still resolves to the portal for every client.
- **Updates:** Unbound 1.19 cannot change view membership at runtime, so the
  controller (`controller/dns_views.py`) rewrites the file atomically, runs
  `unbound-checkconf` (restoring the previous file and skipping the reload if
  it fails, because a bad config stops Unbound on reload) and then
  `unbound-control reload_keep_cache`. It does this after every activation or
  deactivation that changed state, and on every reconcile tick (expiry,
  retries after a failure). Unchanged content causes no reload.
- **Failure direction:** a failed sync leaves a new subscriber with captive
  answers (the portal keeps showing) or a logged-out one with recursion until
  the next tick. DNS is not the enforcement point; the VPP tenant ACL is.
- **Permissions:** `/etc/unbound/bsnl` is `bsnl-vpp:unbound 2755`, files
  `0644`. Unbound reads its config as root before dropping privileges and its
  AppArmor profile grants no `dac_override`, so a `0750`/`0640` layout makes
  Unbound fail to start (seen during the install). The path must stay under
  `/etc/unbound` (AppArmor allows reads only there). The controller unit gets
  `SupplementaryGroups=unbound` (control socket `/run/unbound.ctl` is
  `root:unbound 0660`) and `ReadWritePaths=/etc/unbound/bsnl`.
- **Config source:** `config/lab/host-services.json` (`resolver: unbound`);
  `controller.reconcile_host_services` renders
  `deployment/resolver/unbound-bsnl-vpp-lab.conf`; all names are validated so
  none can inject a directive.

## Verification (lab)

- Pre-auth client: portal name and `captive.apple.com` → `10.44.0.209`,
  `example.com` → REFUSED; bypass suite 14/14.
- After activation of `10.9.101.50`: `captive.apple.com` → Apple addresses,
  `example.com` resolves, portal name → portal. Activation API response
  including the Unbound reload: 57–59 ms.
- After deactivation the same address is back to captive answers/REFUSED.
- `bsnl-vpp-lab-check` HEALTHY with Unbound.

## Limits and follow-ups

- Reload per subscriber change: fine for the lab; at production churn
  (P6 acceptance: 50 activations/s) batch or debounce reloads, or move to a
  design that does not reload (for example two resolver addresses with
  `interface-view` and VPP steering of authenticated sources), measured under
  D-09/D-19.
- Authenticated lab subscribers have no internet path until P7, so their OS
  reports "no internet" rather than "captive" even though DNS is correct.
- DoH to public resolvers is blocked before login only by the VPP ACL (no IP
  path); after login it is out of scope until P6/P7 policy.

## Rollback

`sudo sh deployment/bin/bsnl-vpp-unbound-install --rollback` re-enables
dnsmasq (its config is untouched). Then reinstall the previous controller
unit without `--unbound-views-file`.
