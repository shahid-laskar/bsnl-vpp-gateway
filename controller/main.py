from __future__ import annotations

import argparse
import json
import logging

from .api import serve
from .config import load_json
from .keys import desired_object_keys
from .reconcile import LabAdapter, ReconcileResult, Reconciler, reconcile
from .state import merge_topology
from .store import DesiredStateStore
from .subscribers import SubscriberLifecycle

LOG = logging.getLogger("bsnl_vpp.main")


def parse_port_map(items: list[str]) -> dict[str, str]:
    mapping = {}
    for item in items:
        logical, _, vpp_name = item.partition("=")
        if not logical or not vpp_name:
            raise SystemExit(f"--port-map must be LOGICAL=VPP_INTERFACE, got {item!r}")
        mapping[logical] = vpp_name
    return mapping


def build_adapter(args: argparse.Namespace):
    if not (args.observe_vpp or args.enable_vpp_writes):
        return LabAdapter()
    from .vpp_adapter import CrcMismatchError, VppApiAdapter
    adapter = VppApiAdapter(args.vpp_socket, snapshot_path=args.api_crc_snapshot, enable_writes=args.enable_vpp_writes, port_map=parse_port_map(args.port_map),
                            settle_seconds=args.vpp_startup_settle_seconds)
    try:
        adapter.connect()
    except CrcMismatchError:
        if args.enable_vpp_writes:
            raise SystemExit("refusing to start with VPP writes enabled: API CRC mismatch (see log)")
    return adapter


def main() -> int:
    parser = argparse.ArgumentParser(description="BSNL VPP gateway controller")
    parser.add_argument("--desired-state", default="config/lab/desired-state.json", help="topology file (tenants, pools, policies)")
    parser.add_argument("--store", default="var/controller.sqlite3")
    parser.add_argument("--audit", default="var/audit.jsonl", help="JSONL mirror of the SQLite audit table")
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787, help="API listen port")
    parser.add_argument("--port-map", action="append", default=[], metavar="LOGICAL=VPP_IF", help="ingress port map, e.g. access0=host-vpp-access")
    parser.add_argument("--tls-cert")
    parser.add_argument("--tls-key")
    parser.add_argument("--tls-ca")
    parser.add_argument("--observe-vpp", action="store_true", help="connect to VPP read-only (CRC-checked) for observed state")
    parser.add_argument("--enable-vpp-writes", action="store_true", help="let the controller create/repair tenant sub-interfaces")
    parser.add_argument("--vpp-socket", default="/run/vpp/api.sock")
    parser.add_argument("--api-crc-snapshot", default=None)
    parser.add_argument("--reconcile-interval", type=float, default=30.0)
    parser.add_argument("--vpp-watch-interval", type=float, default=1.0, help="VPP liveness check; re-applies right after a VPP restart (0 disables)")
    parser.add_argument("--vpp-startup-settle-seconds", type=float, default=10.0,
                        help="after a (re)connect, longest wait for VPP's startup config before writing")
    parser.add_argument("--kea-lease-file", default=None, help="Kea memfile lease CSV; enables lease -> SubscriberBinding sync (P5-T4)")
    parser.add_argument("--lease-poll-interval", type=float, default=1.0)
    parser.add_argument("--unbound-views-file", default=None, help="generated Unbound include for authenticated subscribers; enables split DNS (P5-T5)")
    args = parser.parse_args()
    if args.api_crc_snapshot is None:
        from .vpp_adapter import DEFAULT_SNAPSHOT
        args.api_crc_snapshot = str(DEFAULT_SNAPSHOT)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    store = DesiredStateStore(args.store, args.audit)
    lifecycle = SubscriberLifecycle(store)
    desired = merge_topology(store, load_json(args.desired_state), lifecycle)
    expired = lifecycle.expire()
    adapter = build_adapter(args)
    try:
        result = reconcile(adapter, store.read() or desired)
    except RuntimeError as exc:
        if not getattr(exc, "startup_pending", False):
            raise
        # Started while VPP is still running its startup config; the
        # reconciler's watch loop applies once it has finished.
        LOG.info("%s", exc)
        state = store.read() or desired
        result = ReconcileResult([], adapter.observed_state(), desired_object_keys(state))
    print(json.dumps({
        "gateway_revision": (store.read() or {}).get("gateway_revision"),
        "capabilities": adapter.capabilities(),
        "desired_object_keys": result.desired_object_keys,
        "expired_subscribers": [item.__dict__ for item in expired],
    }, indent=2, default=str))
    dns_views = None
    if args.unbound_views_file:
        from .dns_views import UnboundViewSync
        dns_views = UnboundViewSync(args.unbound_views_file)
        dns_views.sync(store.read() or {})
    if args.serve:
        reconciler = Reconciler(store, lifecycle, adapter, args.reconcile_interval, dns_views=dns_views,
                                watch_interval=args.vpp_watch_interval)
        reconciler.start()
        if args.kea_lease_file:
            from .bindings import LeaseWatcher
            from .leases import KeaMemfileLeaseSource
            LeaseWatcher(store, KeaMemfileLeaseSource(args.kea_lease_file), args.lease_poll_interval).start()
        serve(args.listen, args.port, args.store, args.audit, args.tls_cert, args.tls_key, args.tls_ca, adapter=adapter, lifecycle=lifecycle, dns_views=dns_views)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
