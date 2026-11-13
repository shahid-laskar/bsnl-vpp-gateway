from __future__ import annotations

import argparse
import json
import logging

from .api import serve
from .config import load_json
from .reconcile import LabAdapter, Reconciler, reconcile
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
    adapter = VppApiAdapter(args.vpp_socket, snapshot_path=args.api_crc_snapshot, enable_writes=args.enable_vpp_writes, port_map=parse_port_map(args.port_map))
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
    result = reconcile(adapter, store.read() or desired)
    print(json.dumps({
        "gateway_revision": (store.read() or {}).get("gateway_revision"),
        "capabilities": adapter.capabilities(),
        "desired_object_keys": result.desired_object_keys,
        "expired_subscribers": [item.__dict__ for item in expired],
    }, indent=2, default=str))
    if args.serve:
        reconciler = Reconciler(store, lifecycle, adapter, args.reconcile_interval)
        reconciler.start()
        serve(args.listen, args.port, args.store, args.audit, args.tls_cert, args.tls_key, args.tls_ca, adapter=adapter, lifecycle=lifecycle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
