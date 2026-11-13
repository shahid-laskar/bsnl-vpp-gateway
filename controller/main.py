from __future__ import annotations

import argparse
import json

from .api import serve
from .config import load_json
from .reconcile import LabAdapter, reconcile
from .store import DesiredStateStore
from .subscribers import SubscriberLifecycle


def main() -> int:
    parser = argparse.ArgumentParser(description="BSNL VPP lab controller")
    parser.add_argument("--desired-state", default="config/lab/desired-state.json")
    parser.add_argument("--store", default="var/controller.sqlite3")
    parser.add_argument("--audit", default="var/audit.jsonl")
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--tls-cert")
    parser.add_argument("--tls-key")
    parser.add_argument("--tls-ca")
    args = parser.parse_args()
    configured = load_json(args.desired_state)
    store = DesiredStateStore(args.store)
    persisted = store.read()
    if persisted and int(persisted.get("gateway_revision", 0)) >= int(configured.get("gateway_revision", 0)):
        desired = persisted
    else:
        desired = configured
        store.write(desired)
    expired = SubscriberLifecycle(store, args.audit).expire()
    desired = store.read() or desired
    result = reconcile(LabAdapter(), desired)
    print(json.dumps({"changed_objects": result.changed_objects, "desired_object_keys": result.desired_object_keys, "observed": result.observed_state, "expired_subscribers": [item.__dict__ for item in expired]}, indent=2))
    if args.serve:
        serve(args.listen, args.port, args.store, args.audit, args.tls_cert, args.tls_key, args.tls_ca)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
