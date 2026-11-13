"""Generate the pinned VPP binary-API CRC snapshot used by the controller.

Reads the .api.json definitions installed by the VPP packages (no VPP socket
needed) and records name_crc for every message the controller uses. Re-run and
review the diff on every VPP upgrade (plan F-17, K-04); the controller refuses
to operate when the running VPP's message table does not contain these.

    python3 tools/api_crc_snapshot.py --release 26.10 > artifacts/api-crc-26.10.json
"""
import argparse
import glob
import json
import sys

MESSAGES = [
    "control_ping", "show_version",
    "sw_interface_dump", "create_subif", "delete_subif", "sw_interface_set_mtu",
    "sw_interface_set_table", "sw_interface_get_table", "sw_interface_add_del_address",
    "ip_address_dump", "sw_interface_set_flags", "sw_interface_tag_add_del",
    "ip_table_add_del_v2", "ip_table_dump",
    "acl_dump", "acl_interface_list_dump", "acl_add_replace", "acl_interface_set_acl_list", "acl_del",
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", required=True)
    parser.add_argument("--api-dir", default="/usr/share/vpp/api")
    args = parser.parse_args()
    found = {}
    for path in sorted(glob.glob(f"{args.api_dir}/**/*.api.json", recursive=True)):
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
        for message in document.get("messages", []):
            name, crc = message[0], message[-1]["crc"]
            if name in MESSAGES:
                found[name] = f"{name}_{crc[2:]}"
    missing = sorted(set(MESSAGES) - set(found))
    if missing:
        print(f"messages not found in {args.api_dir}: {missing}", file=sys.stderr)
        return 1
    json.dump({"vpp_release": args.release, "source": args.api_dir, "messages": dict(sorted(found.items()))}, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
