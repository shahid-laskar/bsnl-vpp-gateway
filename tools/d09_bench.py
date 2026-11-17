"""D-09 measurement: per-subscriber policy cost, ACL plugin (B) vs SVS (A).

Runs against a separate, throw-away VPP instance (``tools/d09/``), never the
lab dataplane:

    sudo sh tools/d09/run-bench-vpp.sh start      # VPP on core 2, /run/vpp-bench
    sudo python3 -m tools.d09_bench --sizes 100 1000 10000 > report.json
    sudo sh tools/d09/run-bench-vpp.sh stop

Measured, for N authenticated background subscribers:

B  (deployed, ADR-010/015): the controller's own ``VppPolicyEnforcer.apply``
   for one activation and one deactivation (tenant ACL + ABF match ACL
   replace, including the dumps it compares against), and the raw
   ``acl_add_replace`` time for an N-rule ACL.
A  (SVS): ``svs_route_add_del`` of one /32 with N routes present.
Churn: an authenticated subscriber pings a VPP address every 5 ms through the
   QinQ sub-interface while subscribers are activated/deactivated at a target
   rate; reports achieved rate, op latency and ping loss (baseline without
   churn first).

Lab-VM numbers (af_packet, one main thread, no DPDK) are relative evidence for
the choice, not production capacity.
"""
from __future__ import annotations

import argparse
import copy
import ipaddress
import json
import re
import statistics
import subprocess
import threading
import time
from pathlib import Path

from controller.policy import AclRule, VppPolicyEnforcer, PERMIT, ANY4

REPO = Path(__file__).resolve().parent.parent
SOCKET = "/run/vpp-bench/api.sock"
NS, QINQ = "bsnl-bench", "bvpp1.200.101"
PROBE_SRC, PROBE_DST = "10.9.101.7", "192.0.2.1"
GATEWAY = "10.9.0.1/16"


def connect(socket: str):
    from vpp_papi import VPPApiClient
    client = VPPApiClient(server_address=socket, use_socket=True, async_thread=False)
    client.connect("d09-bench")
    return client


def pct(values: list[float], q: float) -> float:
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int(round(q * (len(ordered) - 1))))], 2)


def summary(values_ms: list[float]) -> dict:
    return {"n": len(values_ms), "p50_ms": pct(values_ms, 0.5), "p95_ms": pct(values_ms, 0.95),
            "max_ms": round(max(values_ms), 2), "mean_ms": round(statistics.mean(values_ms), 2)}


def subscriber_ips(count: int) -> list[str]:
    """count addresses in 10.9.0.0/16, skipping the gateway, .255/.0 hosts and the probe."""
    out, host = [], ipaddress.IPv4Address("10.9.1.2")
    while len(out) < count:
        if host.packed[3] not in (0, 255) and str(host) != PROBE_SRC:
            out.append(str(host))
        host += 1
    return out


def bench_state(addresses: list[str]) -> dict:
    lab = json.loads((REPO / "config" / "lab" / "desired-state.json").read_text())
    state = copy.deepcopy(lab)
    tenant = state["tenants"][0]
    tenant.update({"gateway_ip": GATEWAY, "mac_enforcement": "log_only", "parent_interface": "host-bvpp0"})
    policy = state["policies"][tenant["pre_auth_policy_ref"]]
    policy["http_redirect"] = {"next_hop": "192.0.2.254"}
    key = tenant["tenant_key"]
    state["subscribers"] = [{"session_key": f"{key}/{ip}", "tenant_key": key, "subscriber_id": ip, "private_ipv4": ip,
                             "state": "authenticated"} for ip in [PROBE_SRC, *addresses]]
    return state


def sub_if_index(api) -> int:
    return next(int(i.sw_if_index) for i in api.sw_interface_dump() if i.interface_name.rstrip("\x00") == "host-bvpp0.101")


class Pinger:
    """ping -i 0.005 from the authenticated probe subscriber; loss over the window."""

    def __init__(self, seconds: float) -> None:
        self.proc = subprocess.Popen(["ip", "netns", "exec", NS, "ping", "-n", "-q", "-i", "0.005", "-W", "1",
                                      "-w", str(int(seconds)), "-I", PROBE_SRC, PROBE_DST],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def result(self) -> dict:
        out = self.proc.communicate(timeout=120)[0]
        match = re.search(r"(\d+) packets transmitted, (\d+) received", out)
        sent, got = (int(match.group(1)), int(match.group(2))) if match else (0, 0)
        return {"sent": sent, "received": got, "lost": sent - got, "loss_pct": round(100.0 * (sent - got) / sent, 3) if sent else None}


# --- candidate B: ACL plugin (the deployed controller code) -------------------------------------
def measure_b(api, sw: int, n: int, samples: int) -> dict:
    base_ips = subscriber_ips(n)
    extra = subscriber_ips(n + samples)[n:]
    enforcer = VppPolicyEnforcer(api, enable_writes=True)
    index = {bench_state([])["tenants"][0]["tenant_key"]: sw}
    t0 = time.perf_counter()
    enforcer.apply(bench_state(base_ips), index)
    load_ms = (time.perf_counter() - t0) * 1000
    act, deact, noop = [], [], []
    for ip in extra:
        t0 = time.perf_counter(); enforcer.apply(bench_state(base_ips + [ip]), index); act.append((time.perf_counter() - t0) * 1000)
        t0 = time.perf_counter(); enforcer.apply(bench_state(base_ips), index); deact.append((time.perf_counter() - t0) * 1000)
    for _ in range(min(samples, 5)):
        t0 = time.perf_counter(); enforcer.apply(bench_state(base_ips), index); noop.append((time.perf_counter() - t0) * 1000)
    tenant_rules = sum(1 for a in api.acl_dump(acl_index=0xFFFFFFFF) if a.tag.rstrip("\x00").startswith("bsnl:acl/") for _ in a.r)
    return {"subscribers": n, "initial_load_ms": round(load_ms, 1), "tenant_acl_rules": tenant_rules,
            "activation": summary(act), "deactivation": summary(deact), "converged_noop_apply": summary(noop)}


def measure_raw_acl(api, n: int, samples: int) -> dict:
    rules = [AclRule(PERMIT, f"{ip}/32", "192.0.2.0/24").to_api() for ip in subscriber_ips(n)] + \
            [AclRule(0, ANY4, ANY4).to_api()]
    index, times = 0xFFFFFFFF, []
    for _ in range(samples):
        t0 = time.perf_counter()
        reply = api.acl_add_replace(acl_index=index, tag="bench:raw", count=len(rules), r=rules)
        times.append((time.perf_counter() - t0) * 1000)
        index = reply.acl_index
    t0 = time.perf_counter(); api.acl_dump(acl_index=index); dump_ms = (time.perf_counter() - t0) * 1000
    api.acl_del(acl_index=index)
    return {"rules": len(rules), "acl_add_replace": summary(times[1:] or times), "acl_dump_ms": round(dump_ms, 1)}


# --- candidate A: SVS ------------------------------------------------------------------------
SVS_TABLE, INTERNET = 100, 0   # source table (SVS), lookup table for authenticated sources


def svs_setup(api, sw: int) -> None:
    api.ip_table_add_del_v2(is_add=True, create_mfib=False, table={"table_id": SVS_TABLE, "is_ip6": False})
    api.svs_table_add_del(is_add=True, af=0, table_id=SVS_TABLE)
    api.svs_enable_disable(is_enable=True, af=0, table_id=SVS_TABLE, sw_if_index=sw)


def svs_teardown(api, sw: int, prefixes: list[str]) -> None:
    for prefix in prefixes:
        api.svs_route_add_del(is_add=False, prefix=prefix, table_id=SVS_TABLE, source_table_id=INTERNET)
    api.svs_enable_disable(is_enable=False, af=0, table_id=SVS_TABLE, sw_if_index=sw)
    api.svs_table_add_del(is_add=False, af=0, table_id=SVS_TABLE)


def svs_route(api, ip: str, add: bool) -> float:
    t0 = time.perf_counter()
    reply = api.svs_route_add_del(is_add=add, prefix=f"{ip}/32", table_id=SVS_TABLE, source_table_id=INTERNET)
    if reply.retval:
        raise RuntimeError(f"svs_route_add_del retval {reply.retval}")
    return (time.perf_counter() - t0) * 1000


def measure_a(api, sw: int, n: int, samples: int) -> dict:
    base = [PROBE_SRC] + subscriber_ips(n)
    extra = subscriber_ips(n + samples)[n:]
    svs_setup(api, sw)
    t0 = time.perf_counter()
    for ip in base:
        svs_route(api, ip, True)
    load_ms = (time.perf_counter() - t0) * 1000
    act = [svs_route(api, ip, True) for ip in extra]
    deact = [svs_route(api, ip, False) for ip in extra]
    svs_teardown(api, sw, [f"{ip}/32" for ip in base])
    return {"subscribers": n, "initial_load_ms": round(load_ms, 1), "activation": summary(act), "deactivation": summary(deact)}


# --- churn under traffic -----------------------------------------------------------------------
def churn(api, sw: int, n: int, rate: float, seconds: float, candidate: str) -> dict:
    base_ips = subscriber_ips(n)
    pool = subscriber_ips(n + 50)[n:]
    enforcer = VppPolicyEnforcer(api, enable_writes=True)
    index = {bench_state([])["tenants"][0]["tenant_key"]: sw}
    enforcer.apply(bench_state(base_ips), index)            # probe permitted in the ACL in both candidates
    if candidate == "A":
        svs_setup(api, sw)
        for ip in [PROBE_SRC, *base_ips]:
            svs_route(api, ip, True)
    time.sleep(1)
    pinger = Pinger(seconds)
    ops, lat, start, active = 0, [], time.perf_counter(), []
    while time.perf_counter() - start < seconds - 0.5:
        due = start + ops / rate
        delay = due - time.perf_counter()
        if delay > 0:
            time.sleep(delay)
        ip = pool[ops % len(pool)]
        adding = ip not in active
        t0 = time.perf_counter()
        if candidate == "B":
            next_active = active + [ip] if adding else [a for a in active if a != ip]
            enforcer.apply(bench_state(base_ips + next_active), index)
        else:
            svs_route(api, ip, adding)
            next_active = active + [ip] if adding else [a for a in active if a != ip]
        lat.append((time.perf_counter() - t0) * 1000)
        active = next_active
        ops += 1
    elapsed = time.perf_counter() - start
    loss = pinger.result()
    if candidate == "A":
        svs_teardown(api, sw, [f"{ip}/32" for ip in [PROBE_SRC, *base_ips, *active]])
    enforcer.apply(bench_state([]), index)
    return {"candidate": candidate, "subscribers": n, "target_rate": rate, "achieved_rate": round(ops / elapsed, 1),
            "ops": ops, "op_latency": summary(lat), "probe_ping": loss}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--socket", default=SOCKET)
    parser.add_argument("--sizes", type=int, nargs="+", default=[100, 1000, 10000])
    parser.add_argument("--samples", type=int, default=20)
    parser.add_argument("--churn-rates", type=float, nargs="+", default=[10, 50])
    parser.add_argument("--churn-sizes", type=int, nargs="+", default=[1000, 10000])
    parser.add_argument("--churn-seconds", type=float, default=60)
    parser.add_argument("--skip-churn", action="store_true")
    args = parser.parse_args()
    client = connect(args.socket)
    api = client.api
    sw = sub_if_index(api)
    version = api.show_version().version.rstrip("\x00")
    report: dict = {"vpp": version, "socket": args.socket, "B": [], "B_raw_acl": [], "A": [], "churn": []}

    # Baseline loss with the probe permitted and nothing changing.
    VppPolicyEnforcer(api, enable_writes=True).apply(bench_state([]), {bench_state([])["tenants"][0]["tenant_key"]: sw})
    time.sleep(1)
    report["baseline_ping"] = Pinger(min(20, args.churn_seconds)).result()
    for n in args.sizes:
        report["B"].append(measure_b(api, sw, n, args.samples)); print(json.dumps(report["B"][-1]), flush=True)
        report["B_raw_acl"].append(measure_raw_acl(api, n, max(5, args.samples // 2))); print(json.dumps(report["B_raw_acl"][-1]), flush=True)
        report["A"].append(measure_a(api, sw, n, args.samples)); print(json.dumps(report["A"][-1]), flush=True)
    if not args.skip_churn:
        for n in args.churn_sizes:
            for rate in args.churn_rates:
                for candidate in ("B", "A"):
                    report["churn"].append(churn(api, sw, n, rate, args.churn_seconds, candidate))
                    print(json.dumps(report["churn"][-1]), flush=True)
    VppPolicyEnforcer(api, enable_writes=True).apply({**bench_state([]), "tenants": []}, {})
    client.disconnect()
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
