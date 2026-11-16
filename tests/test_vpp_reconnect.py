"""A VPP restart leaves the controller's API socket broken (lab, 2026-11-16):
observed state must reconnect or report the failure, never crash, and
capabilities must not report a dead connection as connected."""
import json
import threading
from http.client import HTTPConnection
from pathlib import Path

from controller.api import SubscriberApiServer
from controller.store import DesiredStateStore
from controller.vpp_adapter import VppApiAdapter, load_snapshot
from tests.fake_vpp import FakeVppApi, FakeVppClient

REPO = Path(__file__).resolve().parent.parent
SNAPSHOT = REPO / "artifacts" / "api-crc-26.10.json"
LAB = json.loads((REPO / "config" / "lab" / "desired-state.json").read_text())


class BrokenPipeApi(FakeVppApi):
    """The old client's view after VPP restarted: every call fails."""

    def __getattribute__(self, name):
        if name in {"control_ping", "sw_interface_dump", "show_version"}:
            def broken(*args, **kwargs):
                raise BrokenPipeError(32, "Broken pipe")
            return broken
        return super().__getattribute__(name)


def adapter_with_clients(*apis):
    messages = set(load_snapshot(SNAPSHOT)["messages"].values())
    clients = iter(FakeVppClient(messages, api) for api in apis)
    created = []

    def factory(socket):
        client = next(clients)
        created.append(client)
        return client
    adapter = VppApiAdapter("/fake.sock", snapshot_path=SNAPSHOT, client_factory=factory, port_map={"access0": "host-vpp-access"})
    return adapter, created


def healthy_api():
    api = FakeVppApi()
    parent = api.add_interface("host-vpp-access", flags=1)
    api.add_interface("host-vpp-access.101", parent=parent, outer=200, inner=101, flags=1, sub_flags=0)
    return api


def test_observed_state_reconnects_after_vpp_restart():
    adapter, created = adapter_with_clients(healthy_api(), healthy_api())
    adapter.connect()
    created[0].api.__class__ = BrokenPipeApi  # VPP restarted under the first client
    state = adapter.observed_state()
    assert state["vpp_connected"] is True and len(created) == 2
    assert [(q["outer_vlan"], q["inner_vlan"]) for q in state["qinq_subinterfaces"]] == [(200, 101)]


def test_observed_state_reports_instead_of_raising_when_vpp_stays_down():
    adapter, created = adapter_with_clients(healthy_api())
    adapter.connect()
    created[0].api.__class__ = BrokenPipeApi
    adapter._factory = lambda socket: (_ for _ in ()).throw(FileNotFoundError("/run/vpp/api.sock"))
    state = adapter.observed_state()
    assert state["vpp_connected"] is False and "connect failed" in state["error"]
    assert adapter.capabilities()["vpp_connected"] is False


def test_observe_mode_reconcile_tick_reconnects_so_capabilities_are_truthful():
    adapter, created = adapter_with_clients(healthy_api(), healthy_api())
    adapter.connect()
    created[0].api.__class__ = BrokenPipeApi
    adapter.apply(LAB)  # writes disabled: liveness check only
    assert len(created) == 2 and adapter.capabilities()["vpp_connected"] is True


def test_get_returns_json_500_instead_of_an_empty_reply(tmp_path, monkeypatch):
    class Exploding:
        def observed_state(self):
            raise RuntimeError("boom")

        def capabilities(self):
            return {}
    store = DesiredStateStore(tmp_path / "s.sqlite3")
    store.write({**LAB, "subscribers": []})
    monkeypatch.setenv("BSNL_VPP_CONTROLLER_TOKEN", "t")
    server = SubscriberApiServer(("127.0.0.1", 0), str(store.path), None, adapter=Exploding())
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        conn = HTTPConnection("127.0.0.1", server.server_port)
        conn.request("GET", "/v1/observed-state", headers={"Authorization": "Bearer t"})
        response = conn.getresponse()
        assert response.status == 500 and "RuntimeError" in json.loads(response.read())["error"]
    finally:
        server.shutdown()
        server.server_close()
