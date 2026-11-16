"""P5-T5: split-horizon DNS with Unbound views (ADR-014)."""
import json
import shutil
import subprocess
import threading
from http.client import HTTPConnection
from pathlib import Path

import pytest

from controller.api import SubscriberApiServer
from controller.dns_views import UnboundViewSync, authenticated_addresses, render_views
from controller.host_services import HostServiceValidationError, host_service_plans, render_unbound_config
from controller.reconcile import LabAdapter, Reconciler
from controller.store import DesiredStateStore
from controller.subscribers import SubscriberLifecycle

REPO = Path(__file__).resolve().parent.parent
LAB = json.loads((REPO / "config" / "lab" / "desired-state.json").read_text())
SERVICES = json.loads((REPO / "config" / "lab" / "host-services.json").read_text())
TENANT = LAB["tenants"][0]["tenant_key"]


def rendered(**changes):
    services = {**SERVICES, **changes}
    return render_unbound_config(host_service_plans(LAB, services), services)


def view_block(text, name):
    return text.split(f'name: "{name}"', 1)[1].split("\nview:", 1)[0]


# --- static resolver config ----------------------------------------------------------------
def test_tenant_subnet_maps_to_captive_view_and_everything_else_is_refused():
    text = rendered()
    assert "access-control: 0.0.0.0/0 refuse" in text
    assert "access-control: 10.9.101.0/24 allow" in text
    assert "access-control-view: 10.9.101.0/24 captive" in text
    assert "interface: 198.51.100.2" in text and "do-ip6: no" in text
    assert 'include: "/etc/unbound/bsnl/*.conf"' in text


def test_captive_view_refuses_unknown_names_and_answers_check_domains_with_the_portal():
    captive = view_block(rendered(), "captive")
    assert 'local-zone: "." refuse' in captive
    assert 'local-data: "captive.apple.com. 5 IN A 10.44.0.209"' in captive
    assert 'local-data: "connectivitycheck.gstatic.com. 5 IN A 10.44.0.209"' in captive
    # portal names are repeated in the view because "." would shadow the global zones
    assert 'local-data: "wifi.bsnl.co.in. 5 IN A 10.44.0.209"' in captive


def test_authenticated_view_has_no_overrides_and_portal_name_is_global():
    text = rendered()
    assert view_block(text, "authenticated").strip() == "view-first: yes"
    server = text.split("\nview:", 1)[0]
    assert 'local-data: "wifi.bsnl.co.in. 5 IN A 10.44.0.209"' in server
    assert "captive.apple.com" not in server  # real answer once authenticated


def test_resolve_mode_and_preauth_dependencies():
    captive = view_block(rendered(preauth_dns_default="resolve", preauth_resolve_domains=["cdn.example.net"]), "captive")
    assert 'local-zone: "." refuse' not in captive
    assert 'local-zone: "cdn.example.net." transparent' in captive


@pytest.mark.parametrize("change", [
    {"captive_hosts": ['evil.com" refuse\nserver: x']},
    {"local_names": {"bad name": "198.51.100.2"}},
    {"preauth_dns_default": "portal"},
    {"captive_ttl_seconds": 3600},
    {"unbound_dynamic_dir": "/var/lib/elsewhere"},
    {"portal_address": "not-an-ip"},
])
def test_unsafe_or_invalid_settings_are_rejected(change):
    with pytest.raises(HostServiceValidationError):
        rendered(**change)


@pytest.mark.skipif(shutil.which("unbound-checkconf") is None, reason="unbound not installed")
def test_rendered_config_passes_unbound_checkconf(tmp_path):
    dynamic = tmp_path / "dyn"
    dynamic.mkdir()
    (dynamic / "authenticated.conf").write_text(render_views({"tenants": LAB["tenants"], "subscribers": [
        {"tenant_key": TENANT, "private_ipv4": "10.9.101.7", "state": "authenticated"}]}))
    conf = tmp_path / "unbound.conf"
    conf.write_text(rendered().replace("/etc/unbound/bsnl", str(dynamic)).replace("server:\n", 'server:\n  chroot: ""\n  username: ""\n  directory: "' + str(tmp_path) + '"\n  pidfile: ""\n', 1))
    result = subprocess.run(["unbound-checkconf", str(conf)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


# --- per-subscriber views -------------------------------------------------------------------
def state(*subs, tenant_state="enabled"):
    return {"tenants": [{**LAB["tenants"][0], "admin_state": tenant_state}], "subscribers": list(subs)}


def sub(ip, st="authenticated"):
    return {"tenant_key": TENANT, "private_ipv4": ip, "state": st}


def test_only_authenticated_subscribers_of_enabled_tenants_get_the_view():
    s = state(sub("10.9.101.9"), sub("10.9.101.7"), sub("10.9.101.8", "deactivated"), sub("10.9.101.6", "expired"))
    assert authenticated_addresses(s) == ["10.9.101.7", "10.9.101.9"]
    assert authenticated_addresses(state(sub("10.9.101.7"), tenant_state="disabled")) == []
    text = render_views(s)
    assert text.splitlines()[1] == "server:"
    assert "  access-control-view: 10.9.101.7/32 authenticated" in text and "10.9.101.8" not in text


class Runner:
    def __init__(self, fail=None):
        self.calls, self.fail = [], fail or set()

    def __call__(self, command):
        self.calls.append(command[0])
        if command[0] in self.fail:
            raise subprocess.CalledProcessError(1, command, stderr="boom")


def test_sync_writes_checks_and_reloads_only_on_change(tmp_path):
    runner = Runner()
    views = UnboundViewSync(tmp_path / "authenticated.conf", runner=runner)
    assert views.sync(state(sub("10.9.101.7"))) is True
    assert runner.calls == ["unbound-checkconf", "unbound-control"]
    assert views.sync(state(sub("10.9.101.7"))) is False  # unchanged: no reload
    assert views.sync(state()) is True
    assert "10.9.101.7" not in (tmp_path / "authenticated.conf").read_text()
    assert oct((tmp_path / "authenticated.conf").stat().st_mode & 0o777) == "0o644"


def test_failed_check_restores_previous_file_and_skips_reload(tmp_path):
    target = tmp_path / "authenticated.conf"
    views = UnboundViewSync(target, runner=Runner())
    views.sync(state(sub("10.9.101.7")))
    before = target.read_text()
    bad = Runner(fail={"unbound-checkconf"})
    views.runner = bad
    assert views.sync(state(sub("10.9.101.8"))) is False
    assert target.read_text() == before and bad.calls == ["unbound-checkconf"]
    assert "boom" in views.last_error


def test_failed_reload_is_retried_on_next_sync(tmp_path):
    views = UnboundViewSync(tmp_path / "authenticated.conf", runner=Runner(fail={"unbound-control"}))
    assert views.sync(state(sub("10.9.101.7"))) is False
    views.runner = Runner()
    assert views.sync(state(sub("10.9.101.7"))) is True  # same content, but never applied


# --- wiring -----------------------------------------------------------------------------------
def test_api_activation_and_logout_update_dns_views(tmp_path, monkeypatch):
    store = DesiredStateStore(tmp_path / "s.sqlite3")
    store.write({**LAB, "subscribers": [], "gateway_revision": 1})
    monkeypatch.setenv("BSNL_VPP_CONTROLLER_TOKEN", "t")
    monkeypatch.delenv("BSNL_VPP_PORTAL_HMAC_SECRET", raising=False)
    views = UnboundViewSync(tmp_path / "authenticated.conf", runner=Runner())
    server = SubscriberApiServer(("127.0.0.1", 0), str(store.path), None, lifecycle=SubscriberLifecycle(store), dns_views=views)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def post(path, body, key):
        conn = HTTPConnection("127.0.0.1", server.server_port)
        conn.request("POST", path, body=json.dumps(body), headers={"Authorization": "Bearer t", "Idempotency-Key": key, "Content-Type": "application/json"})
        status = conn.getresponse().status
        conn.close()
        return status
    try:
        assert post("/v1/subscribers/activate", {"operation_id": "a", "subscriber": {
            "session_key": f"{TENANT}/10.9.101.7", "tenant_key": TENANT, "subscriber_id": "u", "session_id": "s",
            "private_ipv4": "10.9.101.7", "valid_until": "2099-01-01T00:00:00+00:00"}}, "k1") == 200
        assert "10.9.101.7/32 authenticated" in (tmp_path / "authenticated.conf").read_text()
        assert post("/v1/subscribers/deactivate", {"operation_id": "d", "session_key": f"{TENANT}/10.9.101.7"}, "k2") == 200
        assert "10.9.101.7" not in (tmp_path / "authenticated.conf").read_text()
    finally:
        server.shutdown()
        server.server_close()


def test_reconciler_syncs_dns_views(tmp_path):
    store = DesiredStateStore(tmp_path / "s.sqlite3")
    store.write({**LAB, "subscribers": [{**sub("10.9.101.7"), "session_key": f"{TENANT}/10.9.101.7", "subscriber_id": "u"}], "gateway_revision": 1})
    views = UnboundViewSync(tmp_path / "authenticated.conf", runner=Runner())
    summary = Reconciler(store, SubscriberLifecycle(store), LabAdapter(), dns_views=views).run_once()
    assert summary["dns_reloaded"] is True and "10.9.101.7/32" in (tmp_path / "authenticated.conf").read_text()


def test_committed_resolver_config_matches_the_renderer():
    committed = (REPO / "deployment" / "resolver" / "unbound-bsnl-vpp-lab.conf").read_text()
    assert committed == rendered() + "\n" or committed == rendered()


def test_bypass_suite_parses_dig_output():
    from controller.bypass_suite import parse_dig
    ok = ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; flags: qr rd ra\n\ncaptive.apple.com.\t5\tIN\tA\t10.44.0.209\n"
    assert parse_dig(ok) == ("NOERROR", ["10.44.0.209"])
    assert parse_dig(";; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 2\n") == ("REFUSED", [])
    assert parse_dig(";; communications error: timed out\n") == ("TIMEOUT", [])
    cname = "x.\t5\tIN\tCNAME\ty.\ny.\t5\tIN\tA\t192.0.2.1\n;; status: NOERROR"
    assert parse_dig(cname)[1] == ["192.0.2.1"]
