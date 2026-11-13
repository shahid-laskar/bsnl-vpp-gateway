import ipaddress

from controller.host_services import AtomicConfigApplier, HostServiceValidationError, ServiceReconciler, host_service_plans, render_dns_records, render_kea_subnet, render_kea_config, render_dnsmasq_config


def tenant(**changes):
    value = {
        "tenant_key": "lab/200/101", "gateway_ip": "10.9.101.1/24",
        "dhcp_ranges": [{"start": "10.9.101.5", "end": "10.9.101.105"}],
        "admin_state": "enabled",
    }
    value.update(changes)
    return value


def services(**changes):
    value = {"relay_address": "198.51.100.1", "dns_address": "198.51.100.2", "portal_url": "https://wifi.bsnl.co.in/portal/login/"}
    value.update(changes)
    return value


def test_dhcp_and_dns_plan_is_derived_from_tenant_state():
    plan = host_service_plans({"tenants": [tenant()]}, services())[0]
    assert plan.subnet == ipaddress.ip_network("10.9.101.0/24")
    assert plan.pool_start == ipaddress.ip_address("10.9.101.5")
    assert plan.dhcp_key.endswith("lab/200/101")


def test_dhcp_pool_cannot_include_gateway():
    try:
        host_service_plans({"tenants": [tenant(dhcp_ranges=[{"start": "10.9.101.1", "end": "10.9.101.105"}])]}, services())
    except HostServiceValidationError:
        pass
    else:
        raise AssertionError("DHCP pool containing gateway was accepted")


def test_rendered_host_service_payloads_are_deterministic():
    plan = host_service_plans({"tenants": [tenant()]}, services())[0]
    kea = render_kea_subnet(plan)
    assert kea["subnet"] == "10.9.101.0/24"
    assert kea["pools"] == [{"pool": "10.9.101.5-10.9.101.105"}]
    assert render_dns_records(plan, ["portal.lab", "wifi.bsnl.co.in"])["portal.lab"] == "198.51.100.2"


def test_atomic_config_apply_backups_and_rolls_back_on_validation_failure(tmp_path):
    target = tmp_path / "kea.json"
    target.write_text("old\n")
    applier = AtomicConfigApplier(lambda path: (_ for _ in ()).throw(ValueError("invalid")), tmp_path / "backups")
    try:
        applier.apply(target, "new\n")
    except ValueError:
        pass
    else:
        raise AssertionError("invalid config was applied")
    assert target.read_text() == "old\n"


def test_rendered_configs_include_expected_services():
    plan = host_service_plans({"tenants": [tenant()]}, services())[0]
    kea = render_kea_config([plan])
    assert "10.9.101.0/24" in kea
    assert "kea4-ctrl-socket" in kea
    assert "/var/lib/kea/kea-leases4.csv" in kea
    assert "/var/log/kea/kea-dhcp4.log" in kea
    dnsmasq = render_dnsmasq_config([plan], ["portal.lab"])
    assert "address=/portal.lab/198.51.100.2" in dnsmasq
    assert "cache-size=1000" in dnsmasq
    assert "log-queries" in dnsmasq


def test_service_reload_failure_restores_backup(tmp_path):
    target = tmp_path / "dnsmasq.conf"
    target.write_text("old\n")
    calls = []

    def runner(command):
        calls.append(list(command))
        if command == ["systemctl", "reload", "dnsmasq"]:
            raise RuntimeError("reload failed")

    try:
        ServiceReconciler(runner, backup_dir=tmp_path / "backups").apply_and_reload(target, "new\n", ["dnsmasq", "--test", "--conf-file"], ["systemctl", "reload", "dnsmasq"])
    except RuntimeError:
        pass
    else:
        raise AssertionError("reload failure was swallowed")
    assert target.read_text() == "old\n"
    assert calls[-1] == ["systemctl", "reload", "dnsmasq"]


def test_atomic_apply_preserves_target_mode_and_keeps_backup_out_of_conf_dir(tmp_path):
    conf_dir = tmp_path / "dnsmasq.d"
    conf_dir.mkdir()
    target = conf_dir / "bsnl-vpp-lab.conf"
    target.write_text("old\n")
    target.chmod(0o640)
    backups = tmp_path / "backups"
    backup = AtomicConfigApplier(backup_dir=backups).apply(target, "new\n")
    assert target.read_text() == "new\n"
    assert (target.stat().st_mode & 0o777) == 0o640
    assert backup is not None and backup.parent == backups and backup.read_text() == "old\n"
    assert sorted(p.name for p in conf_dir.iterdir()) == ["bsnl-vpp-lab.conf"]


def test_atomic_apply_new_file_is_world_readable_not_0600(tmp_path):
    target = tmp_path / "kea" / "kea-dhcp4.conf"
    assert AtomicConfigApplier(backup_dir=tmp_path / "backups").apply(target, "{}\n") is None
    assert (target.stat().st_mode & 0o777) == 0o644
