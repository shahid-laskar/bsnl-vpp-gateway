from controller.interfaces import InterfaceValidationError, interface_plans, phase4_object_keys


def state(*tenants):
    return {"tenants": list(tenants)}


def tenant(key, outer=200, inner=101, **extra):
    value = {"tenant_key": key, "ingress_port": "access0", "parent_interface": "host-vpp-access", "outer_tpid": "0x8100", "outer_vlan": outer, "inner_vlan": inner, "vrf_id": 101, "gateway_ip": "10.9.101.1/24", "admin_state": "enabled"}
    value.update(extra)
    return value


def test_exact_match_plan_is_deterministic():
    desired = state(tenant("b"), tenant("a", inner=102))
    assert [item.tenant_key for item in interface_plans(desired)] == ["a", "b"]
    assert phase4_object_keys(desired) == ["interface/a", "interface/a/address", "interface/a/vrf", "interface/b", "interface/b/address", "interface/b/vrf"]


def test_duplicate_qinq_context_is_rejected():
    try:
        interface_plans(state(tenant("a"), tenant("b")))
    except InterfaceValidationError as exc:
        assert "duplicate QinQ context" in str(exc)
    else:
        raise AssertionError("duplicate QinQ context was accepted")


def test_exact_match_and_ipv4_are_required():
    for changes in ({"exact_match": False}, {"gateway_ip": "2001:db8::1/64"}):
        try:
            interface_plans(state(tenant("a", **changes)))
        except InterfaceValidationError:
            pass
        else:
            raise AssertionError("invalid interface contract was accepted")
