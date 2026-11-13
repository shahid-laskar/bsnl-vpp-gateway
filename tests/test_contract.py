import json
from pathlib import Path

import pytest

from controller.contract import ContractError, ReplayCache, session_key_for, sign, validate_request, verify_signature

GOLDEN = Path(__file__).resolve().parent.parent / "config" / "contract" / "golden"


@pytest.mark.parametrize("name", ["activate", "deactivate"])
def test_golden_vectors_sign_and_validate(name):
    vector = json.loads((GOLDEN / f"{name}.json").read_text())
    raw = vector["body"].encode()
    assert sign(vector["secret"], vector["timestamp"], vector["nonce"], vector["method"], vector["path"], vector["idempotency_key"], raw) == vector["expected_signature"]
    validate_request(f"{name}Request", json.loads(raw))
    headers = {"X-BSNL-Timestamp": vector["timestamp"], "X-BSNL-Nonce": vector["nonce"], "X-BSNL-Signature": vector["expected_signature"], "Idempotency-Key": vector["idempotency_key"]}
    assert verify_signature(vector["secret"], headers, "POST", vector["path"], raw, ReplayCache(), now=int(vector["timestamp"])) is None


def test_golden_activate_session_key_matches_rule():
    body = json.loads(json.loads((GOLDEN / "activate.json").read_text())["body"])
    subscriber = body["subscriber"]
    assert subscriber["session_key"] == session_key_for(subscriber["tenant_key"], subscriber["private_ipv4"])


def test_unknown_fields_and_bad_ip_are_rejected():
    body = json.loads(json.loads((GOLDEN / "activate.json").read_text())["body"])
    body["subscriber"]["unexpected"] = 1
    with pytest.raises(ContractError):
        validate_request("activateRequest", body)
    body["subscriber"].pop("unexpected")
    body["subscriber"]["private_ipv4"] = "10.9.101.300"
    with pytest.raises(ContractError):
        validate_request("activateRequest", body)


def test_replay_cache_expires_entries():
    cache = ReplayCache(window_seconds=10)
    assert cache.check_and_add("sig", now=0)
    assert not cache.check_and_add("sig", now=5)
    assert cache.check_and_add("sig", now=21)
