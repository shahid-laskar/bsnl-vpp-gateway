from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema


DEFAULT_SCHEMA = Path(__file__).resolve().parent.parent / "config" / "schema" / "desired-state.schema.json"


def validate_desired_state(state: dict[str, Any], schema_path: str | Path = DEFAULT_SCHEMA) -> None:
    with Path(schema_path).open(encoding="utf-8") as handle:
        schema = json.load(handle)
    jsonschema.Draft202012Validator(schema).validate(state)
    _validate_unique_keys(state)


def _validate_unique_keys(state: dict[str, Any]) -> None:
    tenant_keys = [item["tenant_key"] for item in state.get("tenants", [])]
    if len(tenant_keys) != len(set(tenant_keys)):
        raise ValueError("duplicate tenant_key")
    session_keys = [item["session_key"] for item in state.get("subscribers", [])]
    if len(session_keys) != len(set(session_keys)):
        raise ValueError("duplicate session_key")
