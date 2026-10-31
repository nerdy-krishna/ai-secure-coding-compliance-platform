"""Deterministically extract the safe Capability 11 OpenAPI surface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

C11_PATHS = (
    "/api/v1/pentesting/engagements/{engagement_id}/attempts/{attempt_id}/callback-expectations",
    "/api/v1/pentesting/engagements/{engagement_id}/attempts/{attempt_id}/callback-expectations/{expectation_id}",
    "/api/v1/pentesting/engagements/{engagement_id}/attempts/{attempt_id}/callback-causality",
    "/api/v1/pentesting/engagements/{engagement_id}/attempts/{attempt_id}/callback-expectations/{expectation_id}/revoke",
)
SCHEMA_PREFIX = "#/components/schemas/"
FORBIDDEN_SCHEMA_TERMS = (
    "token",
    "verifier",
    "callback_address",
    "raw_payload",
    "object_key",
    "object_version",
    "wrapped_data_key",
    "decryption_material",
)


def _schema_refs(value: Any) -> set[str]:
    refs: set[str] = set()
    if isinstance(value, dict):
        ref = value.get("$ref")
        if isinstance(ref, str) and ref.startswith(SCHEMA_PREFIX):
            refs.add(ref.removeprefix(SCHEMA_PREFIX))
        for child in value.values():
            refs.update(_schema_refs(child))
    elif isinstance(value, list):
        for child in value:
            refs.update(_schema_refs(child))
    return refs


def extract_capability11(document: dict[str, Any]) -> dict[str, Any]:
    available_paths = document.get("paths", {})
    missing = sorted(set(C11_PATHS) - set(available_paths))
    if missing:
        raise ValueError(f"PENTEST_C11_OPENAPI_PATH_SET_MISMATCH:{','.join(missing)}")
    paths = {path: available_paths[path] for path in C11_PATHS}
    available = document.get("components", {}).get("schemas", {})
    pending = _schema_refs(paths)
    selected: dict[str, Any] = {}
    while pending:
        name = min(pending)
        pending.remove(name)
        if name in selected:
            continue
        schema = available.get(name)
        if schema is None:
            raise ValueError(f"PENTEST_C11_OPENAPI_SCHEMA_MISSING:{name}")
        selected[name] = schema
        pending.update(_schema_refs(schema) - selected.keys())
    rendered = json.dumps({"paths": paths, "schemas": selected}, sort_keys=True).lower()
    leaked = [term for term in FORBIDDEN_SCHEMA_TERMS if term in rendered]
    if leaked:
        raise ValueError(f"PENTEST_C11_OPENAPI_PROTECTED_FIELD:{','.join(leaked)}")
    return {
        "openapi": document["openapi"],
        "info": {
            "title": "SCCAP Capability 11 API",
            "version": "c11.v1",
            "description": (
                "Safe asynchronous callback expectation and causality projections; "
                "contains no token, verifier, callback address, restricted payload, "
                "protected locator or decryption material."
            ),
        },
        "paths": paths,
        "components": {
            "schemas": {name: selected[name] for name in sorted(selected)},
            "securitySchemes": document.get("components", {}).get(
                "securitySchemes", {}
            ),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    source = json.loads(args.source.read_text(encoding="utf-8"))
    extracted = extract_capability11(source)
    args.destination.write_text(
        json.dumps(extracted, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
