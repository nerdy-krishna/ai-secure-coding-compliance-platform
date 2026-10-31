"""Deterministically extract the safe Capability 13 OpenAPI surface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


PATH_PREFIX = "/api/v1/pentesting/"
SCHEMA_PREFIX = "#/components/schemas/"
FORBIDDEN_SCHEMA_TERMS = (
    "raw_request",
    "raw_response",
    "object_key",
    "object_version",
    "wrapped_data_key",
    "private_key",
    "callback_token",
    "credential",
    "secret",
    "model_text",
    "prompt",
    "completion",
    "sensitive_prior_state",
    "protected_locator",
)

REQUIRED_OPERATION_NAMES = frozenset(
    {
        "create_capability13_evidence_export_request",
        "create_capability13_fresh_retest_v2",
        "create_capability13_governance_request",
        "create_capability13_report_request",
        "decide_capability13_governance_request",
        "decide_capability13_report_publication",
        "download_capability13_export_artifact",
        "download_capability13_report_artifact",
        "get_capability13_cockpit_snapshot",
        "get_capability13_evidence_export_request",
        "get_capability13_report",
        "issue_capability13_export_grant",
        "list_capability13_attempts",
        "list_capability13_engagements",
        "list_capability13_projection",
        "place_capability13_export_legal_hold",
        "register_capability13_export_policy_bundle",
        "register_capability13_recipient_key",
        "release_capability13_export_legal_hold",
        "revoke_capability13_recipient_key",
        "rotate_capability13_recipient_key",
        "stream_capability13_cockpit",
    }
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


def _schema_property_names(value: Any) -> set[str]:
    """Collect wire-field names without treating safe prose/enums as secrets."""

    names: set[str] = set()
    if isinstance(value, dict):
        properties = value.get("properties")
        if isinstance(properties, dict):
            names.update(str(name).lower() for name in properties)
        for child in value.values():
            names.update(_schema_property_names(child))
    elif isinstance(value, list):
        for child in value:
            names.update(_schema_property_names(child))
    return names


def _c13_operations(path: str, operations: dict[str, Any]) -> dict[str, Any]:
    if not path.startswith(PATH_PREFIX):
        return {}
    selected: dict[str, Any] = {}
    for method, operation in operations.items():
        if method.lower() not in {"get", "post", "put", "patch", "delete"}:
            continue
        if isinstance(operation, dict) and "capability13" in str(
            operation.get("operationId", "")
        ):
            selected[method] = operation
    return selected


def extract_capability13(document: dict[str, Any]) -> dict[str, Any]:
    paths = {
        path: selected
        for path, operations in sorted(document.get("paths", {}).items())
        if (selected := _c13_operations(path, operations))
    }
    operation_names = {
        str(operation["operationId"]).split("_api_v1_pentesting_", 1)[0]
        for operations in paths.values()
        for operation in operations.values()
    }
    if operation_names != REQUIRED_OPERATION_NAMES:
        raise ValueError("PENTEST_C13_OPENAPI_PATH_SET_MISMATCH")

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
            raise ValueError(f"PENTEST_C13_OPENAPI_SCHEMA_MISSING:{name}")
        selected[name] = schema
        pending.update(_schema_refs(schema) - selected.keys())

    wire_fields = _schema_property_names({"paths": paths, "schemas": selected})
    leaked = sorted(
        term
        for term in FORBIDDEN_SCHEMA_TERMS
        if any(term in field for field in wire_fields)
    )
    if leaked:
        raise ValueError(
            f"PENTEST_C13_OPENAPI_PROTECTED_FIELD:{','.join(leaked)}"
        )
    return {
        "openapi": document["openapi"],
        "info": {
            "title": "SCCAP Capability 13 API",
            "version": "c13.v1",
            "description": (
                "Safe cockpit, immutable report metadata, governance, retest, "
                "and delta contracts. Protected evidence and storage details "
                "are excluded."
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
    extracted = extract_capability13(source)
    args.destination.write_text(
        json.dumps(extracted, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
