"""Deterministically extract the safe Capability 10 OpenAPI surface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

C10_PATHS = (
    "/api/v1/pentesting/engagements/{engagement_id}/interaction-boundaries",
    "/api/v1/pentesting/engagements/{engagement_id}/interaction-boundaries/{generation}/revoke",
    "/api/v1/pentesting/engagements/{engagement_id}/attempts/{attempt_id}/mutations",
    "/api/v1/pentesting/engagements/{engagement_id}/attempts/{attempt_id}/mutations/{mutation_id}",
    "/api/v1/pentesting/engagements/{engagement_id}/attempts/{attempt_id}/cleanup-obligations",
    "/api/v1/pentesting/engagements/{engagement_id}/attempts/{attempt_id}/cleanup-obligations/{obligation_id}/retry",
    "/api/v1/pentesting/engagements/{engagement_id}/attempts/{attempt_id}/cleanup-obligations/{obligation_id}/manual-evidence",
    "/api/v1/pentesting/engagements/{engagement_id}/attempts/{attempt_id}/cleanup-summary",
    "/api/v1/pentesting/engagements/{engagement_id}/attempts/{attempt_id}/resource-locks",
)
SCHEMA_PREFIX = "#/components/schemas/"


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


def extract_capability10(document: dict[str, Any]) -> dict[str, Any]:
    available_paths = document.get("paths", {})
    missing = sorted(set(C10_PATHS) - set(available_paths))
    if missing:
        raise ValueError(f"PENTEST_C10_OPENAPI_PATH_SET_MISMATCH:{','.join(missing)}")
    paths = {path: available_paths[path] for path in C10_PATHS}

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
            raise ValueError(f"PENTEST_C10_OPENAPI_SCHEMA_MISSING:{name}")
        selected[name] = schema
        pending.update(_schema_refs(schema) - selected.keys())

    return {
        "openapi": document["openapi"],
        "info": {
            "title": "SCCAP Capability 10 API",
            "version": "c10.v1",
            "description": (
                "Safe mutation-governance, cleanup, lock and restoration projections; "
                "contains no credentials, raw target traffic, sensitive prior state, "
                "restoration values or target-execution authority."
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
    extracted = extract_capability10(source)
    args.destination.write_text(
        json.dumps(extracted, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
