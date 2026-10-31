"""Deterministically extract the safe Capability 9 OpenAPI surface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

C9_PATH_SUFFIXES = (
    "/coverage",
    "/methodology-migrations",
    "/methodology-pin",
    "/operations",
    "/source-handoff-v2",
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


def extract_capability9(document: dict[str, Any]) -> dict[str, Any]:
    paths = {
        path: document["paths"][path]
        for path in sorted(document["paths"])
        if path.startswith("/api/v1/pentesting/")
        and path.endswith(C9_PATH_SUFFIXES)
    }
    if len(paths) != len(C9_PATH_SUFFIXES):
        raise ValueError("PENTEST_C9_OPENAPI_PATH_SET_MISMATCH")

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
            raise ValueError(f"PENTEST_C9_OPENAPI_SCHEMA_MISSING:{name}")
        selected[name] = schema
        pending.update(_schema_refs(schema) - selected.keys())

    return {
        "openapi": document["openapi"],
        "info": {
            "title": "SCCAP Capability 9 API",
            "version": "c9.v1",
            "description": (
                "Safe read and methodology-migration contracts for Capability 9; "
                "contains no credentials, raw evidence, source bodies, or target authority."
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
    extracted = extract_capability9(source)
    args.destination.write_text(
        json.dumps(extracted, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
