"""Validate measured Task24 cluster/load/DR evidence against its contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pydantic import ValidationError

from app.shared.lib.resilience_contract import (
    ResilienceEvidenceSuite,
    evaluate_suite,
)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", nargs="?", type=Path)
    parser.add_argument(
        "--schema",
        action="store_true",
        help="print the evidence JSON Schema instead of validating a run",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    if args.schema:
        print(
            json.dumps(
                ResilienceEvidenceSuite.model_json_schema(), indent=2, sort_keys=True
            )
        )
        return 0
    if args.evidence is None:
        raise SystemExit("evidence path is required unless --schema is used")

    try:
        suite = ResilienceEvidenceSuite.model_validate_json(
            args.evidence.read_text(encoding="utf-8")
        )
    except (OSError, ValidationError) as exc:
        print(json.dumps({"passed": False, "contract_error": str(exc)}, indent=2))
        return 2

    result = evaluate_suite(suite)
    print(result.model_dump_json(indent=2))
    return 0 if result.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
