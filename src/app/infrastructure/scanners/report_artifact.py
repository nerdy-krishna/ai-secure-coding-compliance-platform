"""Bounds and normalizes native scanner output before JSONB persistence."""

from __future__ import annotations

import json
from typing import Any

MAX_NATIVE_REPORT_BYTES = 5 * 1024 * 1024


def scanner_completion_status(expected_to_run: bool, report_available: bool) -> str:
    """Project scanner execution evidence into an operator-facing status."""
    if not expected_to_run:
        return "skipped"
    if not report_available:
        return "degraded"
    return "completed"


def bounded_native_report(payload: Any) -> Any:
    """Keep native scanner evidence useful without unbounded JSONB growth."""
    try:
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError):
        return {"available": False, "reason": "report_not_json_serializable"}
    if len(encoded) <= MAX_NATIVE_REPORT_BYTES:
        return payload
    return {
        "available": False,
        "truncated": True,
        "original_bytes": len(encoded),
        "reason": "native_report_exceeded_5_mib_limit",
    }
