"""Deterministic finding lineage and policy-gate semantics.

This module is intentionally free of database and web concerns.  The worker,
API, reports, and portfolio queries all consume the same persisted vocabulary
defined here so a finding cannot be "new" in one surface and "unchanged" in
another.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence


BASELINE_STATES = frozenset({"new", "fixed", "unchanged", "reintroduced"})
SEVERITY_RANK = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


def _normalized_text(value: object) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip()).casefold()


def finding_fingerprint(finding: Mapping[str, Any] | object) -> str:
    """Return a cross-scan identity based on producer and vulnerable site.

    Scan-local raw/canonical UUIDs are deliberately excluded.  Exact line
    numbers are also excluded because harmless edits above a finding must not
    turn it into a new issue.  Repeated vulnerable snippets in different files
    remain distinct.
    """

    def get(name: str, default: object = None) -> object:
        if isinstance(finding, Mapping):
            return finding.get(name, default)
        return getattr(finding, name, default)

    source = _normalized_text(get("source") or "agent")
    rule = _normalized_text(get("scanner_rule_id") or get("cve_id") or get("cwe"))
    path = str(get("file_path") or "").replace("\\", "/").lstrip("./")
    snippet = _normalized_text(get("vulnerable_snippet"))
    # Legacy/file-level findings may not carry snippets or rule IDs.  Title is
    # the final deterministic fallback, never a preferred identity component.
    fallback = "" if (rule or snippet) else _normalized_text(get("title"))
    payload = json.dumps(
        ["finding-baseline-v1", source, rule, path, snippet, fallback],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def classify_baseline(
    current_fingerprints: Iterable[str],
    previous_fingerprints: Iterable[str],
    historical_fingerprints: Iterable[str],
) -> tuple[dict[str, str], set[str]]:
    """Classify current identities and return identities fixed since baseline."""

    current = set(current_fingerprints)
    previous = set(previous_fingerprints)
    historical = set(historical_fingerprints)
    states: dict[str, str] = {}
    for fingerprint in sorted(current):
        if fingerprint in previous:
            states[fingerprint] = "unchanged"
        elif fingerprint in historical:
            states[fingerprint] = "reintroduced"
        else:
            states[fingerprint] = "new"
    return states, previous - current


def exact_ranges(finding: Mapping[str, Any] | object) -> list[dict[str, Any]]:
    """Project primary and consolidated locations into exact source ranges."""

    def get(name: str, default: object = None) -> object:
        if isinstance(finding, Mapping):
            return finding.get(name, default)
        return getattr(finding, name, default)

    primary_path = str(get("file_path") or "")
    locations: list[dict[str, Any]] = [
        {
            "file_path": primary_path,
            "line_number": int(get("line_number") or 0),
            "snippet": get("vulnerable_snippet"),
            "primary": True,
        }
    ]
    for raw in get("affected_locations", []) or []:
        if not isinstance(raw, Mapping):
            continue
        locations.append(
            {
                "file_path": str(raw.get("file_path") or primary_path),
                "line_number": int(raw.get("line_number") or 0),
                "snippet": raw.get("snippet") or raw.get("vulnerable_snippet"),
                "primary": False,
            }
        )
    ranges: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for location in locations:
        snippet = str(location.get("snippet") or "")
        start_line = max(0, int(location["line_number"]))
        line_count = max(1, len(snippet.splitlines())) if snippet else 1
        key = (location["file_path"], start_line, snippet)
        if key in seen:
            continue
        seen.add(key)
        ranges.append(
            {
                **location,
                "start_line": start_line,
                "end_line": start_line + line_count - 1 if start_line else 0,
                "start_column": 1 if start_line else 0,
                "end_column": (
                    len(snippet.splitlines()[-1]) + 1 if snippet and start_line else 0
                ),
            }
        )
    return ranges


@dataclass(frozen=True)
class GatePolicy:
    minimum_severity: str = "high"
    minimum_confidence: str = "medium"
    require_complete_coverage: bool = True
    allow_waivers: bool = True
    minimum_waiver_remaining_hours: int = 0


def finding_matches_gate(
    finding: Mapping[str, Any] | object,
    policy: GatePolicy,
) -> bool:
    def get(name: str, default: object = None) -> object:
        if isinstance(finding, Mapping):
            return finding.get(name, default)
        return getattr(finding, name, default)

    severity = SEVERITY_RANK.get(str(get("severity") or "").casefold(), -1)
    confidence = CONFIDENCE_RANK.get(str(get("confidence") or "").casefold(), -1)
    return (
        severity >= SEVERITY_RANK[policy.minimum_severity.casefold()]
        and confidence >= CONFIDENCE_RANK[policy.minimum_confidence.casefold()]
    )


def waiver_is_eligible(
    *,
    expires_at: datetime,
    policy: GatePolicy,
    now: datetime | None = None,
) -> bool:
    if not policy.allow_waivers:
        return False
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    expiry = expires_at
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    remaining_seconds = (expiry - current).total_seconds()
    return remaining_seconds > policy.minimum_waiver_remaining_hours * 3600


def evaluate_gate(
    findings: Sequence[Mapping[str, Any] | object],
    *,
    policy: GatePolicy,
    coverage_complete: bool,
    waived_fingerprints: set[str] | frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Evaluate the canonical persisted policy result for one scan."""

    blocking: list[str] = []
    waived: list[str] = []
    for finding in findings:
        if not finding_matches_gate(finding, policy):
            continue
        fingerprint = finding_fingerprint(finding)
        if policy.allow_waivers and fingerprint in waived_fingerprints:
            waived.append(fingerprint)
        else:
            blocking.append(fingerprint)
    coverage_failed = policy.require_complete_coverage and not coverage_complete
    return {
        "outcome": "fail" if blocking or coverage_failed else "pass",
        "blocking_fingerprints": sorted(set(blocking)),
        "waived_fingerprints": sorted(set(waived)),
        "coverage_complete": coverage_complete,
        "coverage_failed": coverage_failed,
        "evaluated_finding_count": len(findings),
    }
