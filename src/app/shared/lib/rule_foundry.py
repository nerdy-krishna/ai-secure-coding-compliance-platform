"""Pure policy primitives for the governed AI rule foundry."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Mapping, Sequence


STATIC_PREDICATES = frozenset({"ast", "taint", "dependency_advisory", "secret_pattern"})
REGISTRY_FOR_PREDICATE = {
    "ast": "semgrep",
    "taint": "semgrep",
    "dependency_advisory": "osv",
    "secret_pattern": "gitleaks",
}
UNPROMOTED_TTL = timedelta(days=30)
SHADOW_REVIEW_TTL = timedelta(days=90)
PROMOTED_FAILURE_WINDOW = timedelta(hours=24)
PROMOTED_FAILURE_THRESHOLD = 3


class RuleFoundryPolicyError(ValueError):
    pass


@dataclass(frozen=True)
class RepresentabilityDecision:
    static_representable: bool
    registry_kind: str
    reason: str | None


@dataclass(frozen=True)
class QualityMetrics:
    vulnerable_total: int
    vulnerable_detected: int
    fixed_total: int
    fixed_clean: int
    negative_total: int
    negative_clean: int
    duplicate_stable_identities: int
    deterministic_run_hashes: tuple[str, ...]
    performance_fixture_count: int
    churn_fixture_count: int
    churn_stable: int
    baseline_median_ms: Decimal
    candidate_median_ms: Decimal
    p95_file_ms: Decimal

    def as_json(self) -> dict[str, Any]:
        value = asdict(self)
        value["baseline_median_ms"] = str(self.baseline_median_ms)
        value["candidate_median_ms"] = str(self.candidate_median_ms)
        value["p95_file_ms"] = str(self.p95_file_ms)
        return value


def decide_representability(
    *,
    predicate_kind: str,
    bounded: bool,
    uses_project_specific_names: bool,
    requires_hidden_runtime_state: bool,
) -> RepresentabilityDecision:
    reasons: list[str] = []
    if predicate_kind not in STATIC_PREDICATES:
        reasons.append("predicate requires semantic or runtime reasoning")
    if not bounded:
        reasons.append("predicate is not bounded")
    if uses_project_specific_names:
        reasons.append("predicate depends on project-specific names")
    if requires_hidden_runtime_state:
        reasons.append("predicate depends on hidden runtime state")
    if reasons:
        return RepresentabilityDecision(False, "ai_dataflow", "; ".join(reasons))
    return RepresentabilityDecision(True, REGISTRY_FOR_PREDICATE[predicate_kind], None)


def assert_quality_gates(metrics: QualityMetrics) -> None:
    failures: list[str] = []
    if metrics.vulnerable_total < 1 or metrics.vulnerable_detected != metrics.vulnerable_total:
        failures.append("vulnerable fixtures must be detected at 100%")
    if metrics.fixed_total < 1 or metrics.fixed_clean != metrics.fixed_total:
        failures.append("fixed fixtures must be clean at 100%")
    if metrics.negative_total < 1 or metrics.negative_clean != metrics.negative_total:
        failures.append("negative fixtures must be clean at 100%")
    if metrics.duplicate_stable_identities != 0:
        failures.append("duplicate stable identities must be zero")
    hashes = metrics.deterministic_run_hashes
    if len(hashes) < 3 or len(set(hashes[:3])) != 1:
        failures.append("output must be deterministic across three runs")
    if metrics.performance_fixture_count < 1:
        failures.append("at least one performance fixture is required")
    if metrics.churn_fixture_count < 1 or metrics.churn_stable != metrics.churn_fixture_count:
        failures.append("all churn fixtures must preserve stable identity")
    if metrics.baseline_median_ms <= 0:
        failures.append("baseline median must be positive")
    elif metrics.candidate_median_ms > metrics.baseline_median_ms * Decimal("2"):
        failures.append("candidate median runtime exceeds 2x baseline")
    if metrics.p95_file_ms >= Decimal("500"):
        failures.append("p95 per-file runtime must be below 500 ms")
    if failures:
        raise RuleFoundryPolicyError("; ".join(failures))


def assert_shadow_gate(*, eligible_files: int, unexpected_matches: int) -> None:
    if eligible_files < 100:
        raise RuleFoundryPolicyError("shadow gate requires at least 100 eligible files")
    if unexpected_matches < 0 or unexpected_matches > eligible_files:
        raise RuleFoundryPolicyError("invalid shadow observation counts")
    if Decimal(unexpected_matches) / Decimal(eligible_files) > Decimal("0.01"):
        raise RuleFoundryPolicyError("shadow unexpected-match rate exceeds 1%")


def sustained_promoted_failure_requires_review(distinct_scans: int) -> bool:
    """Avoid demoting a promoted rule for a single transient scanner failure."""

    return distinct_scans >= PROMOTED_FAILURE_THRESHOLD


def canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=_canonical_default,
    ).encode("utf-8")


def _canonical_default(value: Any) -> str:
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    return str(value)


def canonical_digest(value: Mapping[str, Any]) -> tuple[bytes, str]:
    encoded = canonical_json(value)
    return encoded, hashlib.sha256(encoded).hexdigest()


def stable_identity(*, registry_kind: str, payload: Mapping[str, Any]) -> str:
    _encoded, digest = canonical_digest({"registry": registry_kind, "payload": payload})
    return digest


def candidate_expiry(now: datetime | None = None) -> datetime:
    return (now or datetime.now(timezone.utc)) + UNPROMOTED_TTL


def shadow_review_due(now: datetime | None = None) -> datetime:
    return (now or datetime.now(timezone.utc)) + SHADOW_REVIEW_TTL


def normalize_hashes(hashes: Sequence[str]) -> tuple[str, ...]:
    return tuple(str(value)[:64] for value in hashes)
