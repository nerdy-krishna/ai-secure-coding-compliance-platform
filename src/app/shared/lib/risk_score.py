"""Unified CVSS-weighted risk score.

`compute_cvss_aggregate(findings)` is the single source of truth for
SCCAP's per-scan and per-tenant risk numbers. It returns a float in
``[0.0, 10.0]`` (CVSS 3.x scale, one decimal). Callers adapt as needed:

- ``save_final_report_node`` rounds to ``int`` for the ``Scan.risk_score``
  ``Integer`` column (precision loss of <=0.5 is acceptable; widening
  the column is a deferred follow-up).
- ``DashboardService._risk_score`` and ``ComplianceService._score_from_aggregate``
  map the aggregate to the existing 0-100 posture scale via
  ``max(5, 100 - min(95, round(aggregate * 10)))`` so API JSON shapes
  are unchanged.

The function is pure-Python, takes a ``Sequence[Any]`` (duck-typed on
``severity``, ``cvss_score``, ``cvss_vector``), opens no DB session,
makes no network calls, and never raises. Bad inputs cascade through a
strict fallback ladder: parsed CVSS vector -> numeric ``cvss_score``
-> severity-tier weight -> ``0.0``.
"""

from __future__ import annotations

import logging
from typing import Any, Optional, Sequence

from cvss import CVSS3
from cvss.exceptions import CVSSError

logger = logging.getLogger(__name__)


SEVERITY_WEIGHT: dict[str, float] = {
    "CRITICAL": 9.5,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 2.5,
    "INFORMATIONAL": 0.0,
    "INFO": 0.0,
    "NONE": 0.0,
}

# Defends both the worker thread (per-scan: usually <100 findings) and the
# FastAPI event loop (dashboard/compliance: scope-wide). Above this cap the
# aggregator logs a WARN and scores the highest-severity slice only.
MAX_FINDINGS = 5_000

# Severity rank for truncation ordering when len(findings) > MAX_FINDINGS.
_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _normalize_severity(raw: Any) -> str:
    if raw is None:
        return "NONE"
    return str(raw).upper().strip()


def _severity_rank(finding: Any) -> int:
    return _SEVERITY_RANK.get(
        _normalize_severity(getattr(finding, "severity", None)), 0
    )


def _severity_weight_for_score(score: float) -> int:
    """Tier weight used in the weighted average so a flood of LOWs cannot
    drown a single CRITICAL. CVSS thresholds mirror the standard severity
    bands (>=9.0 Critical, >=7.0 High, >=4.0 Medium, else Low/None).
    """
    if score >= 9.0:
        return 4
    if score >= 7.0:
        return 3
    if score >= 4.0:
        return 2
    return 1


def _parse_vector(vector: Optional[str]) -> Optional[float]:
    """Parse a CVSS 3.x vector string and return the base score, or None
    on any error. Never raises. The cvss library handles both
    ``CVSS:3.0/...`` and ``CVSS:3.1/...`` via the same constructor.
    """
    if not vector:
        return None
    try:
        # CVSS3.scores() returns (base, temporal, environmental).
        base = CVSS3(vector).scores()[0]
        return float(base)
    except (CVSSError, ValueError, KeyError, IndexError, TypeError):
        return None


def _coerce_score(raw: Any) -> Optional[float]:
    if raw is None:
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    if value < 0.0 or value > 10.0:
        return None
    return value


def _score_for(finding: Any, log_context: dict[str, Any]) -> tuple[float, bool]:
    """Resolve a single finding's score via the fallback ladder.

    Returns ``(score, was_unparseable)`` where ``was_unparseable`` is
    True when the supplied ``cvss_vector`` failed to parse and we had to
    fall back. Used for telemetry only.
    """
    vector = getattr(finding, "cvss_vector", None)
    parsed = _parse_vector(vector)
    if parsed is not None:
        return parsed, False

    unparseable = bool(vector)  # we tried to parse, it failed
    if unparseable:
        # Threat-model M2: log only finding id + truncated vector.
        # Never echo description / title / file_path — those are
        # LLM-emitted from attacker-controlled code.
        finding_id = getattr(finding, "id", None)
        truncated = str(vector)[:100]
        logger.warning(
            "compute_cvss_aggregate: malformed cvss_vector finding_id=%s scan_id=%s vector=%r",
            finding_id,
            log_context.get("scan_id"),
            truncated,
        )

    coerced = _coerce_score(getattr(finding, "cvss_score", None))
    if coerced is not None:
        return coerced, unparseable

    weight = SEVERITY_WEIGHT.get(
        _normalize_severity(getattr(finding, "severity", None)), 0.0
    )
    return weight, unparseable


def compute_cvss_aggregate(
    findings: Sequence[Any],
    *,
    scan_id: Any = None,
) -> float:
    """Compute a single CVSS-weighted score for a list of findings.

    Args:
        findings: Sequence of finding-like objects exposing ``severity``,
            ``cvss_score``, ``cvss_vector`` (and optionally ``id``).
            Both ORM ``Finding`` rows and Pydantic ``VulnerabilityFinding``
            instances satisfy this protocol.
        scan_id: Optional context value included in WARN logs.

    Returns:
        A float in ``[0.0, 10.0]``, rounded to one decimal. Empty input
        returns ``0.0``. The function never raises.
    """
    if not findings:
        return 0.0

    truncated = False
    if len(findings) > MAX_FINDINGS:
        # Sort severity-desc so the highest-impact findings always make
        # the cut. Stable sort preserves arrival order within a tier.
        findings = sorted(findings, key=_severity_rank, reverse=True)[:MAX_FINDINGS]
        truncated = True

    log_context: dict[str, Any] = {"scan_id": scan_id}
    scores: list[float] = []
    n_unparseable = 0
    for finding in findings:
        score, was_unparseable = _score_for(finding, log_context)
        scores.append(score)
        if was_unparseable:
            n_unparseable += 1

    if not scores:
        return 0.0

    highest = max(scores)
    weights = [_severity_weight_for_score(s) for s in scores]
    total_weight = sum(weights)
    if total_weight <= 0:
        weighted_avg = 0.0
    else:
        weighted_avg = sum(s * w for s, w in zip(scores, weights)) / total_weight

    aggregate = max(highest, weighted_avg)
    aggregate = max(0.0, min(10.0, aggregate))

    if truncated:
        logger.warning(
            "compute_cvss_aggregate truncated scan_id=%s n=%s cap=%s",
            scan_id,
            MAX_FINDINGS,
            MAX_FINDINGS,
        )
    logger.info(
        "computed cvss aggregate scan_id=%s score=%.1f n=%s n_unparseable=%s",
        scan_id,
        aggregate,
        len(scores),
        n_unparseable,
    )
    return round(aggregate, 1)


def to_posture_score(aggregate: float) -> int:
    """Map a 0.0-10.0 risk aggregate to the legacy 0-100 posture score.

    The 5-floor and 100-ceiling preserve the existing dashboard /
    compliance heuristics so API JSON shapes do not change.
    """
    return max(5, 100 - min(95, round(aggregate * 10)))


def scoreable_findings(findings: Sequence[Any]) -> list[Any]:
    """Filter to the findings that count toward the risk score — those
    whose triage disposition is `open` or `confirmed` (PRD #96 / #99).

    `false_positive` / `remediated` / `risk_accepted` findings are
    dropped. A finding with no `disposition` attribute (legacy callers,
    pre-#96 finding-like objects) is kept — a missing field must never
    silently hide a finding from the score. `compute_cvss_aggregate`
    itself stays disposition-agnostic; callers filter through this.
    """
    from app.shared.lib.finding_disposition import is_scoreable

    out: list[Any] = []
    for finding in findings:
        disposition = getattr(finding, "disposition", None)
        if disposition is None or is_scoreable(str(disposition)):
            out.append(finding)
    return out
