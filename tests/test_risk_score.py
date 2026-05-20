# tests/test_risk_score.py
"""Unit tests for `app.shared.lib.risk_score.compute_cvss_aggregate`.

The aggregator is pure-Python (no DB, no I/O) so these tests run
without any docker / fixture scaffolding. They guard the eight
mitigations from the cvss-weighted-risk-score threat model: each
malformed-input path falls through cleanly, the function never raises,
WARN logs do not echo attacker-controlled finding content, and the
function is incapable of opening a DB session or mutating its inputs.
"""

from __future__ import annotations

import logging
from copy import deepcopy
from dataclasses import dataclass
from typing import Optional

from app.shared.lib.risk_score import (
    MAX_FINDINGS,
    SEVERITY_WEIGHT,
    compute_cvss_aggregate,
    to_posture_score,
)


@dataclass
class _F:
    """Test double — duck-typed to the aggregator's protocol."""

    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    id: Optional[int] = None


# A valid CVSS 3.1 vector for an SSRF-class issue (base score ~9.8).
VALID_CVSS_31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
# A valid CVSS 3.0 vector with a different score (~6.5).
VALID_CVSS_30 = "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"
# Threat-model abuse case 1 — well-formed prefix but invalid metric value.
INJECTED_BAD_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:CHANGED-MANIFOLD/C:H/I:H/A:H"


def test_empty_returns_zero():
    """B2 / M5 — empty input returns 0.0, never raises."""
    assert compute_cvss_aggregate([]) == 0.0


def test_all_null_vectors_falls_to_severity_weights():
    """B3 / M5 — with no CVSS data, severity weights drive the score.
    The weighted average reflects the mix: CRITICAL(9.5×4) + MEDIUM(5.0×2)
    + LOW(2.5×1) / 7 ≈ 7.2."""
    findings = [
        _F(severity="CRITICAL"),
        _F(severity="MEDIUM"),
        _F(severity="LOW"),
    ]
    result = compute_cvss_aggregate(findings)
    # Weighted avg: (9.5*4 + 5.0*2 + 2.5*1) / (4+2+1) = 50.5/7 ≈ 7.2
    assert 7.0 <= result <= 7.5


def test_malformed_vector_falls_back_to_score_and_warn_log_is_clean(caplog):
    """B4 / M1 + M2 + M5 — a malformed vector must (a) not raise,
    (b) fall back to the numeric `cvss_score`, (c) emit a WARN that
    contains the finding id but never the LLM-emitted description /
    title / file_path content."""
    sentinel_description = "DO_NOT_LOG_THIS_DESCRIPTION"
    sentinel_title = "DO_NOT_LOG_THIS_TITLE"
    sentinel_path = "/tmp/DO_NOT_LOG_THIS_PATH.py"
    finding = _F(
        severity="HIGH",
        cvss_score=4.2,
        cvss_vector=INJECTED_BAD_VECTOR,
        id=12345,
    )
    # Smuggle attacker-controlled fields in a way the aggregator must
    # never consume — set them as attributes too, just in case.
    finding.description = sentinel_description  # type: ignore[attr-defined]
    finding.title = sentinel_title  # type: ignore[attr-defined]
    finding.file_path = sentinel_path  # type: ignore[attr-defined]

    with caplog.at_level(logging.WARNING, logger="app.shared.lib.risk_score"):
        result = compute_cvss_aggregate([finding], scan_id="scan-abc")

    # Fallback to cvss_score takes effect.
    assert result == 4.2

    warn_records = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warn_records, "expected one WARN for the malformed vector"
    rendered = "\n".join(r.getMessage() for r in warn_records)
    assert "12345" in rendered, "WARN should include the finding id"
    assert sentinel_description not in rendered
    assert sentinel_title not in rendered
    assert sentinel_path not in rendered


def test_mixed_cvss_30_and_31_parse_cleanly():
    """B5 / M5 — both CVSS 3.0 and 3.1 vectors are accepted by the same
    parser; both contribute their parsed scores to the weighted average."""
    findings = [
        _F(severity="HIGH", cvss_vector=VALID_CVSS_31),  # ~9.8
        _F(severity="HIGH", cvss_vector=VALID_CVSS_30),  # ~6.5
    ]
    result = compute_cvss_aggregate(findings)
    # Weighted avg of ~9.8 and ~6.5 (both weight 4): ~8.15
    assert 7.5 <= result <= 9.0


def test_multi_tenant_isolation_and_input_purity():
    """B6 / M3 + M5 — the function must not mutate inputs and must not
    cross-contaminate state between calls (each tenant scored independently)."""
    tenant_a = [_F(severity="CRITICAL", cvss_vector=VALID_CVSS_31)]
    tenant_b = [_F(severity="LOW")]

    snapshot_a = deepcopy(tenant_a)
    snapshot_b = deepcopy(tenant_b)

    score_a = compute_cvss_aggregate(tenant_a)
    score_b = compute_cvss_aggregate(tenant_b)

    # Each tenant's score reflects only its own findings.
    assert score_a >= 9.0
    assert score_b == SEVERITY_WEIGHT["LOW"]
    assert score_a != score_b

    # Inputs are unchanged.
    assert tenant_a == snapshot_a
    assert tenant_b == snapshot_b


def test_function_has_no_db_or_io_attribute_surface():
    """M3 — the function signature is `(Sequence[Any], *, scan_id) -> float`;
    it must not introspect or accept a `db` / session attribute on a
    finding even if one is present."""
    finding = _F(severity="CRITICAL")
    finding.db = "should_be_ignored"  # type: ignore[attr-defined]
    finding.session = "should_be_ignored"  # type: ignore[attr-defined]
    # No exception, no I/O — just scores via severity weight.
    score = compute_cvss_aggregate([finding])
    assert score == SEVERITY_WEIGHT["CRITICAL"]


def test_truncation_at_max_findings_warns_and_keeps_highest_severity(caplog):
    """B7 / M4 — passing more than MAX_FINDINGS items produces a WARN
    and the aggregator scores only the highest-severity slice.  The
    single CRITICAL + thousands of LOWs must lift the weighted average
    above a pure-LOW baseline (2.5)."""
    # MAX_FINDINGS+10 LOWs with 50 CRITICALs buried at the tail.
    # Severity-rank-desc truncation keeps them; FIFO would drop them.
    bulk = [_F(severity="LOW") for _ in range(MAX_FINDINGS + 10)]
    for i in range(1, 51):
        bulk[-i] = _F(severity="CRITICAL")

    with caplog.at_level(logging.WARNING, logger="app.shared.lib.risk_score"):
        result = compute_cvss_aggregate(bulk, scan_id="big-tenant")

    # With truncation keeping the CRITICAL, the weighted average edges
    # above pure LOW (2.5).  If truncation dropped it, the result would
    # equal SEVERITY_WEIGHT["LOW"] exactly.
    assert result > SEVERITY_WEIGHT["LOW"]
    assert any("truncated" in r.getMessage() for r in caplog.records)


def test_invalid_severity_string_falls_to_zero():
    """Defensive — unknown severity strings normalize to 0.0, no raise."""
    finding = _F(severity="MOSTLY_HARMLESS")
    assert compute_cvss_aggregate([finding]) == 0.0


def test_negative_or_out_of_range_cvss_score_is_rejected():
    """Defensive — `cvss_score` outside [0.0, 10.0] is treated as missing
    and falls through to severity weight."""
    finding = _F(severity="HIGH", cvss_score=42.0)
    assert compute_cvss_aggregate([finding]) == SEVERITY_WEIGHT["HIGH"]


def test_to_posture_score_round_trip():
    """`to_posture_score` clamps to [5, 100] and is monotonic."""
    assert to_posture_score(0.0) == 100
    assert to_posture_score(10.0) == 5  # 100 - min(95, 100) = 5
    assert to_posture_score(5.0) == 50
    # Higher risk -> lower posture.
    assert to_posture_score(7.5) < to_posture_score(2.5)


def test_never_raises_on_completely_empty_finding():
    """Belt-and-braces — a finding with every field None still scores 0.0."""
    finding = _F()
    assert compute_cvss_aggregate([finding]) == 0.0


# --- scoreable_findings filter (PRD #96 / #99) --------------------------

from app.shared.lib.risk_score import scoreable_findings  # noqa: E402


@dataclass
class _FD:
    """Test double exposing a `disposition`, for the scoreable filter."""

    disposition: str
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    id: Optional[int] = None


def test_scoreable_findings_keeps_open_and_confirmed():
    findings = [_FD("open"), _FD("confirmed")]
    assert scoreable_findings(findings) == findings


def test_scoreable_findings_drops_resolved_states():
    findings = [
        _FD("open"),
        _FD("false_positive"),
        _FD("remediated"),
        _FD("risk_accepted"),
        _FD("confirmed"),
    ]
    kept = scoreable_findings(findings)
    assert [f.disposition for f in kept] == ["open", "confirmed"]


def test_scoreable_findings_keeps_objects_without_disposition_attr():
    # Legacy finding-like objects with no `disposition` must be kept —
    # a missing field must never silently hide a finding from the score.
    findings = [_F(severity="HIGH")]
    assert scoreable_findings(findings) == findings


def test_score_drops_to_zero_when_only_finding_is_dispositioned():
    # The behaviour #99 guarantees: triaging a finding away lowers the
    # risk score. A lone Critical scored ~9.8 → 0.0 once resolved.
    crit = _FD("open", cvss_vector=VALID_CVSS_31)
    before = compute_cvss_aggregate(scoreable_findings([crit]))
    assert before > 9.0
    crit.disposition = "false_positive"
    after = compute_cvss_aggregate(scoreable_findings([crit]))
    assert after == 0.0
