"""FindingConsolidator — one finding per real issue (#72).

The reasoning LLM is mocked: the consolidator takes an injected
client, so these tests exercise merge / drop / passthrough shaping and
CVSS re-assessment without any real LLM call.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from app.core.schemas import VulnerabilityFinding
from app.infrastructure.agents.finding_consolidator import (
    FindingConsolidator,
    _ConsolidatedLocation,
    _ConsolidationResponse,
    _MergedFinding,
)

# A CVSS 3.1 vector that scores 9.8 (Critical).
_CRIT_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

_SOURCE = "def q(u):\n    return db.execute('SELECT * FROM t WHERE x=' + u)\n"


def _raw(**over) -> VulnerabilityFinding:
    base = dict(
        title="SQL injection",
        description="Untrusted input concatenated into a query.",
        severity="High",
        line_number=2,
        remediation="Use parameterised queries.",
        confidence="Medium",
        file_path="app.py",
        references=[],
        agent_name="InjectionAgent",
    )
    base.update(over)
    return VulnerabilityFinding(**base)


class _FakeClient:
    """Stand-in reasoning LLM client."""

    def __init__(self, response=None, error=None, raises=False):
        self._response = response
        self._error = error
        self._raises = raises

    async def generate_structured_output(
        self, prompt, response_model, system_prompt=None
    ):
        if self._raises:
            raise RuntimeError("reasoning LLM unreachable")
        return SimpleNamespace(parsed_output=self._response, error=self._error)


def _consolidate(client, findings):
    consolidator = FindingConsolidator(client)
    return asyncio.run(consolidator.consolidate_file("app.py", _SOURCE, findings))


def test_duplicates_merge_into_one_root_finding():
    raw = [
        _raw(agent_name="InjectionAgent"),
        _raw(agent_name="ApiAgent", title="Unsanitised SQL", line_number=2),
    ]
    response = _ConsolidationResponse(
        merged_findings=[
            _MergedFinding(
                subsumed_finding_numbers=[1, 2],
                title="SQL injection in q()",
                description="Root cause: user input is concatenated into SQL.",
                remediation="Use a parameterised query.",
                cvss_vector=_CRIT_VECTOR,
                primary_line_number=2,
                affected_locations=[_ConsolidatedLocation(line_number=2)],
            )
        ],
        dropped_finding_numbers=[],
    )
    result = _consolidate(_FakeClient(response=response), raw)
    assert len(result) == 1
    finding = result[0]
    assert finding.title == "SQL injection in q()"
    # Provenance from both subsumed findings is unioned.
    assert finding.corroborating_agents == ["ApiAgent", "InjectionAgent"]
    # >1 subsumed finding => corroborated => High confidence.
    assert finding.confidence == "High"
    assert finding.id is None


def test_cvss_is_reassessed_and_severity_follows_the_band():
    raw = [_raw(severity="Low")]
    response = _ConsolidationResponse(
        merged_findings=[
            _MergedFinding(
                subsumed_finding_numbers=[1],
                title="t",
                description="d",
                remediation="r",
                cvss_vector=_CRIT_VECTOR,
                primary_line_number=2,
                affected_locations=[],
            )
        ],
        dropped_finding_numbers=[],
    )
    result = _consolidate(_FakeClient(response=response), raw)
    assert len(result) == 1
    # 9.8 → Critical, regardless of the raw finding's "Low" label.
    assert result[0].severity == "Critical"
    assert result[0].cvss_score == 9.8


def test_false_positive_is_dropped():
    raw = [_raw(title="real"), _raw(title="false positive", agent_name="NoiseAgent")]
    response = _ConsolidationResponse(
        merged_findings=[
            _MergedFinding(
                subsumed_finding_numbers=[1],
                title="real",
                description="d",
                remediation="r",
                cvss_vector=_CRIT_VECTOR,
                primary_line_number=2,
                affected_locations=[],
            )
        ],
        dropped_finding_numbers=[2],
    )
    result = _consolidate(_FakeClient(response=response), raw)
    assert len(result) == 1
    assert result[0].title == "real"
    assert all(f.title != "false positive" for f in result)


def test_affected_locations_is_populated():
    raw = [_raw()]
    response = _ConsolidationResponse(
        merged_findings=[
            _MergedFinding(
                subsumed_finding_numbers=[1],
                title="t",
                description="d",
                remediation="r",
                cvss_vector=_CRIT_VECTOR,
                primary_line_number=2,
                affected_locations=[
                    _ConsolidatedLocation(line_number=2, snippet="a"),
                    _ConsolidatedLocation(line_number=14),
                ],
            )
        ],
        dropped_finding_numbers=[],
    )
    result = _consolidate(_FakeClient(response=response), raw)
    locs = result[0].affected_locations
    assert locs is not None
    assert [loc.line_number for loc in locs] == [2, 14]


def test_finding_neither_merged_nor_dropped_is_kept_as_orphan():
    raw = [_raw(title="merged"), _raw(title="orphan")]
    response = _ConsolidationResponse(
        merged_findings=[
            _MergedFinding(
                subsumed_finding_numbers=[1],
                title="merged",
                description="d",
                remediation="r",
                cvss_vector=_CRIT_VECTOR,
                primary_line_number=2,
                affected_locations=[],
            )
        ],
        dropped_finding_numbers=[],
    )
    result = _consolidate(_FakeClient(response=response), raw)
    assert {f.title for f in result} == {"merged", "orphan"}


def test_llm_error_passes_findings_through_unchanged():
    raw = [_raw(title="keep me")]
    result = _consolidate(_FakeClient(raises=True), raw)
    assert len(result) == 1
    assert result[0].title == "keep me"
    assert result[0].id is None
    # corroborating_agents is seeded from agent_name on passthrough.
    assert result[0].corroborating_agents == ["InjectionAgent"]


def test_empty_findings_returns_empty():
    assert _consolidate(_FakeClient(), []) == []
