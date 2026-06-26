from __future__ import annotations

from app.core.schemas import VulnerabilityFinding
from app.infrastructure.workflows.nodes.consolidate_findings import (
    _deserialise_consolidation_result,
    _normalise_consolidation_result,
    _serialise_findings,
)


def _finding(title: str) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        title=title,
        description="desc",
        severity="Medium",
        line_number=1,
        remediation="fix",
        confidence="High",
        file_path="app.py",
        references=[],
        agent_name="Agent",
    )


def test_normalise_accepts_legacy_bare_finding_list_with_more_than_two_items():
    findings = [_finding(str(i)) for i in range(4)]

    normalised, flow_map = _normalise_consolidation_result(findings)

    assert normalised == findings
    assert flow_map == []


def test_serialised_consolidation_result_preserves_flow_map_for_reuse():
    finding = _finding("merged")
    flow = [{"raw_title": "raw", "consolidated_title": "merged", "status": "merged"}]

    payload = _serialise_findings([finding], flow)
    findings, flow_map = _deserialise_consolidation_result(payload)

    assert [f.title for f in findings] == ["merged"]
    assert flow_map == flow


def test_deserialise_legacy_result_without_flow_map_is_backward_compatible():
    payload = {"findings": [_finding("legacy").model_dump(mode="json")]}

    findings, flow_map = _deserialise_consolidation_result(payload)

    assert [f.title for f in findings] == ["legacy"]
    assert flow_map == []
