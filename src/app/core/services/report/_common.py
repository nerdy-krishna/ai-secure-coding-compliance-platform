"""Shared helpers for the findings-report generators."""

from __future__ import annotations

from typing import List

from app.api.v1.models import AnalysisResultDetailResponse, VulnerabilityFindingResponse

# Severity sort order — Critical first, Informational last.
SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Informational": 4,
}


def collect_findings(
    result: AnalysisResultDetailResponse,
) -> List[VulnerabilityFindingResponse]:
    """Flatten every finding across the scan's analysed files, sorted by
    severity then file then line — the order a reviewer reads them in."""
    report = result.summary_report
    if report is None:
        return []
    findings: List[VulnerabilityFindingResponse] = []
    for file_item in report.files_analyzed:
        findings.extend(file_item.findings)
    findings.sort(
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 9),
            f.file_path,
            f.line_number,
        )
    )
    return findings


def affected_lines(finding: VulnerabilityFindingResponse) -> List[int]:
    """The line numbers in a finding's `affected_locations`, if any."""
    out: List[int] = []
    for loc in finding.affected_locations or []:
        line = loc.get("line_number") if isinstance(loc, dict) else None
        if isinstance(line, int):
            out.append(line)
    return out
