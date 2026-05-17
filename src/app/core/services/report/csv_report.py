"""CSV findings-report generator — one row per finding.

A finding is the unit a reviewer triages and tracks in a spreadsheet,
so the CSV has exactly one row per finding; the affected-location sites
are collapsed into a single semicolon-joined column rather than
exploded into extra rows.
"""

from __future__ import annotations

import csv
import io

from app.api.v1.models import AnalysisResultDetailResponse
from app.core.services.report._common import affected_lines, collect_findings

_COLUMNS = [
    "file_path",
    "line_number",
    "severity",
    "cvss_score",
    "confidence",
    "cwe",
    "source",
    "title",
    "description",
    "remediation",
    "corroborating_agents",
    "affected_lines",
]


def render_csv(result: AnalysisResultDetailResponse) -> str:
    """Render the scan's findings as CSV text — one row per finding."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for finding in collect_findings(result):
        writer.writerow(
            {
                "file_path": finding.file_path,
                "line_number": finding.line_number,
                "severity": finding.severity,
                "cvss_score": (
                    finding.cvss_score if finding.cvss_score is not None else ""
                ),
                "confidence": finding.confidence,
                "cwe": finding.cwe or "",
                "source": finding.source or "agent",
                "title": finding.title,
                "description": finding.description,
                "remediation": finding.remediation,
                "corroborating_agents": "; ".join(finding.corroborating_agents or []),
                "affected_lines": "; ".join(
                    str(line) for line in affected_lines(finding)
                ),
            }
        )
    return buffer.getvalue()
