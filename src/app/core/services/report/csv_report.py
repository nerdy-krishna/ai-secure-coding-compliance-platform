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
    "record_type",
    "file_path",
    "line_number",
    "severity",
    "cvss_score",
    "confidence",
    "cwe",
    "source",
    "scanner_version",
    "scanner_binary_sha256",
    "scanner_provenance_status",
    "title",
    "description",
    "remediation",
    "corroborating_agents",
    "affected_lines",
    # Operator triage state + justification (PRD #96 / #102).
    "disposition",
    "disposition_note",
    "coverage_entry_id",
    "coverage_status",
    "coverage_reason",
    "baseline_state",
    "finding_fingerprint",
    "evidence_object_ids",
]


def render_csv(result: AnalysisResultDetailResponse) -> str:
    """Render the scan's findings as CSV text — one row per finding."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_COLUMNS, lineterminator="\n")
    writer.writeheader()
    governance_by_finding = {
        item.get("finding_id"): item
        for item in (result.finding_governance or {}).get("items", [])
        if item.get("finding_id") is not None
    }
    for finding in collect_findings(result):
        source = finding.source or "agent"
        provenance = result.toolchain_provenance.get(source, {})
        binary = provenance.get("binary", {}) if isinstance(provenance, dict) else {}
        governance = governance_by_finding.get(finding.id, {})
        writer.writerow(
            {
                "record_type": "finding",
                "file_path": finding.file_path,
                "line_number": finding.line_number,
                "severity": finding.severity,
                "cvss_score": (
                    finding.cvss_score if finding.cvss_score is not None else ""
                ),
                "confidence": finding.confidence,
                "cwe": finding.cwe or "",
                "source": source,
                "scanner_version": binary.get("version", ""),
                "scanner_binary_sha256": binary.get("sha256", ""),
                "scanner_provenance_status": (
                    provenance.get("status", "") if isinstance(provenance, dict) else ""
                ),
                "title": finding.title,
                "description": finding.description,
                "remediation": finding.remediation,
                "corroborating_agents": "; ".join(finding.corroborating_agents or []),
                "affected_lines": "; ".join(
                    str(line) for line in affected_lines(finding)
                ),
                "disposition": getattr(finding, "disposition", None) or "open",
                "disposition_note": getattr(finding, "disposition_note", None) or "",
                "coverage_entry_id": getattr(finding, "coverage_entry_id", None) or "",
                "coverage_status": "",
                "coverage_reason": "",
                "baseline_state": governance.get("baseline_state", ""),
                "finding_fingerprint": governance.get("fingerprint", ""),
                "evidence_object_ids": "; ".join(
                    governance.get("evidence_object_ids", [])
                ),
            }
        )
    coverage = result.scanner_coverage
    if coverage is None:
        writer.writerow(
            {
                "record_type": "coverage",
                "coverage_status": "unavailable",
                "coverage_reason": (
                    "Coverage manifest unavailable; zero findings are not proof of a clean scan."
                ),
            }
        )
    else:
        writer.writerow(
            {
                "record_type": "coverage",
                "coverage_status": coverage.overall_status,
                "coverage_reason": (
                    "Every planned deterministic scanner/input completed."
                    if coverage.is_complete
                    else "Coverage is incomplete; zero findings are not proof of a clean scan."
                ),
            }
        )
        for entry in coverage.entries:
            writer.writerow(
                {
                    "record_type": "coverage",
                    "file_path": entry.input_path,
                    "source": entry.scanner_name,
                    "coverage_entry_id": entry.id,
                    "coverage_status": entry.status,
                    "coverage_reason": entry.reason or "",
                }
            )
    return buffer.getvalue()
