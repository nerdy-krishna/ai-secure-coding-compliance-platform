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
    "candidate_id",
    "candidate_state",
    "requirement_type",
    "requirement_value",
    "validation_profile",
    "validation_tool",
    "validation_tool_version",
    "validation_outcome",
    "validation_timestamp",
    "validation_diagnostic",
    "unified_diff",
    "governance_state",
    "policy_outcome",
    "predecessor_finding_id",
    "attempt_id",
    "dataflow",
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
    governance_payload = result.finding_governance or {}
    if governance_payload:
        governance_counts = governance_payload.get("counts", {})
        evaluation = governance_payload.get("policy_evaluation") or {}
        writer.writerow(
            {
                "record_type": "governance_summary",
                "governance_state": "; ".join(
                    f"{state}={governance_counts.get(state, 0)}"
                    for state in ("new", "fixed", "unchanged", "reintroduced")
                ),
                "policy_outcome": evaluation.get("outcome", "not_evaluated"),
            }
        )
        for item in governance_payload.get("items", []):
            writer.writerow(
                {
                    "record_type": "governance_lineage",
                    "governance_state": item.get("baseline_state", ""),
                    "finding_fingerprint": item.get("fingerprint", ""),
                    "predecessor_finding_id": item.get("predecessor_finding_id", ""),
                    "attempt_id": item.get("attempt_id", ""),
                    "dataflow": str(item.get("dataflow", {})),
                    "evidence_object_ids": "; ".join(item.get("evidence_object_ids", [])),
                }
            )
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
    remediation = (
        result.summary_report.remediation.model_dump(mode="json")
        if result.summary_report and result.summary_report.remediation is not None
        else {}
    )
    if remediation:
        writer.writerow(
            {
                "record_type": "remediation_summary",
                "candidate_state": remediation.get("outcome", "unknown"),
                "validation_diagnostic": str(remediation),
            }
        )
    for file_plan in (result.patch_plan or {}).get("files", []):
        for requirement in file_plan.get("requirements", []):
            for label, key in (
                ("import", "required_imports"),
                ("dependency", "required_dependencies"),
                ("configuration", "configuration_changes"),
                ("migration", "migration_changes"),
                ("command", "required_commands"),
                ("manual_step", "manual_steps"),
            ):
                for value in requirement.get(key, []):
                    writer.writerow(
                        {
                            "record_type": "patch_requirement",
                            "file_path": file_plan.get("file_path", ""),
                            "candidate_id": requirement.get("candidate_id", ""),
                            "candidate_state": file_plan.get("status", ""),
                            "requirement_type": label,
                            "requirement_value": value,
                        }
                    )
        for check in file_plan.get("validation_checks", []):
            writer.writerow(
                {
                    "record_type": "validation_evidence",
                    "file_path": file_plan.get("file_path", ""),
                    "candidate_state": file_plan.get("status", ""),
                    "validation_profile": check.get("profile")
                    or check.get("stage", ""),
                    "validation_tool": check.get("tool", ""),
                    "validation_tool_version": check.get("tool_version", ""),
                    "validation_outcome": check.get("status", "not_run"),
                    "validation_timestamp": check.get("completed_at", ""),
                    "validation_diagnostic": check.get("detail", ""),
                }
            )
        if file_plan.get("unified_diff"):
            writer.writerow(
                {
                    "record_type": "patch",
                    "file_path": file_plan.get("file_path", ""),
                    "candidate_state": file_plan.get("status", ""),
                    "unified_diff": file_plan["unified_diff"],
                }
            )
    return buffer.getvalue()
