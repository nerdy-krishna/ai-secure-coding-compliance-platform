"""Terminal save nodes for the worker graph.

Two nodes: `save_results_node` writes findings + the post-remediation
snapshot; `save_final_report_node` writes the summary blob and the
0–10 risk score and flips the scan to `COMPLETED` /
`REMEDIATION_COMPLETED`.

The string names registered via `workflow.add_node(...)` are part of
the LangGraph checkpointer's on-disk contract — do not rename.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.workflows.state import WorkerState
from app.shared.lib.risk_score import compute_cvss_aggregate
from app.shared.lib.scan_progress import EV_STARTED
from app.shared.lib.scan_status import (
    STATUS_COMPLETED,
    STATUS_REMEDIATION_COMPLETED,
)

logger = logging.getLogger(__name__)


async def save_results_node(state: WorkerState) -> Dict[str, Any]:
    scan_id = state["scan_id"]
    scan_type = state["scan_type"]
    findings = state.get("findings", [])
    final_file_map = state.get("final_file_map")

    logger.info("Saving final results for scan %s.", scan_id)
    try:
        async with AsyncSessionLocal() as db:
            repo = ScanRepository(db)

            # After the consolidation pass (#72), `state["findings"]` is
            # the authoritative final finding set: merged root findings
            # plus whatever survived the quality gate. The deterministic-
            # prescan node inserted its raw rows earlier (so the prescan-
            # approval card could render them) — clear those and write
            # the consolidated set fresh so a merged cluster never leaves
            # its pre-merge rows behind. The consolidation node strips
            # `id` from every output finding, so `save_findings` inserts
            # the whole set. Always delete first, even when `findings` is
            # empty — the quality gate may have dropped everything.
            await repo.replace_findings_for_scan(scan_id, findings)

            if scan_type == "REMEDIATE" and final_file_map:
                logger.info("Saving POST_REMEDIATION snapshot for scan %s.", scan_id)
                await repo.create_code_snapshot(
                    scan_id=scan_id,
                    file_map=final_file_map,
                    snapshot_type="POST_REMEDIATION",
                )
    except Exception:
        logger.error(
            "save_results_failed", extra={"scan_id": str(scan_id)}, exc_info=True
        )
        raise

    return {}


async def save_final_report_node(state: WorkerState) -> Dict[str, Any]:
    scan_id, findings = state["scan_id"], state.get("findings", [])
    logger.info("Saving final reports and risk score for scan %s.", scan_id)
    try:
        async with AsyncSessionLocal() as _db_start:
            await ScanRepository(_db_start).record_scan_event(
                scan_id, "GENERATING_REPORTS", EV_STARTED
            )
    except Exception as _e:  # noqa: BLE001
        logger.warning("GENERATING_REPORTS started-event emit failed: %s", _e)
    severity_map = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
    for f in findings:
        sev = (f.severity or "LOW").upper()
        if sev in severity_map:
            severity_map[sev] += 1
    aggregate = compute_cvss_aggregate(findings, scan_id=scan_id)
    final_risk_score = min(10, int(round(aggregate)))

    summary_data = {
        "summary": {
            "total_findings_count": len(findings),
            "files_analyzed_count": len(set(f.file_path for f in findings)),
            "severity_counts": severity_map,
        },
        "overall_risk_score": {"score": final_risk_score, "severity": "High"},
    }
    final_status = (
        STATUS_REMEDIATION_COMPLETED
        if state.get("scan_type") == "REMEDIATE"
        else STATUS_COMPLETED
    )
    logger.info(
        "audit.scan.finalized",
        extra={
            "scan_id": str(scan_id),
            "scan_type": state.get("scan_type"),
            "final_status": final_status,
            "findings_total": len(findings),
            "risk_score": final_risk_score,
            "severity_counts": severity_map,
        },
    )
    try:
        async with AsyncSessionLocal() as db:
            repo = ScanRepository(db)
            await repo.save_final_reports_and_status(
                scan_id=scan_id,
                status=final_status,
                summary=summary_data,
                risk_score=final_risk_score,
            )
            # Stage-event audit trail — GENERATING_REPORTS marker so
            # the timeline closes out the final stage. Wrapped in a
            # nested try so a logging-side issue here doesn't roll
            # back the just-persisted final-report transaction.
            try:
                await repo.create_scan_event(
                    scan_id=scan_id,
                    stage_name="GENERATING_REPORTS",
                    status="COMPLETED",
                    details={
                        "findings_total": len(findings),
                        "risk_score": final_risk_score,
                        "severity_counts": severity_map,
                    },
                )
            except Exception as _e:
                logger.warning("GENERATING_REPORTS event emit failed: %s", _e)
    except Exception:
        logger.error(
            "save_final_report_failed", extra={"scan_id": str(scan_id)}, exc_info=True
        )
        raise
    return {}
