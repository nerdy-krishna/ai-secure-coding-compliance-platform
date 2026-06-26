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
    batch = state.get("_batch", 1)

    logger.info("Saving final results for scan %s (batch %s).", scan_id, batch)
    try:
        async with AsyncSessionLocal() as db:
            repo = ScanRepository(db)

            await repo.replace_findings_for_scan(scan_id, findings, batch=batch)

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
    except Exception as _e:
        logger.warning("GENERATING_REPORTS started-event emit failed: %s", _e)
    severity_map: Dict[str, int] = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFORMATIONAL": 0,
    }
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

    # Persist exact finding_lineage artifact for new scans (non-fatal).
    try:
        await _persist_finding_lineage_artifact(scan_id, state, findings)
    except Exception:
        logger.warning(
            "save_final_report: lineage artifact persistence failed "
            "(non-fatal) for scan %s",
            scan_id,
            exc_info=True,
        )

    return {}


async def _persist_finding_lineage_artifact(
    scan_id,
    state: WorkerState,
    findings: list,
) -> None:
    """Generate and persist a finding_lineage_v1 artifact for the scan."""
    import hashlib
    import json as _json

    from sqlalchemy import select

    from app.infrastructure.database import models as db_models
    from app.infrastructure.database.repositories.scan_artifact_repo import (
        ARTIFACT_TYPE_LINEAGE,
        ScanArtifactRepository,
    )

    async with AsyncSessionLocal() as db:
        all_findings = list(
            (
                await db.execute(
                    select(db_models.Finding).where(
                        db_models.Finding.scan_id == scan_id
                    )
                )
            )
            .scalars()
            .all()
        )

        flow_map_raw: list = []
        events = list(
            (
                await db.execute(
                    select(db_models.ScanEvent)
                    .where(
                        db_models.ScanEvent.scan_id == scan_id,
                        db_models.ScanEvent.stage_name == "CONSOLIDATING",
                    )
                    .order_by(db_models.ScanEvent.timestamp.desc())
                    .limit(1)
                )
            )
            .scalars()
            .all()
        )
        if events and events[0].details:
            raw = events[0].details.get("flow_map_json")
            if isinstance(raw, str):
                flow_map_raw = _json.loads(raw)
            elif isinstance(raw, list):
                flow_map_raw = raw

        sast = [f for f in all_findings if getattr(f, "finding_bucket", "") == "sast"]
        raw_llm = [
            f for f in all_findings if getattr(f, "finding_bucket", "") == "raw_llm"
        ]
        consolidated = [
            f
            for f in all_findings
            if getattr(f, "finding_bucket", "consolidated") == "consolidated"
        ]
        all_raw = sast + raw_llm

        raw_records: list = []
        for f in all_raw:
            lid = getattr(f, "id", None)
            key = _json.dumps(
                [
                    str(scan_id),
                    getattr(f, "source", "") or "",
                    getattr(f, "file_path", "") or "",
                    getattr(f, "line_number", None) or 0,
                    (getattr(f, "title", "") or "")[:200],
                    (getattr(f, "cwe", "") or ""),
                ],
                sort_keys=True,
            )
            lineage_ref = f"raw:sha256:{hashlib.sha256(key.encode()).hexdigest()[:16]}"
            raw_records.append(
                {
                    "lineage_ref": lineage_ref,
                    "db_id": lid,
                    "title": getattr(f, "title", ""),
                    "source": getattr(f, "source", "") or getattr(f, "agent_name", ""),
                    "file_path": getattr(f, "file_path", ""),
                    "severity": getattr(f, "severity", "INFO"),
                    "cwe": getattr(f, "cwe", ""),
                    "line_number": getattr(f, "line_number", None),
                }
            )

        final_records: list = []
        for f in consolidated:
            fid = getattr(f, "id", None)
            key = _json.dumps(
                [
                    str(scan_id),
                    (getattr(f, "title", "") or "")[:200],
                    (getattr(f, "cwe", "") or ""),
                    (getattr(f, "remediation", "") or "")[:500],
                ],
                sort_keys=True,
            )
            lineage_ref = (
                f"final:sha256:{hashlib.sha256(key.encode()).hexdigest()[:16]}"
            )
            final_records.append(
                {
                    "lineage_ref": lineage_ref,
                    "db_id": fid,
                    "title": getattr(f, "title", ""),
                    "severity": getattr(f, "severity", "INFO"),
                    "cwe": getattr(f, "cwe", ""),
                    "remediation": getattr(f, "remediation", ""),
                }
            )

        links: list = []
        for fm in flow_map_raw:
            raw_title = fm.get("raw_title", "")
            status = (fm.get("status") or "passthrough").lower()
            cons_title = fm.get("consolidated_title", "")

            raw_ref = None
            for rec in raw_records:
                if rec["title"] == raw_title:
                    raw_ref = rec["lineage_ref"]
                    break

            final_ref = None
            for rec in final_records:
                if rec["title"] == cons_title:
                    final_ref = rec["lineage_ref"]
                    break

            link: dict = {
                "raw_ref": raw_ref,
                "final_ref": final_ref,
                "status": status,
            }
            if status == "dropped":
                link["drop_reason"] = fm.get("false_positive_reason")
                link["drop_kind"] = "false_positive"
            links.append(link)

        payload = {
            "schema_version": 1,
            "raw_findings": raw_records,
            "final_findings": final_records,
            "links": links,
        }

        await ScanArtifactRepository(db).upsert(
            scan_id=scan_id,
            artifact_type=ARTIFACT_TYPE_LINEAGE,
            version=1,
            payload=payload,
        )
        logger.info(
            "Persisted finding_lineage artifact for scan %s: %d raw, %d final, %d links",
            scan_id,
            len(raw_records),
            len(final_records),
            len(links),
        )
