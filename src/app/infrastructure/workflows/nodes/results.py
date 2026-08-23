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
from app.infrastructure.database.repositories.llm_usage_repo import LLMUsageRepository
from app.infrastructure.workflows.state import WorkerState
from app.shared.lib.risk_score import compute_cvss_aggregate
from app.shared.lib.risk_severity import risk_severity_for_score
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
    fix_candidates = state.get("fix_candidates", []) or []
    patch_plan = state.get("patch_plan")
    patch_validation_summary = state.get("patch_validation_summary")
    final_file_map = state.get("final_file_map")
    batch = state.get("_batch", 1)

    logger.info("Saving final results for scan %s (batch %s).", scan_id, batch)
    try:
        async with AsyncSessionLocal() as db:
            repo = ScanRepository(db)

            await repo.replace_findings_for_scan(scan_id, findings, batch=batch)
            await repo.replace_fix_candidates_for_scan(
                scan_id, fix_candidates, batch=batch
            )
            if patch_plan is not None:
                from app.infrastructure.database.repositories.scan_artifact_repo import (
                    ARTIFACT_TYPE_PATCH_PLAN,
                    ScanArtifactRepository,
                )

                await ScanArtifactRepository(db).upsert(
                    scan_id=scan_id,
                    artifact_type=ARTIFACT_TYPE_PATCH_PLAN,
                    version=2,
                    payload=patch_plan,
                )
            if patch_validation_summary is not None:
                await repo.create_scan_event(
                    scan_id=scan_id,
                    stage_name="PATCH_VALIDATION",
                    status="COMPLETED",
                    details=patch_validation_summary,
                )

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
    async with AsyncSessionLocal() as _db_start:
        generation_claimed = await ScanRepository(_db_start).record_scan_event(
            scan_id, "GENERATING_REPORTS", EV_STARTED
        )
    if not generation_claimed:
        logger.info(
            "save_final_report: report-generation transition rejected for scan %s",
            scan_id,
        )
        return {}
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
        "overall_risk_score": {
            "score": final_risk_score,
            "severity": risk_severity_for_score(final_risk_score),
        },
    }
    if state.get("patch_validation_summary") is not None:
        summary_data["remediation"] = state["patch_validation_summary"]
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
            # Close the estimate feedback loop before terminal status is
            # persisted. Future preflights consume these same canonical
            # analysis events as model/stage calibration observations.
            await LLMUsageRepository(db).measure_scan_estimate_variance(
                scan_id=scan_id,
                stage="analysis",
            )
            finalized = await repo.save_final_reports_and_status(
                scan_id=scan_id,
                status=final_status,
                summary=summary_data,
                risk_score=final_risk_score,
            )
            if not finalized:
                logger.info(
                    "save_final_report: terminal transition rejected for scan %s",
                    scan_id,
                )
                return {}
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

    try:
        from app.infrastructure.database.repositories.evidence_repo import (
            EvidenceRepository,
        )
        from app.infrastructure.database.repositories.scan_attempt_repo import (
            ScanAttemptRepository,
        )

        async with AsyncSessionLocal() as db:
            attempt = await ScanAttemptRepository(db).mark_current_terminal(
                scan_id, status="completed", commit=False
            )
            if attempt is not None:
                await EvidenceRepository(db).finalize_attempt(
                    attempt.id, actor_user_id=None, commit=False
                )
            await db.commit()
    except Exception:
        logger.warning(
            "save_final_report: attempt manifest finalization failed for scan %s",
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
        candidate_rows = list(
            (
                await db.execute(
                    select(db_models.FindingFixCandidate).where(
                        db_models.FindingFixCandidate.scan_id == scan_id
                    )
                )
            )
            .scalars()
            .all()
        )

        flow_map_raw: list = list(state.get("finding_lineage") or [])
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
        if not flow_map_raw and events and events[0].details:
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
            stable_raw_id = getattr(f, "raw_finding_id", None)
            lineage_ref = (
                f"raw:{stable_raw_id}"
                if stable_raw_id
                else f"raw:sha256:{hashlib.sha256(key.encode()).hexdigest()[:16]}"
            )
            raw_records.append(
                {
                    "lineage_ref": lineage_ref,
                    "raw_finding_id": str(stable_raw_id) if stable_raw_id else None,
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
            stable_canonical_id = getattr(f, "canonical_finding_id", None)
            lineage_ref = (
                f"canonical:{stable_canonical_id}"
                if stable_canonical_id
                else f"final:sha256:{hashlib.sha256(key.encode()).hexdigest()[:16]}"
            )
            final_records.append(
                {
                    "lineage_ref": lineage_ref,
                    "canonical_finding_id": (
                        str(stable_canonical_id) if stable_canonical_id else None
                    ),
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

            stable_raw_id = fm.get("raw_finding_id")
            raw_ref = f"raw:{stable_raw_id}" if stable_raw_id else None
            if raw_ref is None:  # Legacy scans only.
                for rec in raw_records:
                    if rec["title"] == raw_title:
                        raw_ref = rec["lineage_ref"]
                        break

            stable_canonical_id = fm.get("canonical_finding_id")
            final_ref = (
                f"canonical:{stable_canonical_id}" if stable_canonical_id else None
            )
            if final_ref is None and not stable_raw_id:  # Legacy scans only.
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

        fix_candidate_records = [
            {
                "candidate_id": str(row.candidate_id),
                "raw_finding_id": str(row.raw_finding_id),
                "canonical_finding_id": (
                    str(row.canonical_finding_id) if row.canonical_finding_id else None
                ),
                "source_snapshot_hash": row.source_snapshot_hash,
                "anchor_fingerprint": row.anchor_fingerprint,
                "patch_fingerprint": row.patch_fingerprint,
                "resolved_range": row.resolved_range,
                "context_fingerprint": row.context_fingerprint,
                "patch_hunk_id": str(row.patch_hunk_id) if row.patch_hunk_id else None,
                "applicability_status": row.applicability_status,
                "language": row.language,
                "symbol": row.symbol,
                "required_imports": row.required_imports,
                "required_dependencies": row.required_dependencies,
                "configuration_changes": row.configuration_changes,
                "migration_changes": row.migration_changes,
                "manual_steps": row.manual_steps,
                "file_path": row.file_path,
                "line_number": row.line_number,
                "suggestion": row.suggestion,
                "disposition": row.disposition,
                "decision_reason": row.decision_reason,
                "validation_status": row.validation_status,
                "is_applied": row.is_applied,
                "contributing_agents": row.contributing_agents,
                "contributing_models": row.contributing_models,
            }
            for row in candidate_rows
        ]

        payload = {
            "schema_version": 1,
            "raw_findings": raw_records,
            "final_findings": final_records,
            "links": links,
            "fix_candidates": fix_candidate_records,
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
