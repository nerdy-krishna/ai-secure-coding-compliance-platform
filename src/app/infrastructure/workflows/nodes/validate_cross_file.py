"""`validate_cross_file` worker-graph node (#81 / PRD #75).

Wired permanently after `consolidate_findings`. Opt-in: when the scan
did not set `cross_file_validation` the node early-returns a no-op and
emits no timeline event, so an opted-out scan's pipeline is
byte-identical to before this node existed.

When opted in: the `CrossFileSlicer` eligibility pre-filter selects the
consolidated findings that have real cross-file context, and each
eligible finding gets one reasoning-LLM verdict via the
`CrossFileValidator`, fired under bounded concurrency. The verdict is
non-destructive — it only stamps `cross_file_status` /
`cross_file_rationale`; severity is never changed and no finding is
added or dropped. Pre-filter-skipped findings keep a NULL status.

The string name registered via `workflow.add_node("validate_cross_file", ...)`
is part of the LangGraph checkpointer's on-disk contract — do not rename.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Tuple

from app.core.schemas import VulnerabilityFinding
from app.infrastructure.agents.cross_file_validator import (
    create_cross_file_validator,
)
from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.workflows.state import WorkerState
from app.shared.analysis_tools.cross_file_slicer import (
    CrossFileSlicer,
    CrossFileSlices,
)
from app.shared.lib.llm_slots import (
    LLMStep,
    resolve_llm_config_id,
    resolve_temperature,
)
from app.shared.lib.scan_progress import EV_STARTED

from app.config.config import settings

logger = logging.getLogger(__name__)

# Bounds concurrent per-finding validation calls on the reasoning slot.
CONCURRENT_VALIDATION_LIMIT = settings.CONCURRENT_VALIDATION_LIMIT


async def validate_cross_file_node(state: WorkerState) -> Dict[str, Any]:
    """Re-judge each eligible consolidated finding against its cross-file
    context. A no-op (no state change, no timeline event) when the scan
    did not opt in to cross-file validation.
    """
    if not state.get("cross_file_validation"):
        # Opted out — byte-identical to a pipeline without this node.
        return {}

    async with AsyncSessionLocal() as db:
        await ScanRepository(db).record_scan_event(
            state["scan_id"], "CROSS_FILE_VALIDATION", EV_STARTED
        )

    findings: List[VulnerabilityFinding] = state.get("findings") or []
    if not findings:
        await _emit_event(state["scan_id"], 0, 0, {})
        return {"findings": []}

    repository_map = state.get("repository_map")
    live_codebase: Dict[str, str] = state.get("live_codebase") or {}
    if repository_map is None or not live_codebase:
        logger.warning(
            "validate_cross_file: scan_id=%s no repository map / codebase — "
            "skipping cross-file validation",
            state["scan_id"],
        )
        await _emit_event(state["scan_id"], 0, len(findings), {})
        return {}

    reasoning_llm_id = resolve_llm_config_id(LLMStep.CONSOLIDATION, state)
    if not reasoning_llm_id:
        return {"error_message": "validate_cross_file requires a reasoning LLM config."}

    # Eligibility pre-filter — only findings with real cross-file
    # context (and not secret / dependency-CVE scanner findings) are
    # worth a paid validation call.
    slicer = CrossFileSlicer(repository_map, live_codebase)
    eligible: List[Tuple[int, CrossFileSlices]] = []
    for idx, finding in enumerate(findings):
        slices = slicer.extract_slices(finding)
        if not slices.is_empty:
            eligible.append((idx, slices))

    if not eligible:
        logger.info(
            "validate_cross_file: scan_id=%s 0/%d findings eligible",
            state["scan_id"],
            len(findings),
        )
        await _emit_event(state["scan_id"], 0, len(findings), {})
        return {}

    try:
        validator = await create_cross_file_validator(
            reasoning_llm_id,
            temperature=resolve_temperature(LLMStep.CONSOLIDATION, state),
        )
    except Exception as exc:  # noqa: BLE001
        return {"error_message": f"Could not start cross-file validator: {exc}"}

    validation_limit = CONCURRENT_VALIDATION_LIMIT
    try:
        from app.shared.lib.concurrency_limits import get_concurrency_limit

        async with AsyncSessionLocal() as _db:
            validation_limit = await get_concurrency_limit(
                _db, "CONCURRENT_VALIDATION_LIMIT"
            )
    except Exception:
        pass
    semaphore = asyncio.Semaphore(validation_limit)

    async def _validate(idx: int, slices: CrossFileSlices):
        async with semaphore:
            return idx, await validator.validate(findings[idx], slices)

    results = await asyncio.gather(
        *(_validate(idx, slices) for idx, slices in eligible),
        return_exceptions=True,
    )

    # Apply verdicts non-destructively: copy every finding, stamp the
    # status onto the eligible ones. Pre-filter-skipped findings keep a
    # NULL `cross_file_status`. Severity is never touched.
    updated: List[VulnerabilityFinding] = [f.model_copy(deep=True) for f in findings]
    counts = {"confirmed": 0, "mitigated": 0, "unconfirmed": 0}
    for res in results:
        if isinstance(res, BaseException):
            logger.warning("validate_cross_file: a validation task raised: %s", res)
            continue
        idx, verdict = res
        updated[idx].cross_file_status = verdict.status
        updated[idx].cross_file_rationale = verdict.rationale
        counts[verdict.status] = counts.get(verdict.status, 0) + 1

    logger.info(
        "validate_cross_file: scan_id=%s validated %d/%d findings "
        "(confirmed=%d mitigated=%d unconfirmed=%d)",
        state["scan_id"],
        len(eligible),
        len(findings),
        counts["confirmed"],
        counts["mitigated"],
        counts["unconfirmed"],
    )
    await _emit_event(state["scan_id"], len(eligible), len(findings), counts)
    return {"findings": updated}


async def _emit_event(
    scan_id, eligible_count: int, total_count: int, counts: Dict[str, int]
) -> None:
    """Best-effort CROSS_FILE_VALIDATION timeline marker."""
    try:
        async with AsyncSessionLocal() as db:
            await ScanRepository(db).create_scan_event(
                scan_id=scan_id,
                stage_name="CROSS_FILE_VALIDATION",
                status="COMPLETED",
                details={
                    "eligible_count": eligible_count,
                    "total_findings": total_count,
                    "confirmed": counts.get("confirmed", 0),
                    "mitigated": counts.get("mitigated", 0),
                    "unconfirmed": counts.get("unconfirmed", 0),
                },
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "validate_cross_file: CROSS_FILE_VALIDATION event emit failed: %s", exc
        )
