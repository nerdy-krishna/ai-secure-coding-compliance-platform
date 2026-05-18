"""`consolidate_findings` worker-graph node (#72).

Replaces the old exact-key `correlate_findings` node. Groups the raw
findings by file and runs the `FindingConsolidator` (reasoning LLM
slot) over each file: findings describing the same root cause are
merged into one root finding, false positives / fully-subsumed
duplicates / non-actionable noise are dropped.

The string name registered via `workflow.add_node("consolidate_findings", ...)`
is part of the LangGraph checkpointer's on-disk contract — do not rename.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List

from app.core.schemas import VulnerabilityFinding
from app.infrastructure.agents.finding_consolidator import (
    _passthrough,
    create_finding_consolidator,
)
from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.workflows.state import WorkerState
from app.shared.lib.llm_slots import (
    LLMStep,
    resolve_llm_config_id,
    resolve_temperature,
)
from app.shared.lib.scan_progress import EV_STARTED

logger = logging.getLogger(__name__)

# Bounds concurrent per-file consolidation calls on the reasoning slot.
CONCURRENT_CONSOLIDATION_LIMIT = 5


async def consolidate_findings_node(state: WorkerState) -> Dict[str, Any]:
    """Consolidate raw findings into one root finding per real issue.

    Per-file: the file's source plus all its raw findings go to the
    reasoning LLM, which merges same-root-cause findings and drops
    noise. A per-file consolidation failure degrades safely — that
    file's raw findings pass through unchanged. Every output finding
    has `id` cleared; `save_results_node` writes the consolidated set
    fresh.
    """
    findings: List[VulnerabilityFinding] = state.get("findings") or []
    async with AsyncSessionLocal() as db:
        await ScanRepository(db).record_scan_event(
            state["scan_id"], "CONSOLIDATING", EV_STARTED
        )
    if not findings:
        await _emit_event(
            state["scan_id"],
            {
                "raw_count": 0,
                "consolidated_count": 0,
                "merged_roots": 0,
                "merged_inputs": 0,
                "dropped": 0,
                "finding_count": 0,
            },
        )
        return {"findings": []}

    reasoning_llm_id = resolve_llm_config_id(LLMStep.CONSOLIDATION, state)
    if not reasoning_llm_id:
        return {
            "error_message": "consolidate_findings requires a reasoning LLM config."
        }

    live_codebase: Dict[str, str] = state.get("live_codebase") or {}

    # Group raw findings by file — consolidation is per-file.
    by_file: Dict[str, List[VulnerabilityFinding]] = {}
    for f in findings:
        by_file.setdefault(f.file_path, []).append(f)

    try:
        consolidator = await create_finding_consolidator(
            reasoning_llm_id,
            temperature=resolve_temperature(LLMStep.CONSOLIDATION, state),
        )
    except Exception as exc:  # noqa: BLE001
        return {"error_message": f"Could not start finding consolidator: {exc}"}

    semaphore = asyncio.Semaphore(CONCURRENT_CONSOLIDATION_LIMIT)

    async def _consolidate(file_path: str, file_findings: List[VulnerabilityFinding]):
        source = live_codebase.get(file_path)
        if not source:
            # No source to reason over — pass the findings through.
            return [_passthrough(f) for f in file_findings]
        async with semaphore:
            return await consolidator.consolidate_file(file_path, source, file_findings)

    results = await asyncio.gather(
        *(_consolidate(fp, ff) for fp, ff in by_file.items()),
        return_exceptions=True,
    )

    consolidated: List[VulnerabilityFinding] = []
    for file_path, result in zip(by_file.keys(), results):
        if isinstance(result, BaseException):
            logger.warning(
                "consolidate_findings: file %s raised %s — passing findings through",
                file_path,
                result,
            )
            consolidated.extend(_passthrough(f) for f in by_file[file_path])
            continue
        consolidated.extend(result)

    logger.info(
        "consolidate_findings: scan_id=%s %d raw -> %d consolidated across %d file(s)",
        state["scan_id"],
        len(findings),
        len(consolidated),
        len(by_file),
    )
    await _emit_event(
        state["scan_id"],
        {
            "raw_count": len(findings),
            "consolidated_count": len(consolidated),
            "merged_roots": consolidator.merged_roots,
            "merged_inputs": consolidator.merged_inputs,
            "dropped": consolidator.dropped,
            "finding_count": len(consolidated),  # back-compat key
        },
    )
    return {"findings": consolidated}


async def _emit_event(scan_id, stats: Dict[str, int]) -> None:
    """Best-effort CONSOLIDATING timeline marker carrying the
    consolidation tally (raw → consolidated, merged, dropped)."""
    try:
        async with AsyncSessionLocal() as db:
            await ScanRepository(db).create_scan_event(
                scan_id=scan_id,
                stage_name="CONSOLIDATING",
                status="COMPLETED",
                details=stats,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("consolidate_findings: CONSOLIDATING event emit failed: %s", exc)
