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
import hashlib
import json
import logging
from typing import Any, Dict, List

from app.core.schemas import VulnerabilityFinding
from app.infrastructure.agents.finding_consolidator import (
    _passthrough,
    create_finding_consolidator,
)
from app.infrastructure.database import AsyncSessionLocal
from app.core.services.scan.task_ledger import ScanTaskLedgerService
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.workflows.state import WorkerState
from app.shared.lib.llm_slots import (
    LLMStep,
    resolve_llm_config_id,
    resolve_temperature,
)
from app.shared.lib.scan_progress import EV_STARTED

from app.config.config import settings

logger = logging.getLogger(__name__)

# Bounds concurrent per-file consolidation calls on the reasoning slot.
CONCURRENT_CONSOLIDATION_LIMIT = settings.CONCURRENT_CONSOLIDATION_LIMIT
CONSOLIDATION_TASK_TYPE = "consolidation:file"
CONSOLIDATION_TASK_VERSION = "consolidation-file-v1"


def _stable_hash(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


ConsolidationResult = tuple[List[VulnerabilityFinding], list[dict[str, Any]]]


def _serialise_findings(
    findings: List[VulnerabilityFinding], flow_map: list[dict[str, Any]] | None = None
) -> Dict[str, Any]:
    return {
        "findings": [f.model_dump(mode="json") for f in findings],
        "flow_map": list(flow_map or []),
    }


def _deserialise_findings(payload: Dict[str, Any]) -> List[VulnerabilityFinding]:
    return [
        VulnerabilityFinding.model_validate(item)
        for item in payload.get("findings", [])
    ]


def _deserialise_consolidation_result(payload: Dict[str, Any]) -> ConsolidationResult:
    """Read a durable consolidation result.

    Older task rows contain only ``findings``. Treat their missing
    flow-map as empty so manual resume remains backward compatible.
    """
    return _deserialise_findings(payload), list(payload.get("flow_map") or [])


def _normalise_consolidation_result(result: Any) -> ConsolidationResult:
    """Coerce legacy/internal consolidation return shapes to one contract.

    The node's downstream loop expects ``(findings, flow_map)``. Older
    branches returned a bare list of findings (passthrough/no-source /
    reused durable result), which is ambiguous with a two-item findings
    list and crashes with >2 findings. Accept both shapes defensively;
    always return a tuple.
    """
    if isinstance(result, tuple) and len(result) == 2:
        findings, flow_map = result
        return list(findings or []), list(flow_map or [])
    if isinstance(result, list):
        return result, []
    raise TypeError(f"Unexpected consolidation result shape: {type(result)!r}")


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

    consolidation_limit = CONCURRENT_CONSOLIDATION_LIMIT
    try:
        from app.shared.lib.concurrency_limits import get_concurrency_limit
        async with AsyncSessionLocal() as _db:
            consolidation_limit = await get_concurrency_limit(_db, "CONCURRENT_CONSOLIDATION_LIMIT")
    except Exception:
        pass
    semaphore = asyncio.Semaphore(consolidation_limit)
    stats = {"reused": 0, "rerun": 0, "failed": 0, "completed": 0}

    async def _consolidate(file_path: str, file_findings: List[VulnerabilityFinding]):
        source = live_codebase.get(file_path)
        if not source:
            # No source to reason over — pass the findings through.
            return [_passthrough(f) for f in file_findings], []
        input_payload = {
            "file_path": file_path,
            "source_hash": _stable_hash(source),
            "findings": [f.model_dump(mode="json") for f in file_findings],
        }
        input_hash = _stable_hash(input_payload)
        prompt_hash = _stable_hash(
            {"source": source, "findings": input_payload["findings"]}
        )
        version_hash = _stable_hash(CONSOLIDATION_TASK_VERSION)
        task_key = f"{file_path}::file-consolidation"
        async with AsyncSessionLocal() as task_db:
            ledger = ScanTaskLedgerService(task_db)
            reused = await ledger.get_reusable_result(
                scan_id=state["scan_id"],
                task_type=CONSOLIDATION_TASK_TYPE,
                task_key=task_key,
                input_hash=input_hash,
                prompt_hash=prompt_hash,
                version_hash=version_hash,
            )
            if reused is not None:
                stats["reused"] += 1
                return _deserialise_consolidation_result(reused)
            lease = await ledger.acquire_task(
                scan_id=state["scan_id"],
                task_type=CONSOLIDATION_TASK_TYPE,
                task_key=task_key,
                input_hash=input_hash,
                prompt_hash=prompt_hash,
                version_hash=version_hash,
                input_payload=input_payload,
                lease_owner=f"worker:{state['scan_id']}",
                lease_ttl_seconds=1800,
                max_attempts=3,
            )
        if lease is None:
            stats["failed"] += 1
            return [_passthrough(f) for f in file_findings], []
        stats["rerun"] += 1
        try:
            async with semaphore:
                result, flow = await consolidator.consolidate_file(
                    file_path, source, file_findings
                )
        except Exception as exc:  # noqa: BLE001
            stats["failed"] += 1
            async with AsyncSessionLocal() as task_db:
                await ScanTaskLedgerService(task_db).fail_task(
                    lease.task.id, error=str(exc), retryable=True
                )
            return [_passthrough(f) for f in file_findings], []
        async with AsyncSessionLocal() as task_db:
            await ScanTaskLedgerService(task_db).complete_task(
                lease.task.id, result_payload=_serialise_findings(result, flow)
            )
        stats["completed"] += 1
        return result, flow

    results = await asyncio.gather(
        *(_consolidate(fp, ff) for fp, ff in by_file.items()),
        return_exceptions=True,
    )

    consolidated: List[VulnerabilityFinding] = []
    all_flow_maps: list[dict] = []
    for file_path, result in zip(by_file.keys(), results):
        if isinstance(result, BaseException):
            logger.warning(
                "consolidate_findings: file %s raised %s — passing findings through",
                file_path,
                result,
            )
            consolidated.extend(_passthrough(f) for f in by_file[file_path])
            continue
        findings_list, flow = _normalise_consolidation_result(result)
        consolidated.extend(findings_list)
        all_flow_maps.extend(flow)

    logger.info(
        "consolidate_findings: scan_id=%s %d raw -> %d consolidated across %d file(s)",
        state["scan_id"],
        len(findings),
        len(consolidated),
        len(by_file),
    )
    # Store consolidation flow map for the sankey diagram
    flow_map_json = json.dumps(all_flow_maps, default=str)
    await _emit_event(
        state["scan_id"],
        {
            "raw_count": len(findings),
            "consolidated_count": len(consolidated),
            "merged_roots": consolidator.merged_roots,
            "merged_inputs": consolidator.merged_inputs,
            "dropped": consolidator.dropped,
            "reused_tasks": stats["reused"],
            "rerun_tasks": stats["rerun"],
            "failed_tasks": stats["failed"],
            "completed_tasks": stats["completed"],
            "finding_count": len(consolidated),  # back-compat key
            "flow_map_json": flow_map_json,
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
