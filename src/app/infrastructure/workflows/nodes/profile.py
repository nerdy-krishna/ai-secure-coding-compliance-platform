"""Per-file profiler + profiling-cost gate (#71).

Two worker-graph nodes live here, inserted between the prescan-approval
gate and the analysis-cost gate:

- `estimate_profiling_cost_node` — estimates the cost of profiling
  every file on the utility LLM slot, persists the estimate, sets
  status `PENDING_PROFILING_APPROVAL`, and `interrupt()`s for operator
  approval before any profiling spend happens.
- `profile_files_node` — runs the `FileProfiler` over every file on the
  utility slot and persists the resulting per-file profiles to
  `Scan.file_profiles` (the shared file-understanding artifact).

The string names registered via `workflow.add_node(...)` in
`worker_graph.py` are part of the LangGraph checkpointer's on-disk
contract — do not rename.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict

from langgraph.types import interrupt

from app.infrastructure.agents.file_profiler import create_file_profiler
from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database.repositories.llm_config_repo import LLMConfigRepository
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.workflows.state import WorkerState
from app.shared.lib import cost_estimation
from app.shared.lib.llm_slots import (
    LLMStep,
    resolve_llm_config_id,
    resolve_temperature,
)
from app.shared.lib.scan_progress import (
    EV_COMPLETED,
    EV_STARTED,
    EV_WAITING,
    STAGE_PROFILING_REVIEW,
)
from app.shared.lib.scan_status import (
    STATUS_ANALYZING_CONTEXT,
    STATUS_PENDING_PROFILING_APPROVAL,
)

logger = logging.getLogger(__name__)

# Bounds concurrent utility-LLM profiling calls so a large scan can't
# saturate the provider rate limit. Mirrors the analysis-side cap.
CONCURRENT_PROFILER_LIMIT = 5


async def estimate_profiling_cost_node(state: WorkerState) -> Dict[str, Any]:
    """Estimate the profiling spend and pause for operator approval.

    Profiling sends each file's content once through the utility-slot
    model, so the input-token basis is the sum of all file token
    counts priced at the utility config's rate. Pauses on `interrupt()`
    with status `PENDING_PROFILING_APPROVAL`; the gate fires even when
    the deterministic prescan produced no findings.
    """
    scan_id = state["scan_id"]
    files: Dict[str, str] = state.get("files") or {}

    async with AsyncSessionLocal() as db:
        await ScanRepository(db).record_scan_event(
            scan_id, "ESTIMATING_PROFILING_COST", EV_STARTED
        )

    utility_llm_config_id = resolve_llm_config_id(LLMStep.PROFILER, state)
    if not utility_llm_config_id:
        return {
            "error_message": "Profiling-cost estimation missing a utility LLM config."
        }

    total_input_tokens = 0
    async with AsyncSessionLocal() as db:
        utility_config = await LLMConfigRepository(db).get_by_id_with_decrypted_key(
            utility_llm_config_id
        )
        if not utility_config:
            return {
                "error_message": (
                    f"LLM Config {utility_llm_config_id} not found for "
                    "profiling-cost estimation."
                )
            }
        for content in files.values():
            total_input_tokens += await cost_estimation.count_tokens(
                content, utility_config
            )

    cost_details = cost_estimation.estimate_cost_for_prompt(
        utility_config, total_input_tokens
    )

    async with AsyncSessionLocal() as db:
        repo = ScanRepository(db)
        await repo.update_cost_and_status(
            scan_id, STATUS_PENDING_PROFILING_APPROVAL, cost_details
        )
        await repo.record_scan_event(
            scan_id,
            "ESTIMATING_PROFILING_COST",
            EV_COMPLETED,
            details=cost_details,
        )
        # The gate's WAITING event — parks `scans.status` at
        # PENDING_PROFILING_APPROVAL. The bare `profiling_cost_gate`
        # node owns the interrupt(), so this work node runs exactly once
        # and never re-fires these writes on resume (#84).
        await repo.record_scan_event(scan_id, STAGE_PROFILING_REVIEW, EV_WAITING)

    logger.info(
        "estimate_profiling_cost: scan_id=%s files=%d tokens=%d est=$%.4f — gated",
        scan_id,
        len(files),
        total_input_tokens,
        cost_details.get("total_estimated_cost", 0.0),
    )
    return {}


async def profiling_cost_gate_node(state: WorkerState) -> Dict[str, Any]:
    """Bare profiling-cost interrupt gate (#84).

    Contains only `interrupt()` plus the gate's `COMPLETED` event — no
    pre-interrupt side effects — so a LangGraph resume re-runs nothing
    that could duplicate an event or clobber `scans.status`. The
    `estimate_profiling_cost` work node already emitted the
    `PROFILING_REVIEW/WAITING` event and set the pause status.
    """
    scan_id = state["scan_id"]
    approval_payload = interrupt(
        {"scan_id": str(scan_id), "kind": "profiling_approval"}
    )
    logger.info(
        "profiling_cost_gate: scan_id=%s resumed payload=%s",
        scan_id,
        approval_payload,
    )
    async with AsyncSessionLocal() as db:
        await ScanRepository(db).record_scan_event(
            scan_id, STAGE_PROFILING_REVIEW, EV_COMPLETED
        )
    return {"profiling_approval": approval_payload or {}}


async def profile_files_node(state: WorkerState) -> Dict[str, Any]:
    """Profile every file on the utility slot and persist the profiles.

    Builds the domain vocabulary from the scan's relevant agents, runs
    the `FileProfiler` over each file (bounded concurrency), and writes
    the `{file_path: profile}` map to `Scan.file_profiles`.
    """
    scan_id = state["scan_id"]
    files: Dict[str, str] = state.get("files") or {}

    async with AsyncSessionLocal() as db:
        await ScanRepository(db).record_scan_event(
            scan_id, "PROFILING_FILES", EV_STARTED
        )

    utility_llm_config_id = resolve_llm_config_id(LLMStep.PROFILER, state)
    if not utility_llm_config_id:
        return {"error_message": "File profiling missing a utility LLM config."}

    # Domain vocabulary = the relevant agents' name → description. The
    # profiler constrains each file's `applicable_domains` to these.
    all_relevant_agents = state.get("all_relevant_agents") or {}
    domain_vocabulary: Dict[str, str] = {
        name: (agent.get("description") or "")
        for name, agent in all_relevant_agents.items()
    }

    if not files:
        logger.info("profile_files: scan_id=%s no files to profile", scan_id)
        return {"file_profiles": {}}

    # The tree-sitter repository map grounds the profiler with each
    # file's deterministic imports + symbols (#77). Built in
    # `retrieve_and_prepare_data`; `.files` survives the checkpointer
    # round-trip (the cost node reads it the same way).
    repository_map = state.get("repository_map")
    repo_files = getattr(repository_map, "files", None) or {}

    try:
        profiler = await create_file_profiler(
            utility_llm_config_id,
            temperature=resolve_temperature(LLMStep.PROFILER, state),
        )
    except Exception as exc:  # noqa: BLE001
        return {"error_message": f"Could not start file profiler: {exc}"}

    semaphore = asyncio.Semaphore(CONCURRENT_PROFILER_LIMIT)

    async def _profile(path: str, content: str):
        async with semaphore:
            profile = await profiler.profile_file(
                path,
                content,
                domain_vocabulary,
                repo_summary=repo_files.get(path),
            )
            return path, profile

    results = await asyncio.gather(
        *(_profile(p, c) for p, c in files.items()),
        return_exceptions=True,
    )
    file_profiles: Dict[str, Any] = {}
    for result in results:
        if isinstance(result, BaseException):
            # _profile already swallows per-file LLM errors; a raise here
            # is unexpected. Log and skip — a missing profile degrades
            # gracefully to extension-based routing for that file.
            logger.warning(
                "profile_files: scan_id=%s profiling task raised: %s", scan_id, result
            )
            continue
        path, profile = result
        file_profiles[path] = profile.model_dump()

    async with AsyncSessionLocal() as db:
        repo = ScanRepository(db)
        await repo.update_scan_artifacts(scan_id, {"file_profiles": file_profiles})
        await repo.record_scan_event(scan_id, "PROFILING_FILES", EV_COMPLETED)

    logger.info(
        "profile_files: scan_id=%s profiled %d/%d file(s)",
        scan_id,
        len(file_profiles),
        len(files),
    )
    return {
        "file_profiles": file_profiles,
        "current_scan_status": STATUS_ANALYZING_CONTEXT,
    }
