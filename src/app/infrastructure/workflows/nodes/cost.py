"""`estimate_cost` worker-graph node.

Performs a dry run to estimate input tokens/cost, persists the
estimate, and pauses on `interrupt()` for cost approval.

The string name registered via `workflow.add_node("estimate_cost", ...)`
is part of the LangGraph checkpointer's on-disk contract — do not rename.

Security controls
-----------------
V02.3.5 (Level 3) — Dual-control for high-value approvals:
    When the estimated cost meets or exceeds ``HIGH_VALUE_COST_USD`` the
    interrupt payload carries ``requires_dual_approval=True``.  The
    lifecycle service (``ScanLifecycleService.approve_scan``) is
    responsible for enforcing that two *distinct* approver user-ids are
    recorded before the LangGraph thread is resumed.  Lower-cost scans
    continue to use the existing single-approver path
    (``requires_dual_approval=False``).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

import networkx as nx
from langgraph.types import interrupt

from app.core.schemas import CodeChunk
from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database.repositories.llm_config_repo import LLMConfigRepository
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.workflows.state import WorkerState
from app.shared.analysis_tools.chunker import semantic_chunker
from app.shared.lib import cost_estimation
from app.shared.lib.agent_routing import resolve_agents_for_file
from app.shared.lib.scan_status import (
    STATUS_PENDING_APPROVAL,
    STATUS_QUEUED_FOR_SCAN,
)

logger = logging.getLogger(__name__)

# Files under this token size are passed whole to the analysis agents; only
# truly huge files (lockfiles, generated bundles, etc.) fall through to the
# semantic chunker. With 200k-context models + Anthropic prompt caching this
# is almost always cheaper than chunking, since chunking re-sends the same
# guidelines / dependency context per chunk.
CHUNK_ONLY_IF_LARGER_THAN = 150_000

# V02.3.5 — estimated costs at or above this threshold require dual-control
# approval (two distinct approver user-ids) before the scan may proceed.
HIGH_VALUE_COST_USD = 50.0


async def estimate_cost_node(state: WorkerState) -> Dict[str, Any]:
    """
    Performs a dry run of the analysis to generate a highly accurate cost estimate.
    """
    scan_id = state["scan_id"]
    logger.info("Performing cost estimation dry run for scan %s.", scan_id)

    # --- REVISED GUARD CLAUSE BLOCK ---
    repository_map = state.get("repository_map")
    if not repository_map:
        return {"error_message": "Cost estimation missing 'repository_map'."}

    dependency_graph_data = state.get("dependency_graph")
    if not dependency_graph_data:
        return {"error_message": "Cost estimation missing 'dependency_graph'."}

    reasoning_llm_config_id = state.get("reasoning_llm_config_id")
    if not reasoning_llm_config_id:
        return {"error_message": "Cost estimation missing 'reasoning_llm_config_id'."}

    live_codebase = state.get("live_codebase")
    if not live_codebase:
        return {"error_message": "Cost estimation missing 'live_codebase'."}

    all_relevant_agents = state.get("all_relevant_agents")
    if not all_relevant_agents:
        return {"error_message": "Cost estimation missing 'all_relevant_agents'."}
    # --- END REVISED GUARD CLAUSE BLOCK ---

    # Per-file profiles drive content-based agent routing (#73). Empty
    # when the profiler was skipped — routing then falls back to
    # extension-only and the estimate is the full-roster worst case.
    file_profiles: Dict[str, Any] = state.get("file_profiles") or {}

    try:
        dependency_graph = nx.node_link_graph(dependency_graph_data)
        processing_order = list(nx.topological_sort(dependency_graph))
    except nx.NetworkXUnfeasible:
        processing_order = sorted(list(live_codebase.keys()))

    # The utility slot drives the cheap steps (#69); it falls back to
    # the reasoning config when the submit left it unset.
    utility_llm_config_id = (
        state.get("utility_llm_config_id") or reasoning_llm_config_id
    )

    total_input_tokens = 0
    async with AsyncSessionLocal() as db:
        llm_repo = LLMConfigRepository(db)
        llm_config = await llm_repo.get_by_id_with_decrypted_key(
            reasoning_llm_config_id
        )
        if not llm_config:
            return {
                "error_message": f"LLM Config {reasoning_llm_config_id} not found for cost estimation."
            }
        if utility_llm_config_id == reasoning_llm_config_id:
            utility_llm_config = llm_config
        else:
            utility_llm_config = await llm_repo.get_by_id_with_decrypted_key(
                utility_llm_config_id
            )
            if not utility_llm_config:
                return {
                    "error_message": f"LLM Config {utility_llm_config_id} not found for cost estimation."
                }

        for file_path in processing_order:
            file_content = live_codebase[file_path]
            file_summary = repository_map.files.get(file_path)
            if not file_summary:
                continue

            chunks: List[CodeChunk] = []
            if (len(file_content) / 4) > CHUNK_ONLY_IF_LARGER_THAN:
                chunks = semantic_chunker(file_content, file_summary)
            else:
                chunks = [
                    {
                        "symbol_name": file_path,
                        "code": file_content,
                        "start_line": 1,
                        "end_line": 1,
                    }
                ]

            # Content-based routing (#73): the estimate reflects the
            # agent set this file will actually be routed to — driven by
            # its profile's applicable domains — not the worst-case
            # full-roster count. The profiler ran before this node so
            # `file_profiles` is populated.
            file_profile = file_profiles.get(file_path) or {}
            routed_agents = resolve_agents_for_file(
                file_path,
                all_relevant_agents,
                file_profile.get("applicable_domains"),
            )

            for chunk in chunks:
                for _ in routed_agents:
                    total_input_tokens += await cost_estimation.count_tokens(
                        chunk["code"], llm_config
                    )

    # Two-slot estimate (#69): the analysis dry-run tokens are priced on
    # the reasoning slot. Utility-slot usage is 0 here until the per-file
    # profiler (#71) feeds its dry-run tokens into the utility term.
    cost_details = cost_estimation.estimate_cost_two_slot(
        reasoning_config=llm_config,
        reasoning_input_tokens=total_input_tokens,
        utility_config=utility_llm_config,
        utility_input_tokens=0,
    )

    async with AsyncSessionLocal() as db:
        repo = ScanRepository(db)
        await repo.update_cost_and_status(
            scan_id, STATUS_PENDING_APPROVAL, cost_details
        )
        # Stage-event audit trail — surfaces ESTIMATING_COST as
        # complete on the timeline. Prior to this the timeline went
        # QUEUED → QUEUED_FOR_SCAN with no breadcrumb that the cost
        # node had run.
        await repo.create_scan_event(
            scan_id=scan_id,
            stage_name="ESTIMATING_COST",
            status="COMPLETED",
            details=cost_details,
        )

    # V02.3.5 — flag high-value scans so the lifecycle service can enforce
    # dual-control: two distinct approver user-ids must be recorded before
    # the LangGraph thread is resumed.  Lower-cost scans use the existing
    # single-approver path.
    estimated_cost_usd = cost_details.get("estimated_cost_usd", 0.0)
    requires_dual_approval = estimated_cost_usd >= HIGH_VALUE_COST_USD

    # Native LangGraph human-in-the-loop gate. The checkpointer persists
    # state here; execution resumes from this point when the approval
    # handler calls ainvoke(Command(resume=...)) on the same thread_id.
    # The resume payload lands as the return value of interrupt().
    approval_payload = interrupt(
        {
            "scan_id": str(scan_id),
            "estimated_cost": cost_details,
            "requires_dual_approval": requires_dual_approval,
        }
    )

    logger.info(
        "Cost-approval gate resumed for scan %s with payload: %s",
        scan_id,
        approval_payload,
    )
    return {"current_scan_status": STATUS_QUEUED_FOR_SCAN}
