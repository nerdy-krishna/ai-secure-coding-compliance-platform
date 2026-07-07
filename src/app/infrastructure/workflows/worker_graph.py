# src/app/infrastructure/workflows/worker_graph.py
"""LangGraph StateGraph wiring for the scan worker.

The node implementations live in ``app.infrastructure.workflows.nodes.*``
(split out by the split-worker-graph run, 2026-04-26). This module owns
only:

- StateGraph construction + node registration + edges + routing
- ``get_workflow()`` / ``close_workflow_resources()`` lifecycle
- back-compat re-exports of the moved node functions and helpers, so
  existing call sites (`workers/consumer.py`, the two
  `tests/test_worker_graph_*.py` tests) keep importing them as
  ``worker_graph.<name>`` attributes

The string identifiers passed to ``workflow.add_node("<name>", fn)``
are part of the LangGraph checkpointer's on-disk contract — in-flight
scans key off them. NEVER rename them without a checkpointer
migration.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

import psycopg
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from langgraph.graph import END, StateGraph
from langgraph.pregel import Pregel

from app.config.config import settings

from app.infrastructure.workflows.nodes.analyze import (
    analyze_files_parallel_node,
)
from app.infrastructure.workflows.nodes.classify import classify_files_node
from app.infrastructure.workflows.nodes.consolidate import (
    HAS_TREE_SITTER,
    _resolve_file_fix_conflicts,
    _run_merge_agent,
    _verify_syntax_with_treesitter,
    consolidate_and_patch_node,
)
from app.infrastructure.workflows.nodes.consolidate_findings import (
    consolidate_findings_node,
)
from app.infrastructure.workflows.nodes.global_consolidate import (
    global_consolidate_findings_node,
)
from app.infrastructure.workflows.nodes.save_raw_llm import (
    save_raw_llm_findings_node,
)
from app.infrastructure.workflows.nodes.cost import (
    CHUNK_ONLY_IF_LARGER_THAN,
    cost_gate_node,
    estimate_cost_node,
)
from app.infrastructure.workflows.nodes.error import handle_error_node
from app.infrastructure.workflows.nodes.prescan import (
    PRESCAN_FILE_BYTE_LIMIT,
    blocked_pre_llm_node,
    deterministic_prescan_node,
    pending_prescan_approval_node,
    user_decline_node,
)
from app.infrastructure.workflows.nodes.profile import (
    estimate_profiling_cost_node,
    profile_files_node,
    profiling_cost_gate_node,
)
from app.infrastructure.workflows.nodes.results import (
    save_final_report_node,
    save_results_node,
)
from app.infrastructure.workflows.nodes.retrieve import retrieve_and_prepare_data_node
from app.infrastructure.workflows.nodes.validate_cross_file import (
    validate_cross_file_node,
)
from app.infrastructure.workflows.nodes.verify import verify_patches_node
from app.infrastructure.workflows.state import RelevantAgent, WorkerState

# Status constants — re-exported from the shared module so downstream
# callers can keep importing them from `worker_graph` if they already do.
from app.shared.lib.scan_status import (  # noqa: F401
    STATUS_ANALYZING_CONTEXT,
    STATUS_BLOCKED_PRE_LLM,
    STATUS_BLOCKED_USER_DECLINE,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PENDING_APPROVAL,
    STATUS_PENDING_PRESCAN_APPROVAL,
    STATUS_PENDING_PROFILING_APPROVAL,
    STATUS_QUEUED_FOR_SCAN,
    STATUS_REMEDIATION_COMPLETED,
)

# Re-export concurrency limits at module level for backwards compat
# (tests and other modules import these from worker_graph).
CONCURRENT_LLM_LIMIT = settings.CONCURRENT_LLM_LIMIT
CONCURRENT_SCANNER_LIMIT = settings.CONCURRENT_SCANNER_LIMIT
CONCURRENT_CONSOLIDATION_LIMIT = settings.CONCURRENT_CONSOLIDATION_LIMIT
CONCURRENT_VALIDATION_LIMIT = settings.CONCURRENT_VALIDATION_LIMIT

logger = logging.getLogger(__name__)


__all__ = [
    # Public API the worker consumer + tests rely on:
    "WorkerState",
    "RelevantAgent",
    "get_workflow",
    "close_workflow_resources",
    "CONCURRENT_LLM_LIMIT",
    "CONCURRENT_SCANNER_LIMIT",
    "CONCURRENT_CONSOLIDATION_LIMIT",
    "CONCURRENT_VALIDATION_LIMIT",
    "PRESCAN_FILE_BYTE_LIMIT",
    "CHUNK_ONLY_IF_LARGER_THAN",
    "HAS_TREE_SITTER",
    # Node + helper re-exports for tests and any external module-attr access:
    "retrieve_and_prepare_data_node",
    "deterministic_prescan_node",
    "pending_prescan_approval_node",
    "user_decline_node",
    "blocked_pre_llm_node",
    "estimate_profiling_cost_node",
    "profiling_cost_gate_node",
    "profile_files_node",
    "estimate_cost_node",
    "cost_gate_node",
    "analyze_files_parallel_node",
    "consolidate_findings_node",
    "validate_cross_file_node",
    "consolidate_and_patch_node",
    "verify_patches_node",
    "save_results_node",
    "save_final_report_node",
    "handle_error_node",
    "_run_merge_agent",
    "_resolve_file_fix_conflicts",
    "_verify_syntax_with_treesitter",
    # Routing helpers (used by tests via attribute access):
    "should_continue",
    "_route_after_retrieve",
    "_route_after_prescan",
    "_route_after_prescan_approval",
    "_route_after_profiling_approval",
]


# --- FINAL WORKFLOW WIRING ---
#
# CRITICAL: the string names passed to `workflow.add_node(...)` below are
# part of the LangGraph checkpointer thread-state contract. In-flight scans
# (paused at `pending_prescan_approval` or `estimate_cost`) key off these
# strings. NEVER rename them here without a checkpointer migration.
workflow = StateGraph(WorkerState)

workflow.add_node("retrieve_and_prepare_data", retrieve_and_prepare_data_node)
workflow.add_node("classify_files", classify_files_node)
workflow.add_node("deterministic_prescan", deterministic_prescan_node)
workflow.add_node("pending_prescan_approval", pending_prescan_approval_node)
workflow.add_node("blocked_pre_llm", blocked_pre_llm_node)
workflow.add_node("user_decline", user_decline_node)
workflow.add_node("estimate_profiling_cost", estimate_profiling_cost_node)
workflow.add_node("profiling_cost_gate", profiling_cost_gate_node)
workflow.add_node("profile_files", profile_files_node)
workflow.add_node("estimate_cost", estimate_cost_node)
workflow.add_node("cost_gate", cost_gate_node)
workflow.add_node("analyze_files_parallel", analyze_files_parallel_node)
workflow.add_node("save_raw_llm_findings", save_raw_llm_findings_node)
workflow.add_node("consolidate_findings", consolidate_findings_node)
workflow.add_node("global_consolidate_findings", global_consolidate_findings_node)
workflow.add_node("validate_cross_file", validate_cross_file_node)
workflow.add_node("consolidate_and_patch", consolidate_and_patch_node)
workflow.add_node("verify_patches", verify_patches_node)
workflow.add_node("save_results", save_results_node)
workflow.add_node("save_final_report", save_final_report_node)
workflow.add_node("handle_error", handle_error_node)

workflow.set_entry_point("retrieve_and_prepare_data")


def should_continue(state: WorkerState) -> str:
    return "handle_error" if state.get("error_message") else "continue"


def _route_after_retrieve(state: WorkerState) -> str:
    """Retrieval either fails early or proceeds to deterministic classification."""
    return "handle_error" if state.get("error_message") else "classify_files"


def _route_after_prescan(state: WorkerState) -> str:
    """Route after the deterministic SAST pre-pass (ADR-009).

    - Hard prescan failure → `handle_error` (rare; per N15 the prescan
      node already swallows scanner crashes and returns `findings=[]`).
    - Findings non-empty → pause at `pending_prescan_approval` for
      operator review (replaces the pre-ADR-009 Critical-Gitleaks
      auto-block — that path now fires only on user-decline-of-override
      after the human has seen the finding).
    - Findings empty → profiling-cost gate at `estimate_profiling_cost`
      (#71). The profiling gate fires even with zero prescan findings.
    """
    if state.get("error_message"):
        return "handle_error"
    findings = state.get("findings") or []
    if findings:
        return "pending_prescan_approval"
    return "estimate_profiling_cost"


def _route_after_prescan_approval(state: WorkerState) -> str:
    """Route after the prescan-approval interrupt resumes (ADR-009).

    Reads the approval payload (returned by `interrupt()` and stamped
    into ``state.prescan_approval`` by `pending_prescan_approval_node`)
    plus the findings-state and dispatches:

    - ``approved=False`` → terminal `user_decline` (operator clicked
      Stop on the prescan card).
    - ``approved=True`` AND any Critical Gitleaks finding present
      AND ``override_critical_secret=False`` → terminal
      `blocked_pre_llm` (operator declined the override modal).
    - Otherwise → continue to the profiling-cost gate at
      `estimate_profiling_cost` (#71).
    """
    if state.get("error_message"):
        return "handle_error"

    # V02.4.1: anti-automation — cap resume attempts per scan to 3.
    # The counter is incremented inside `pending_prescan_approval_node` so the
    # checkpointer persists it; we only read it here.
    resume_attempts = state.get("resume_attempts") or 0
    if resume_attempts > 3:
        logger.warning(
            "audit.prescan_approval_routed: too many resume attempts, declining",
            extra={
                "scan_id": str(state.get("scan_id")),
                "resume_attempts": resume_attempts,
            },
        )
        return "user_decline"

    payload = state.get("prescan_approval") or {}

    findings = state.get("findings") or []
    has_critical_secret = any(
        getattr(f, "source", None) == "gitleaks"
        and (f.severity or "").lower() == "critical"
        for f in findings
    )
    critical_gitleaks_count = sum(
        1
        for f in findings
        if getattr(f, "source", None) == "gitleaks"
        and (f.severity or "").lower() == "critical"
    )

    # V16.3.3: emit audit log for every routing decision at this security gate.
    logger.info(
        "audit.prescan_approval_routed",
        extra={
            "scan_id": str(state.get("scan_id")),
            "approved": bool(payload.get("approved")),
            "override_critical_secret": bool(payload.get("override_critical_secret")),
            "approver_user_id": payload.get("approver_user_id"),
            "critical_gitleaks_count": critical_gitleaks_count,
        },
    )

    # V02.2.3: reject contradictory payloads — override without approval, or
    # override when there are no Critical Gitleaks findings present.
    override = payload.get("override_critical_secret")
    approved = payload.get("approved")
    if override is True and approved is not True:
        return "user_decline"
    if override is True and not has_critical_secret:
        return "user_decline"

    # V02.2.1: use strict identity check (is True) so non-bool truthy values
    # such as 'yes' or 1 are rejected rather than accepted.
    if approved is not True:
        return "user_decline"
    if has_critical_secret and override is not True:
        return "blocked_pre_llm"
    return "estimate_profiling_cost"


def _route_after_profiling_approval(state: WorkerState) -> str:
    """Route after the profiling-cost interrupt resumes (#71).

    Reads the approval payload stamped into ``state.profiling_approval``
    by `estimate_profiling_cost_node`:

    - ``approved=False`` → terminal `user_decline` (operator declined
      the profiling spend).
    - ``approved=True`` → continue to `profile_files`.

    `approved` is strict-identity-checked so non-bool truthy values are
    rejected, matching the prescan-approval gate.
    """
    if state.get("error_message"):
        return "handle_error"
    payload = state.get("profiling_approval") or {}
    if payload.get("approved") is not True:
        logger.info(
            "audit.profiling_approval_routed: declined scan_id=%s",
            state.get("scan_id"),
        )
        return "user_decline"
    return "profile_files"


workflow.add_conditional_edges(
    "retrieve_and_prepare_data",
    _route_after_retrieve,
    {
        "classify_files": "classify_files",
        "handle_error": "handle_error",
    },
)
workflow.add_conditional_edges(
    "classify_files",
    should_continue,
    {"continue": "deterministic_prescan", "handle_error": "handle_error"},
)
workflow.add_conditional_edges(
    "deterministic_prescan",
    _route_after_prescan,
    {
        "estimate_profiling_cost": "estimate_profiling_cost",
        "pending_prescan_approval": "pending_prescan_approval",
        "handle_error": "handle_error",
    },
)
# pending_prescan_approval calls interrupt(); the graph pauses there,
# the checkpointer flushes state, and the worker yields. On approval,
# the worker calls ainvoke(Command(resume=...)) and the post-resume
# router decides where to go next.
workflow.add_conditional_edges(
    "pending_prescan_approval",
    _route_after_prescan_approval,
    {
        "estimate_profiling_cost": "estimate_profiling_cost",
        "blocked_pre_llm": "blocked_pre_llm",
        "user_decline": "user_decline",
        "handle_error": "handle_error",
    },
)
workflow.add_edge("blocked_pre_llm", END)
workflow.add_edge("user_decline", END)

# Profiling-cost gate split (#84): `estimate_profiling_cost` is a work
# node that runs once (estimate + events), then hands to the bare
# `profiling_cost_gate` node which owns the interrupt(). On resume the
# post-resume router sends the scan to the profiler or to a terminal
# user-decline.
workflow.add_conditional_edges(
    "estimate_profiling_cost",
    should_continue,
    {"continue": "profiling_cost_gate", "handle_error": "handle_error"},
)
workflow.add_conditional_edges(
    "profiling_cost_gate",
    _route_after_profiling_approval,
    {
        "profile_files": "profile_files",
        "user_decline": "user_decline",
        "handle_error": "handle_error",
    },
)
workflow.add_conditional_edges(
    "profile_files",
    should_continue,
    {"continue": "estimate_cost", "handle_error": "handle_error"},
)

# Analysis-cost gate split (#84): `estimate_cost` is a work node that
# runs once (dry-run estimate + events), then hands to the bare
# `cost_gate` node which owns the interrupt(). On approval the worker
# calls ainvoke(Command(resume=...)) and execution continues to
# analyze_files_parallel.
workflow.add_conditional_edges(
    "estimate_cost",
    should_continue,
    {"continue": "cost_gate", "handle_error": "handle_error"},
)
workflow.add_conditional_edges(
    "cost_gate",
    should_continue,
    {"continue": "analyze_files_parallel", "handle_error": "handle_error"},
)

workflow.add_conditional_edges(
    "analyze_files_parallel",
    should_continue,
    {"continue": "save_raw_llm_findings", "handle_error": "handle_error"},
)
workflow.add_edge("save_raw_llm_findings", "consolidate_findings")
workflow.add_conditional_edges(
    "consolidate_findings",
    should_continue,
    {"continue": "global_consolidate_findings", "handle_error": "handle_error"},
)
workflow.add_conditional_edges(
    "global_consolidate_findings",
    should_continue,
    {"continue": "validate_cross_file", "handle_error": "handle_error"},
)
# validate_cross_file is permanently wired but no-ops (no state change,
# no timeline event) unless the scan opted in to cross-file validation
# (#81). An opted-out scan's pipeline is unchanged.
workflow.add_conditional_edges(
    "validate_cross_file",
    should_continue,
    {"continue": "consolidate_and_patch", "handle_error": "handle_error"},
)
workflow.add_conditional_edges(
    "consolidate_and_patch",
    should_continue,
    {"continue": "verify_patches", "handle_error": "handle_error"},
)
workflow.add_conditional_edges(
    "verify_patches",
    should_continue,
    {"continue": "save_results", "handle_error": "handle_error"},
)
workflow.add_conditional_edges(
    "save_results",
    should_continue,
    {"continue": "save_final_report", "handle_error": "handle_error"},
)
workflow.add_edge("save_final_report", END)
workflow.add_edge("handle_error", END)


_workflow: Optional[Pregel] = None
_checkpointer_conn: Optional[psycopg.AsyncConnection] = None
_workflow_init_lock = asyncio.Lock()


async def get_workflow() -> Pregel:
    # V15.4.1: double-checked locking prevents concurrent coroutines from each
    # creating a psycopg.AsyncConnection and compiling the workflow.
    global _workflow, _checkpointer_conn
    if _workflow is not None:
        return _workflow
    async with _workflow_init_lock:
        if _workflow is not None:
            return _workflow
        if not settings.ASYNC_DATABASE_URL:
            raise ValueError("ASYNC_DATABASE_URL must be configured.")
        if _checkpointer_conn is None or _checkpointer_conn.closed:
            # V16.4.1: use a plain string literal — no f-string, no variable interpolation.
            logger.info("Creating new psycopg async connection for checkpointer")
            try:
                conn_url = settings.ASYNC_DATABASE_URL.replace(
                    "postgresql+asyncpg://", "postgresql://"
                )
                _checkpointer_conn = await psycopg.AsyncConnection.connect(conn_url)
            except Exception as e:
                # V16.3.4: log without interpolating `e` (which can contain DSN
                # fragments); exc_info=True still gives the full traceback to ops.
                logger.error("checkpointer_connect_failed", exc_info=True)
                raise RuntimeError("Checkpointer connection failed") from e
        checkpointer = AsyncPostgresSaver(conn=_checkpointer_conn)  # type: ignore
        _workflow = workflow.compile(checkpointer=checkpointer)
        # V16.4.1: plain string, no f-string interpolation.
        logger.info(
            "Main worker workflow compiled and ready with PostgreSQL checkpointer"
        )
        return _workflow


async def close_workflow_resources():
    global _checkpointer_conn
    if _checkpointer_conn and not _checkpointer_conn.closed:
        logger.info("Closing checkpointer database connection.")
        await _checkpointer_conn.close()
        _checkpointer_conn = None
