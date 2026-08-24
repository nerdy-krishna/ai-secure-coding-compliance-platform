"""Shared TypedDicts for the worker LangGraph workflow.

Hoisted out of `worker_graph.py` so the per-node modules under
`workflows/nodes/` can import the state types without creating an
import cycle through `worker_graph.py` itself (G1 from the
split-worker-graph threat model).

Callers import these state contracts directly rather than through the graph
wiring module.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, NotRequired, Optional, TypedDict

from app.core.schemas import FixResult, VulnerabilityFinding


class RelevantAgent(TypedDict):
    name: str
    description: str
    domain_query: Dict[str, Any]


class WorkerState(TypedDict):
    """The two-tier (utility + reasoning) state for the worker workflow."""

    scan_id: uuid.UUID
    attempt_id: Optional[uuid.UUID]
    scan_type: str
    current_scan_status: Optional[str]
    # New split-pool scans checkpoint between result persistence and terminal
    # report generation. Missing/false preserves the N-1 straight-through
    # graph contract for existing checkpoints and the unified worker.
    distributed_worker_pools: NotRequired[bool]
    # Set only after the internal report interrupt resumes. It lets a
    # redelivery prove the exact outbox already advanced and continue from the
    # next durable checkpoint without replaying Command(resume).
    report_handoff_outbox_id: NotRequired[str]
    # The two LLM slots configured on the scan (#69). The reasoning slot
    # drives analysis / consolidation / patch-evidence judgement; the utility slot drives
    # the profiler. Slot resolution lives
    # in `shared.lib.llm_slots`; utility falls back to reasoning when None.
    reasoning_llm_config_id: Optional[uuid.UUID]
    utility_llm_config_id: Optional[uuid.UUID]
    # Optional second reasoning LLM for the analysis stage (#93 / PRD
    # #91). When set, `analyze_files_parallel` runs every routed agent
    # on both this config and `reasoning_llm_config_id`. None ⇒ today's
    # single-LLM analysis. Set from `Scan.secondary_reasoning_llm_config_id`
    # by `retrieve`.
    secondary_reasoning_llm_config_id: Optional[uuid.UUID]
    # Per-stage LLM temperature map ({profiler, analysis, consolidation}
    # → float) chosen at submit time (#78). Patch-evidence re-analysis inherits
    # the consolidation value. `resolve_temperature`
    # falls back to 0.2 per stage when a stage or the map is missing.
    stage_temperatures: Optional[Dict[str, Any]]
    # Opt-in (#92 / PRD #91): when true, `resolve_temperature` returns
    # None for every stage so no temperature is sent on any LLM call and
    # each model runs at its provider default. Set from
    # `Scan.disable_temperature` by `retrieve`.
    disable_temperature: Optional[bool]
    # Opt-in cross-file finding validation (#81 / PRD #75). When true,
    # the `validate_cross_file` node re-judges each eligible consolidated
    # finding against its cross-file context; when false / None the node
    # is a no-op. Set from `Scan.cross_file_validation` by `retrieve`.
    cross_file_validation: Optional[bool]
    # Opt-in deeper analysis of vendor/minified/static assets. Default false;
    # classification policy otherwise skips low-value LLM/Semgrep work.
    deep_vendor_scan: Optional[bool]
    files: Optional[Dict[str, str]]
    initial_file_map: Optional[Dict[str, str]]
    final_file_map: Optional[Dict[str, str]]
    # Path → patched content map produced by `consolidate_and_patch_node`
    # for files that actually had fixes applied. Consumed by the §3.9
    # `verify_patches_node` so it can re-run Semgrep over the post-
    # remediation content without round-tripping through the source-
    # file repository. None for non-REMEDIATE scans.
    patched_files: Optional[Dict[str, str]]
    repository_map: Optional[Any]
    dependency_graph: Optional[Any]
    # Per-file profiles produced by `profile_files_node` (#71): a
    # {file_path: {summary, security_relevant_operations,
    # applicable_domains}} map, persisted to `Scan.file_profiles`.
    file_profiles: Optional[Dict[str, Any]]
    # Decision payload returned by the profiling-cost interrupt; carries
    # `approved: bool`. Populated only between the interrupt return and
    # the next route.
    profiling_approval: Optional[Dict[str, Any]]
    # Decision payload returned by the full-analysis cost interrupt.
    cost_approval: Optional[Dict[str, Any]]
    all_relevant_agents: Dict[str, RelevantAgent]
    live_codebase: Optional[Dict[str, str]]
    findings: List[VulnerabilityFinding]
    # Governed per-agent patch candidates. Consolidation stamps the surviving
    # canonical finding, disposition, and decision reason before remediation
    # is allowed to consume a candidate.
    fix_candidates: Optional[List[FixResult]]
    # Exact raw -> canonical consolidation decisions. Unlike the timeline
    # event projection, this state contract is updated by global consolidation.
    finding_lineage: Optional[List[Dict[str, Any]]]
    # Versioned deterministic range/hunk plan for SUGGEST and REMEDIATE.
    patch_plan: Optional[Dict[str, Any]]
    patch_validation_summary: Optional[Dict[str, Any]]
    agent_results: Optional[List[Dict[str, Any]]]
    # CycloneDX SBOM produced by `osv_runner` during the deterministic
    # prescan. Persisted to `Scan.bom_cyclonedx` on completion. May be
    # None when OSV is unavailable. (ADR-009 / §3.6.)
    bom_cyclonedx: Optional[Dict[str, Any]]
    # Decision payload returned by the prescan-approval interrupt;
    # carries `approved: bool` and `override_critical_secret: bool`.
    # Populated only between the interrupt return and the next route.
    prescan_approval: Optional[Dict[str, Any]]
    # Current durable HITL gate identity. Replaced for each gate occurrence;
    # queue payloads and interrupt returns must match its gate_id.
    active_approval_gate: NotRequired[Optional[Dict[str, Any]]]
    # Number of resume attempts on the prescan-approval interrupt; capped at 3
    # by `_route_after_prescan_approval` to prevent loop-back denial of service.
    resume_attempts: Optional[int]
    error_message: Optional[str]
    # Analysis batch number — incremented on each restart/resume so
    # multiple generations of findings can coexist in the DB.
    _batch: int
    # Exact graph-node completion order, persisted atomically in the LangGraph
    # checkpoint by `cancellation_aware`. Manual resume uses the same thread;
    # manual restart deletes the thread before starting a clean run.
    completed_stages: NotRequired[List[str]]
