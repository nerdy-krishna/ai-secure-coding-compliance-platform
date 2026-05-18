"""Shared TypedDicts for the worker LangGraph workflow.

Hoisted out of `worker_graph.py` so the per-node modules under
`workflows/nodes/` can import the state types without creating an
import cycle through `worker_graph.py` itself (G1 from the
split-worker-graph threat model).

Both `WorkerState` and `RelevantAgent` are re-exported from
`worker_graph.py` for back-compat — historic callers (e.g.
`workers/consumer.py`, the LangGraph checkpointer) keep importing
from the original location.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional, TypedDict

from app.core.schemas import FixResult, VulnerabilityFinding


class RelevantAgent(TypedDict):
    name: str
    description: str
    domain_query: Dict[str, Any]


class WorkerState(TypedDict):
    """The two-tier (utility + reasoning) state for the worker workflow."""

    scan_id: uuid.UUID
    scan_type: str
    current_scan_status: Optional[str]
    # The two LLM slots configured on the scan (#69). The reasoning slot
    # drives analysis / consolidation / merge; the utility slot drives
    # the profiler and fix-snippet verification. Slot resolution lives
    # in `shared.lib.llm_slots`; utility falls back to reasoning when None.
    reasoning_llm_config_id: Optional[uuid.UUID]
    utility_llm_config_id: Optional[uuid.UUID]
    # Per-stage LLM temperature map ({profiler, analysis, consolidation,
    # merge} → float) chosen at submit time (#78). `resolve_temperature`
    # falls back to 0.2 per stage when a stage or the map is missing.
    stage_temperatures: Optional[Dict[str, Any]]
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
    all_relevant_agents: Dict[str, RelevantAgent]
    live_codebase: Optional[Dict[str, str]]
    findings: List[VulnerabilityFinding]
    # Raw per-agent fix proposals collected by analyze_files_parallel_node and
    # consumed by consolidate_and_patch_node. Carries (finding, suggestion)
    # pairs before correlation; the correlated findings live in `findings`.
    proposed_fixes: Optional[List[FixResult]]
    agent_results: Optional[List[Dict[str, Any]]]
    # CycloneDX SBOM produced by `osv_runner` during the deterministic
    # prescan. Persisted to `Scan.bom_cyclonedx` on completion. May be
    # None when OSV is unavailable. (ADR-009 / §3.6.)
    bom_cyclonedx: Optional[Dict[str, Any]]
    # Decision payload returned by the prescan-approval interrupt;
    # carries `approved: bool` and `override_critical_secret: bool`.
    # Populated only between the interrupt return and the next route.
    prescan_approval: Optional[Dict[str, Any]]
    # Number of resume attempts on the prescan-approval interrupt; capped at 3
    # by `_route_after_prescan_approval` to prevent loop-back denial of service.
    resume_attempts: Optional[int]
    error_message: Optional[str]
