"""`analyze_files_parallel` worker-graph node.

Runs every relevant agent against every file in parallel (bounded by
``CONCURRENT_LLM_LIMIT``) and returns the union of findings + the raw
per-file fix proposals for downstream consolidation.

The string name registered via `workflow.add_node("analyze_files_parallel", ...)`
is part of the LangGraph checkpointer's on-disk contract — do not rename.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, cast

import networkx as nx

from app.core.schemas import (
    CodeChunk,
    FixResult,
    SpecializedAgentState,
    VulnerabilityFinding,
)
from app.infrastructure.agents.generic_specialized_agent import (
    build_generic_specialized_agent_graph,
)
from app.infrastructure.workflows.nodes.cost import CHUNK_ONLY_IF_LARGER_THAN
from app.infrastructure.workflows.state import WorkerState
from app.shared.analysis_tools.chunker import semantic_chunker
from app.shared.lib.agent_routing import resolve_agents_for_file
from app.shared.lib.analysis_dispatch import (
    LANE_SECONDARY,
    plan_agent_invocations,
    resolve_reasoning_lanes,
)
from app.shared.lib.scan_progress import EV_COMPLETED, EV_STARTED
from app.shared.lib.llm_slots import (
    LLMStep,
    resolve_llm_config_id,
    resolve_secondary_reasoning_llm_config_id,
    resolve_temperature,
)

logger = logging.getLogger(__name__)

CONCURRENT_LLM_LIMIT = 5


def _number_lines(code: str, start_line: int) -> str:
    """Prefix each line with its 1-based *file* line number (`NNN| `).

    The agent sees accurate file-relative line numbers — even for a
    chunk drawn from the middle of a large file — so the `line_number`
    it reports is a real anchor and the `vulnerable_snippet` it copies
    can be located precisely. The prompt tells it to drop the prefix.
    """
    lines = code.split("\n")
    width = len(str(start_line + len(lines) - 1))
    return "\n".join(
        f"{start_line + i:>{width}}| {line}" for i, line in enumerate(lines)
    )


async def analyze_files_parallel_node(state: WorkerState) -> Dict[str, Any]:
    """Single-pass analysis: every agent runs against the original code.

    Replaces the old iterative `dependency_aware_analysis_orchestrator`
    (D.5 decision, F.5.2). Key differences:
      - All files are analyzed in parallel (bounded by CONCURRENT_LLM_LIMIT).
        No topological ordering; no cross-file patch propagation — all agents
        see `live_codebase` (the ORIGINAL_SUBMISSION snapshot content).
      - No mid-graph DB writes: findings and proposed fixes collect into
        returned state. Consolidation + patch + snapshot persistence happen
        once in `consolidate_and_patch_node` and `save_results_node`.
      - The dependency graph is still used to build the per-file `dep_summary`
        that enriches each agent's prompt, since that summary is sourced from
        the repository map (stable regardless of processing order).
    """
    scan_id, scan_type = state["scan_id"], state["scan_type"]
    logger.info(
        "Starting single-pass analysis for scan %s in %r mode.", scan_id, scan_type
    )

    # Stage-event audit trail — RUNNING_AGENTS marker emitted at the
    # entry of the analyze phase so the timeline reflects "agents are
    # running" before the per-file FILE_ANALYZED rows arrive. Wrapped
    # in try/except so a logging-side error never aborts analysis.
    try:
        from app.infrastructure.database import (
            AsyncSessionLocal as _AsyncSessionLocal_start,
        )
        from app.infrastructure.database.repositories.scan_repo import (
            ScanRepository as _ScanRepository_start,
        )

        async with _AsyncSessionLocal_start() as _db_start:
            await _ScanRepository_start(_db_start).record_scan_event(
                scan_id, "RUNNING_AGENTS", EV_STARTED
            )
    except Exception as _e:
        logger.warning("RUNNING_AGENTS started-event emit failed: %s", _e)

    # --- REVISED GUARD CLAUSE BLOCK ---
    live_codebase = state.get("live_codebase")
    if not live_codebase:
        return {"error_message": "Orchestrator is missing 'live_codebase'."}

    repository_map = state.get("repository_map")
    if not repository_map:
        return {"error_message": "Orchestrator is missing 'repository_map'."}

    graph_data = state.get("dependency_graph")
    if not graph_data:
        return {"error_message": "Orchestrator is missing 'dependency_graph'."}
    dependency_graph = nx.node_link_graph(graph_data)  # Deserialize the graph

    all_relevant_agents = state.get("all_relevant_agents", {})
    if not all_relevant_agents:
        return {"error_message": "Orchestrator is missing 'all_relevant_agents'."}

    # Per-file analysis runs on the reasoning slot (#69) at the
    # analysis stage's per-scan temperature (#78).
    reasoning_llm_id = resolve_llm_config_id(LLMStep.ANALYSIS, state)
    if not reasoning_llm_id:
        return {"error_message": "Orchestrator is missing 'reasoning_llm_config_id'."}
    analysis_temperature = resolve_temperature(LLMStep.ANALYSIS, state)
    # --- END REVISED GUARD CLAUSE BLOCK ---

    # Dual-LLM analysis (#93): when the scan opted into a second
    # reasoning LLM, every routed agent runs once per lane and the two
    # findings sets union downstream in `consolidate_findings`. One
    # lane = today's single-pass analysis. The secondary lane uses the
    # same analysis temperature for now; #95 gives it its own.
    lanes = resolve_reasoning_lanes(
        primary_config_id=reasoning_llm_id,
        primary_temperature=analysis_temperature,
        secondary_config_id=resolve_secondary_reasoning_llm_config_id(state),
        secondary_temperature=analysis_temperature,
    )
    logger.info(
        "analyze: scan_id=%s reasoning lanes=%s",
        scan_id,
        [(lane.lane, str(lane.config_id)) for lane in lanes],
    )

    generic_agent_graph = build_generic_specialized_agent_graph()
    # One concurrency pool per distinct reasoning-LLM config. Two lanes
    # on different configs (different providers, independent rate
    # limits) each get a pool of CONCURRENT_LLM_LIMIT; two lanes on the
    # same config share one pool. Single-LLM scans keep one pool.
    semaphores: Dict[Any, asyncio.Semaphore] = {
        lane.pool_key: asyncio.Semaphore(CONCURRENT_LLM_LIMIT) for lane in lanes
    }

    def build_dep_summary(file_path: str) -> str:
        """Per-file dependency context. Pure read from repository_map; safe to
        compute concurrently across files."""
        if file_path not in dependency_graph:
            return ""
        dep_parts: List[str] = []
        for dep_path in dependency_graph.successors(file_path):
            dep_file_summary = repository_map.files.get(dep_path)
            if dep_file_summary and dep_file_summary.symbols:
                symbol_sigs = [
                    f"  - {s.type} {s.name} (line {s.line_number})"
                    for s in dep_file_summary.symbols[:15]
                ]
                dep_parts.append(f"# File: {dep_path}\n" + "\n".join(symbol_sigs))
        if not dep_parts:
            return ""
        return (
            "# --- [DEPENDENCY CONTEXT: symbols from imported files] ---\n"
            + "\n".join(dep_parts)
            + "\n# --- [END DEPENDENCY CONTEXT] ---\n\n"
        )

    def chunk_file(file_path: str, file_content: str) -> List[CodeChunk]:
        file_summary = repository_map.files.get(file_path)
        if not file_summary:
            return []
        token_count = len(file_content) / 4
        if token_count > CHUNK_ONLY_IF_LARGER_THAN:
            logger.info(
                "%s is a large file, applying chunking.",
                file_path,
                extra={"scan_id": str(scan_id)},
            )
            return semantic_chunker(file_content, file_summary)
        return [
            {
                "symbol_name": file_path,
                "code": file_content,
                "start_line": 1,
                "end_line": len(file_content.splitlines()),
            }
        ]

    async def run_agent_with_sem(pool_key, coro):
        async with semaphores[pool_key]:
            return await coro

    async def analyze_one_file(
        file_path: str,
    ) -> Dict[str, Any]:
        file_content = live_codebase.get(file_path)
        if not file_content:
            logger.warning(
                "analyze: skipping file — empty content",
                extra={"scan_id": str(scan_id), "file_path": file_path},
            )
            return {"findings": [], "fixes": [], "agent_calls": 0, "agent_failures": 0}

        chunks = chunk_file(file_path, file_content)
        if not chunks:
            logger.warning(
                "analyze: skipping file — no chunks produced",
                extra={
                    "scan_id": str(scan_id),
                    "file_path": file_path,
                    "in_repo_map": file_path in repository_map.files,
                    "repo_map_keys_sample": list(repository_map.files.keys())[:5],
                },
            )
            return {"findings": [], "fixes": [], "agent_calls": 0, "agent_failures": 0}

        # Content-based routing (#73): the file profile's applicable
        # domains narrow the agent set; falls back to extension-only
        # routing when the file has no profile.
        file_profile = (state.get("file_profiles") or {}).get(file_path) or {}
        relevant_agents = resolve_agents_for_file(
            file_path,
            all_relevant_agents,
            file_profile.get("applicable_domains"),
        )
        if not relevant_agents:
            logger.warning(
                "analyze: skipping file — no relevant agents",
                extra={
                    "scan_id": str(scan_id),
                    "file_path": file_path,
                    "all_agents_count": len(all_relevant_agents),
                },
            )
            return {"findings": [], "fixes": [], "agent_calls": 0, "agent_failures": 0}

        logger.info(
            "analyze: file accepted for analysis",
            extra={
                "scan_id": str(scan_id),
                "file_path": file_path,
                "chunk_count": len(chunks),
                "agent_count": len(relevant_agents),
            },
        )

        dep_summary = build_dep_summary(file_path)

        file_findings: List[VulnerabilityFinding] = []
        file_fixes: List[FixResult] = []
        # Per-lane call / failure counters (#93). Surfaced upstream so
        # the parent node can (a) mark the scan FAILED only when EVERY
        # lane is dead and (b) emit a degradation event when only the
        # secondary lane collapsed. 0 findings on a clean codebase is
        # fine; 0 findings because every LLM call raised is not.
        lane_calls: Dict[str, int] = {}
        lane_failures: Dict[str, int] = {}

        # Verified-findings prompt prefix (B4): pass the per-file
        # SAST scanner findings into the agent so it can avoid
        # re-flagging issues the deterministic scanners already found.
        prior_findings_all = state.get("findings") or []
        per_file_scanner_findings = [
            f
            for f in prior_findings_all
            if getattr(f, "source", None) in ("bandit", "semgrep", "gitleaks")
            and f.file_path == file_path
        ]

        for chunk in chunks:
            # The file-under-review code is line-numbered (file-relative);
            # dep_summary is kept as a separate, un-numbered context block
            # so the agent never confuses dependency context with the
            # file it must report line numbers and snippets against.
            numbered_code = _number_lines(chunk["code"], chunk["start_line"])
            code_under_review = (
                "=== CODE UNDER REVIEW "
                "(line-numbered; copy snippets WITHOUT the 'NNN| ' prefix) ===\n"
                f"{numbered_code}"
            )
            enriched_code = (
                f"{dep_summary}\n{code_under_review}"
                if dep_summary
                else code_under_review
            )
            # Dual-LLM dispatch (#93): expand the routed agents across
            # the reasoning lane(s). One lane → today's behaviour; two
            # lanes → every agent runs once per reasoning LLM, each on
            # its lane's config / temperature / concurrency pool.
            specs = plan_agent_invocations(relevant_agents, lanes)
            tasks = []
            for spec in specs:
                initial_agent_state: SpecializedAgentState = {
                    "scan_id": scan_id,
                    "llm_config_id": spec.lane.config_id,
                    "temperature": spec.lane.temperature,
                    "filename": file_path,
                    "code_snippet": enriched_code,
                    "file_content_for_verification": file_content,
                    "workflow_mode": (
                        "remediate"
                        if scan_type in ("REMEDIATE", "SUGGEST")
                        else "audit"
                    ),
                    "findings": [],
                    "fixes": [],
                    "error": None,
                    "prescan_findings_for_file": per_file_scanner_findings,
                }
                tasks.append(
                    run_agent_with_sem(
                        spec.lane.pool_key,
                        generic_agent_graph.ainvoke(
                            initial_agent_state,
                            config={"configurable": cast(dict, spec.agent)},
                        ),
                    )
                )

            agent_results = await asyncio.gather(*tasks, return_exceptions=True)
            # Per-agent diagnostics — historically this loop swallowed
            # every exception and None silently, which is why scans
            # were completing with 0 findings even though N agent
            # tasks were dispatched. Surface each outcome (with its
            # lane) so we can see *what* came back from the LangGraph
            # subagent calls.
            for idx, r in enumerate(agent_results):
                inv_spec = specs[idx] if idx < len(specs) else None
                lane_name = inv_spec.lane.lane if inv_spec else "?"
                agent_name = inv_spec.agent.get("name", "?") if inv_spec else "?"
                lane_calls[lane_name] = lane_calls.get(lane_name, 0) + 1
                if isinstance(r, BaseException):
                    lane_failures[lane_name] = lane_failures.get(lane_name, 0) + 1
                    logger.error(
                        "agent: ainvoke raised",
                        extra={
                            "scan_id": str(scan_id),
                            "file_path": file_path,
                            "agent": agent_name,
                            "lane": lane_name,
                            "exception_class": r.__class__.__name__,
                        },
                        exc_info=r,
                    )
                    continue
                if r is None:
                    lane_failures[lane_name] = lane_failures.get(lane_name, 0) + 1
                    logger.warning(
                        "agent: ainvoke returned None",
                        extra={
                            "scan_id": str(scan_id),
                            "file_path": file_path,
                            "agent": agent_name,
                            "lane": lane_name,
                        },
                    )
                    continue
                if isinstance(r, dict) and r.get("error"):
                    # An agent that returned an error dict (e.g. the LLM
                    # call 400'd and `generate_structured_output`
                    # surfaced it as `error`) IS a failed invocation —
                    # count it so the stage-level guards can act on it.
                    lane_failures[lane_name] = lane_failures.get(lane_name, 0) + 1
                    logger.warning(
                        "agent: returned error",
                        extra={
                            "scan_id": str(scan_id),
                            "file_path": file_path,
                            "agent": agent_name,
                            "lane": lane_name,
                            "error": str(r.get("error"))[:300],
                        },
                    )
                    continue
                file_findings.extend(r.get("findings", []))
                # The agent returns `fixes` as a separate list of FixResult
                # objects; collect them directly for the terminal consolidation.
                file_fixes.extend(r.get("fixes", []))

        # §3.10b: emit a `FILE_ANALYZED` ScanEvent so the SSE stream
        # can surface per-file progress mid-scan. The event carries
        # the file path and the count of agent-emitted findings; the
        # frontend ScanRunningPage uses these to render a per-file
        # progress widget without waiting for the whole scan to
        # complete. Wrapped in try/except so a logging-side error
        # never aborts the scan flow.
        try:
            from app.infrastructure.database import (
                AsyncSessionLocal as _AsyncSessionLocal,
            )
            from app.infrastructure.database.repositories.scan_repo import (
                ScanRepository as _ScanRepository,
            )

            async with _AsyncSessionLocal() as _db:
                await _ScanRepository(_db).create_scan_event(
                    scan_id=scan_id,
                    stage_name="FILE_ANALYZED",
                    status="COMPLETED",
                    details={
                        "file_path": file_path,
                        "findings_count": len(file_findings),
                        "fixes_count": len(file_fixes),
                    },
                )
        except Exception as e:
            logger.warning("FILE_ANALYZED event emit failed for %s: %s", file_path, e)

        return {
            "findings": file_findings,
            "fixes": file_fixes,
            "lane_calls": lane_calls,
            "lane_failures": lane_failures,
        }

    # All files analyzed in parallel. Concurrency across files is bounded
    # inside each run_agent_with_sem invocation (the same semaphore gates
    # agent calls regardless of which file they belong to).
    file_tasks = [analyze_one_file(fp) for fp in live_codebase.keys()]
    file_results = await asyncio.gather(*file_tasks, return_exceptions=True)

    all_scan_findings: List[VulnerabilityFinding] = []
    all_proposed_fixes: List[FixResult] = []
    # Per-lane totals aggregated across files (#93).
    lane_calls: Dict[str, int] = {}
    lane_failures: Dict[str, int] = {}
    failed_file_tasks = 0
    for r in file_results:
        if isinstance(r, BaseException):
            failed_file_tasks += 1
            logger.error(
                "File analysis task failed for scan %s: %s", scan_id, r, exc_info=r
            )
            continue
        all_scan_findings.extend(r.get("findings", []))
        all_proposed_fixes.extend(r.get("fixes", []))
        for _lane, _n in (r.get("lane_calls") or {}).items():
            lane_calls[_lane] = lane_calls.get(_lane, 0) + int(_n)
        for _lane, _n in (r.get("lane_failures") or {}).items():
            lane_failures[_lane] = lane_failures.get(_lane, 0) + int(_n)

    total_agent_calls = sum(lane_calls.values())
    total_agent_failures = sum(lane_failures.values())

    # Carry forward any findings already on state (e.g. deterministic
    # SAST findings from the prescan node) so they survive to
    # `correlate_findings_node` (which dedupes by (file_path, cwe,
    # line_number)) and on to `save_results_node`.
    prior_findings = state.get("findings") or []

    logger.info(
        "Single-pass analysis complete for scan %s: %d agent findings, %d prior findings, %d proposed fixes; "
        "agent_calls=%d agent_failures=%d failed_file_tasks=%d",
        scan_id,
        len(all_scan_findings),
        len(prior_findings),
        len(all_proposed_fixes),
        total_agent_calls,
        total_agent_failures,
        failed_file_tasks,
    )

    # Stage-level validation: if every agent invocation that fired
    # raised or returned None, the LLM analyze stage is broken
    # (rate-limiter not initialised, LLM API key invalid, RAG outage,
    # etc.). Fail the scan so the user sees `STATUS_FAILED` instead
    # of a misleading "completed with 0 findings". A clean codebase
    # with 0 findings reports total_agent_calls > 0 and 0 failures —
    # that's still a successful scan.
    if total_agent_calls > 0 and total_agent_failures == total_agent_calls:
        logger.error(
            "analyze: every agent invocation failed — marking scan FAILED",
            extra={
                "scan_id": str(scan_id),
                "agent_calls": total_agent_calls,
                "agent_failures": total_agent_failures,
                "files_analyzed": len(file_results),
            },
        )
        return {
            "findings": prior_findings,
            "proposed_fixes": [],
            "error_message": (
                f"Analyze stage failed: all {total_agent_calls} agent "
                f"invocations errored across {len(file_results)} file(s). "
                "Check worker logs for `agent: ainvoke raised` entries."
            ),
        }

    # Dual-LLM degradation (#93): the secondary reasoning lane fired but
    # every one of its calls failed (bad key / model down) while the
    # primary lane carried the scan. The scan still completes on the
    # primary model's findings; leave a timeline breadcrumb so the
    # operator knows their dual-LLM scan silently ran single-LLM. (The
    # both-lanes-dead case was already handled by the guard above.)
    secondary_calls = lane_calls.get(LANE_SECONDARY, 0)
    secondary_failures = lane_failures.get(LANE_SECONDARY, 0)
    if secondary_calls > 0 and secondary_failures == secondary_calls:
        logger.warning(
            "analyze: secondary reasoning LLM lane fully failed — scan "
            "continues single-LLM",
            extra={
                "scan_id": str(scan_id),
                "secondary_calls": secondary_calls,
                "secondary_failures": secondary_failures,
            },
        )
        try:
            from app.infrastructure.database import (
                AsyncSessionLocal as _AsyncSessionLocal_deg,
            )
            from app.infrastructure.database.repositories.scan_repo import (
                ScanRepository as _ScanRepository_deg,
            )

            async with _AsyncSessionLocal_deg() as _db_deg:
                await _ScanRepository_deg(_db_deg).create_scan_event(
                    scan_id=scan_id,
                    stage_name="SECONDARY_LLM_DEGRADED",
                    status="FAILED",
                    details={
                        "secondary_calls": secondary_calls,
                        "secondary_failures": secondary_failures,
                        "message": (
                            "Every second-reasoning-LLM call failed; the scan "
                            "completed on the primary model only."
                        ),
                    },
                )
        except Exception as _e:
            logger.warning("SECONDARY_LLM_DEGRADED event emit failed: %s", _e)

    try:
        from app.infrastructure.database import (
            AsyncSessionLocal as _AsyncSessionLocal_end,
        )
        from app.infrastructure.database.repositories.scan_repo import (
            ScanRepository as _ScanRepository_end,
        )

        async with _AsyncSessionLocal_end() as _db_end:
            await _ScanRepository_end(_db_end).record_scan_event(
                scan_id, "RUNNING_AGENTS", EV_COMPLETED
            )
    except Exception as _e:
        logger.warning("RUNNING_AGENTS completed-event emit failed: %s", _e)

    return {
        "findings": prior_findings + all_scan_findings,
        "proposed_fixes": all_proposed_fixes,
    }
