"""`estimate_cost` worker-graph node.

Performs a dry run to estimate input tokens/cost, persists the
estimate, and pauses on `interrupt()` for cost approval.

The string name registered via `workflow.add_node("estimate_cost", ...)`
is part of the LangGraph checkpointer's on-disk contract — do not rename.

Security controls
-----------------
V02.3.5 (Level 3) — Dual-control for high-value approvals:
    When the estimated cost meets or exceeds ``HIGH_VALUE_COST_USD`` the
    persisted estimate carries ``requires_dual_approval=True``. The field
    is an explicit contract for the future dual-control workflow; the
    current lifecycle still has a single approval endpoint and must not be
    represented as enforcing two distinct approvers.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict

import networkx as nx
from langgraph.types import interrupt

from app.infrastructure.agents.generic_specialized_agent import (
    analysis_response_schema_text,
    render_analysis_prompt_envelope,
)
from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database.repositories.llm_config_repo import LLMConfigRepository
from app.infrastructure.database.repositories.llm_usage_repo import LLMUsageRepository
from app.infrastructure.database.repositories.llm_usage_repo import (
    LLMPriceOverrideRepository,
)
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.database.repositories.approval_gate_repo import (
    ApprovalGateRepository,
    approval_gate_payload,
)
from app.infrastructure.workflows.state import WorkerState
from app.infrastructure.llm_client_rate_limiter import get_provider_limits
from app.shared.lib import cost_estimation
from app.shared.lib.analysis_envelope import (
    build_code_chunks,
    build_dependency_summary,
    build_enriched_code,
)
from app.shared.lib.approval_policy import requires_dual_cost_approval
from app.shared.lib.agent_routing import resolve_agents_for_file
from app.shared.lib.llm_estimation import calibrate_estimate
from app.shared.lib.scan_progress import (
    EV_COMPLETED,
    EV_STARTED,
    EV_WAITING,
    STAGE_COST_REVIEW,
)
from app.shared.lib.scan_status import (
    STATUS_PENDING_APPROVAL,
    STATUS_QUEUED_FOR_SCAN,
)

logger = logging.getLogger(__name__)


def _estimate_processing_seconds(*, configs, tokens_per_config) -> int:
    estimates: list[float] = []
    for cfg, tokens in zip(configs, tokens_per_config):
        if cfg is None:
            continue
        provider_rpm, provider_tpm = get_provider_limits(cfg.provider)
        rpm = getattr(cfg, "requests_per_minute", None) or provider_rpm
        tpm = getattr(cfg, "tokens_per_minute", None) or provider_tpm
        calls = max(1, int(tokens > 0))
        estimates.append(max((calls / max(1, rpm)) * 60, (tokens / max(1, tpm)) * 60))
    return int(max(estimates or [0]))


def _rate_limit_warnings(*, configs, tokens_per_config) -> list[Dict[str, Any]]:
    warnings: list[Dict[str, Any]] = []
    for cfg, tokens in zip(configs, tokens_per_config):
        if cfg is None:
            continue
        max_prompt = getattr(cfg, "max_prompt_tokens", None)
        if max_prompt and tokens > max_prompt:
            warnings.append(
                {
                    "llm_config_id": str(cfg.id),
                    "model": cfg.model_name,
                    "warning": "estimated_prompt_tokens_exceed_configured_max",
                    "estimated_tokens": int(tokens),
                    "max_prompt_tokens": int(max_prompt),
                }
            )
    return warnings


async def estimate_cost_node(state: WorkerState) -> Dict[str, Any]:
    """
    Performs a dry run of the analysis to generate a highly accurate cost estimate.
    """
    scan_id = state["scan_id"]
    logger.info("Performing cost estimation dry run for scan %s.", scan_id)

    async with AsyncSessionLocal() as db:
        await ScanRepository(db).record_scan_event(
            scan_id, "ESTIMATING_COST", EV_STARTED
        )

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

    # Optional second reasoning LLM (#93): the analysis pass is priced
    # a second time at this config's rate. None ⇒ single-LLM estimate,
    # unchanged.
    secondary_reasoning_config_id = state.get("secondary_reasoning_llm_config_id")

    total_input_tokens = 0
    secondary_input_tokens = 0
    rendered_envelopes: list[str] = []
    planned_requests_per_lane = 0
    secondary_reasoning_config = None
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

        if secondary_reasoning_config_id:
            if secondary_reasoning_config_id == reasoning_llm_config_id:
                secondary_reasoning_config = llm_config
            elif secondary_reasoning_config_id == utility_llm_config_id:
                secondary_reasoning_config = utility_llm_config
            else:
                secondary_reasoning_config = (
                    await llm_repo.get_by_id_with_decrypted_key(
                        secondary_reasoning_config_id
                    )
                )
                if not secondary_reasoning_config:
                    return {
                        "error_message": (
                            f"LLM Config {secondary_reasoning_config_id} not "
                            "found for cost estimation."
                        )
                    }

        price_repo = LLMPriceOverrideRepository(db)
        reasoning_price_snapshot = await price_repo.active_snapshot(llm_config.id)
        utility_price_snapshot = await price_repo.active_snapshot(utility_llm_config.id)
        secondary_price_snapshot = (
            await price_repo.active_snapshot(secondary_reasoning_config.id)
            if secondary_reasoning_config is not None
            else None
        )

        prior_findings_all = state.get("findings") or []
        workflow_mode = (
            "remediate"
            if state.get("scan_type") in ("REMEDIATE", "SUGGEST")
            else "audit"
        )
        response_schema = analysis_response_schema_text()
        for file_path in processing_order:
            file_content = live_codebase[file_path]
            chunks = build_code_chunks(file_path, file_content, repository_map)
            dependency_summary = build_dependency_summary(
                file_path, dependency_graph, repository_map
            )

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

            scanner_findings = [
                finding
                for finding in prior_findings_all
                if getattr(finding, "source", None) in ("bandit", "semgrep", "gitleaks")
                and finding.file_path == file_path
            ]
            for chunk in chunks:
                enriched_code = build_enriched_code(chunk, dependency_summary)
                for agent_config in routed_agents:
                    agent_name = str(agent_config.get("name") or "agent")
                    try:
                        system_prompt, user_prompt, _ = (
                            await render_analysis_prompt_envelope(
                                agent_name=agent_name,
                                agent_description=agent_config.get("description") or "",
                                domain_query=agent_config.get("domain_query") or {},
                                filename=file_path,
                                code_bundle=enriched_code,
                                workflow_mode=workflow_mode,
                                scanner_findings=scanner_findings,
                            )
                        )
                    except (LookupError, RuntimeError) as exc:
                        return {
                            "error_message": (
                                f"Could not render the analysis envelope for "
                                f"{agent_name} on {file_path}: {exc}"
                            )
                        }
                    rendered_envelope = (
                        f"{system_prompt or ''}\n\n{user_prompt}\n\n{response_schema}"
                    )
                    rendered_envelopes.append(rendered_envelope)
                    total_input_tokens += await cost_estimation.count_tokens(
                        rendered_envelope, llm_config
                    )
                    planned_requests_per_lane += 1

        if secondary_reasoning_config is not None:
            for rendered_envelope in rendered_envelopes:
                secondary_input_tokens += await cost_estimation.count_tokens(
                    rendered_envelope, secondary_reasoning_config
                )

        usage_repo = LLMUsageRepository(db)
        reasoning_observations = await usage_repo.recent_estimation_observations(
            llm_config_id=llm_config.id,
            stage="analysis",
        )
        utility_observations = await usage_repo.recent_estimation_observations(
            llm_config_id=utility_llm_config.id,
            stage="analysis",
        )
        secondary_observations = []
        if secondary_reasoning_config is not None:
            secondary_observations = await usage_repo.recent_estimation_observations(
                llm_config_id=secondary_reasoning_config.id,
                stage="analysis",
            )

    # Two-slot estimate (#69): the analysis dry-run tokens are priced on
    # the reasoning slot. Utility-slot usage is 0 here until the per-file
    # profiler (#71) feeds its dry-run tokens into the utility term.
    # Dual-LLM (#93): when a second reasoning LLM is configured, the
    # analysis pass is priced again at its rate over the SAME token
    # basis (every routed agent runs once per reasoning LLM), so the
    # `reasoning_secondary` slot reuses `total_input_tokens`.
    cost_details = cost_estimation.estimate_cost_two_slot(
        reasoning_config=llm_config,
        reasoning_input_tokens=total_input_tokens,
        utility_config=utility_llm_config,
        utility_input_tokens=0,
        secondary_reasoning_config=secondary_reasoning_config,
        secondary_reasoning_input_tokens=(
            secondary_input_tokens if secondary_reasoning_config is not None else 0
        ),
        calibrations={
            "reasoning": calibrate_estimate("analysis", reasoning_observations),
            "utility": calibrate_estimate("analysis", utility_observations),
            "secondary_reasoning": calibrate_estimate(
                "analysis", secondary_observations
            ),
        },
        price_snapshots={
            "reasoning": reasoning_price_snapshot,
            "utility": utility_price_snapshot,
            "secondary_reasoning": secondary_price_snapshot,
        },
        planned_request_counts={
            "reasoning": planned_requests_per_lane,
            "utility": 0,
            "secondary_reasoning": (
                planned_requests_per_lane
                if secondary_reasoning_config is not None
                else 0
            ),
        },
        stage="analysis",
    )
    cost_details["planned_request_count"] = planned_requests_per_lane * (
        2 if secondary_reasoning_config is not None else 1
    )
    cost_details["rendered_envelope_includes"] = [
        "system_prompt",
        "domain_scope",
        "retrieved_rag_patterns",
        "verified_scanner_findings",
        "dependency_context",
        "line_numbered_code",
        "structured_output_schema",
    ]

    processing_seconds = _estimate_processing_seconds(
        configs=[llm_config]
        + ([secondary_reasoning_config] if secondary_reasoning_config else []),
        tokens_per_config=[total_input_tokens]
        + ([secondary_input_tokens] if secondary_reasoning_config else []),
    )
    cost_details["estimated_processing_seconds"] = processing_seconds
    cost_details["rate_limit_warnings"] = _rate_limit_warnings(
        configs=[llm_config]
        + ([secondary_reasoning_config] if secondary_reasoning_config else []),
        tokens_per_config=[total_input_tokens]
        + ([secondary_input_tokens] if secondary_reasoning_config else []),
    )

    # V02.3.5 — flag high-value scans for the lifecycle service's
    # dual-control check; carried in the gate's interrupt payload.
    requires_dual_approval = requires_dual_cost_approval(cost_details)
    cost_details["requires_dual_approval"] = requires_dual_approval

    async with AsyncSessionLocal() as db:
        repo = ScanRepository(db)
        changed = await repo.update_cost_and_status(
            scan_id, STATUS_PENDING_APPROVAL, cost_details, commit=False
        )
        if not changed:
            await db.rollback()
            return {"error_message": "Scan left analysis-cost approval path."}
        await repo.record_scan_event(
            scan_id,
            "ESTIMATING_COST",
            EV_COMPLETED,
            details=cost_details,
            commit=False,
        )
        gate = await ApprovalGateRepository(db).create_or_get_pending(
            scan_id=scan_id,
            kind="cost_approval",
            node_name="cost_gate",
            display_name="Approve full security analysis cost",
            purpose=(
                "Approve the full multi-agent security-analysis estimate after "
                "file profiling is complete."
            ),
            evidence={"cost_details": cost_details, "stage": "analysis"},
            commit=False,
        )
        gate_data = approval_gate_payload(gate)
        # The gate's WAITING event — parks `scans.status` at
        # PENDING_COST_APPROVAL. The bare `cost_gate` node owns the
        # interrupt(), so this work node runs exactly once (#84).
        await repo.record_scan_event(
            scan_id,
            STAGE_COST_REVIEW,
            EV_WAITING,
            details={
                **gate_data,
                "requires_dual_approval": requires_dual_approval,
                "dual_approval_enforced": False,
            },
        )

    logger.info("Cost-estimate work node complete for scan %s — gated.", scan_id)
    return {"active_approval_gate": gate_data}


async def cost_gate_node(state: WorkerState) -> Dict[str, Any]:
    """Bare analysis-cost interrupt gate (#84).

    Contains only `interrupt()` plus the gate's `COMPLETED` event — no
    pre-interrupt side effects — so a LangGraph resume re-runs nothing
    that could duplicate an event or clobber `scans.status`. The
    `estimate_cost` work node already emitted the `COST_REVIEW/WAITING`
    event and set the pause status.
    """
    scan_id = state["scan_id"]
    gate_data = state.get("active_approval_gate") or {}
    if not gate_data.get("gate_id"):
        async with AsyncSessionLocal() as db:
            gate = await ApprovalGateRepository(db).get_active_for_scan(scan_id)
            if gate is not None:
                gate_data = approval_gate_payload(gate)
    if not gate_data.get("gate_id"):
        return {"error_message": "Analysis-cost approval gate identity is missing."}
    approval_payload = interrupt(gate_data)
    logger.info(
        "Cost-approval gate resumed for scan %s with payload: %s",
        scan_id,
        approval_payload,
    )
    if approval_payload.get("gate_id") != gate_data["gate_id"]:
        return {"error_message": "Stale analysis-cost gate payload rejected."}
    async with AsyncSessionLocal() as db:
        if not await ApprovalGateRepository(db).mark_resumed(
            uuid.UUID(gate_data["gate_id"])
        ):
            return {
                "error_message": "Analysis-cost gate resume claim is no longer active."
            }
    return {
        "cost_approval": approval_payload or {},
        "current_scan_status": STATUS_QUEUED_FOR_SCAN,
    }
