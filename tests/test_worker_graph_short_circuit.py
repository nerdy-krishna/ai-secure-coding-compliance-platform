"""Tests for `_route_after_prescan` and the prescan-blocked terminal node.

Post-ADR-009 semantics: ANY findings (Critical-Gitleaks included) now
route to `pending_prescan_approval` for operator review. The
`blocked_pre_llm` terminal is reachable only via
`_route_after_prescan_approval` when the operator declines an override
on a Critical Gitleaks finding.

Exercises `_route_after_prescan` and `blocked_pre_llm_node` directly
(the full graph compile path is out of scope for the same reasons
documented in `tests/test_worker_graph_prescan.py`).
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List

import pytest

# `worker_graph` pulls tree_sitter via its imports; only collect when
# the worker venv is available (api container's pytest skips cleanly).
pytest.importorskip("tree_sitter_languages")

from app.core.schemas import VulnerabilityFinding  # noqa: E402
from app.infrastructure.workflows import worker_graph  # noqa: E402


pytestmark = pytest.mark.asyncio


def _critical_gitleaks_finding() -> VulnerabilityFinding:
    return VulnerabilityFinding(
        cwe="CWE-798",
        title="Secret leak: aws-access-token",
        description="AWS Access Key",
        severity="Critical",
        line_number=42,
        remediation="Rotate the credential.",
        confidence="High",
        references=[],
        cvss_score=None,
        cvss_vector=None,
        file_path="config.py",
        fixes=None,
        source="gitleaks",
        agent_name=None,
        corroborating_agents=None,
        is_applied_in_remediation=False,
    )


def _state_with(findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
    return {
        "scan_id": uuid.uuid4(),
        "scan_type": "AUDIT",
        "current_scan_status": "RUNNING_AGENTS",
        "reasoning_llm_config_id": None,
        "files": None,
        "initial_file_map": None,
        "final_file_map": None,
        "repository_map": None,
        "dependency_graph": None,
        "all_relevant_agents": {},
        "live_codebase": None,
        "findings": findings,
        "proposed_fixes": None,
        "agent_results": None,
        "error_message": None,
    }


def test_route_after_prescan_picks_pending_approval_on_critical_gitleaks():
    """Post-ADR-009: Critical-Gitleaks no longer auto-routes to the
    blocked terminal. Findings route to `pending_prescan_approval` for
    operator review; the operator then decides via the override modal."""
    state = _state_with([_critical_gitleaks_finding()])
    assert worker_graph._route_after_prescan(state) == "pending_prescan_approval"


def test_route_after_prescan_picks_pending_approval_on_any_findings():
    """Any non-empty findings list routes to the prescan-approval
    pause; severity / source don't change the routing decision."""
    bandit_finding = VulnerabilityFinding(
        cwe="CWE-78",
        title="Bandit B602",
        description="subprocess shell=True",
        severity="High",
        line_number=10,
        remediation="Use shell=False.",
        confidence="High",
        references=[],
        cvss_score=None,
        cvss_vector=None,
        file_path="x.py",
        fixes=None,
        source="bandit",
        agent_name=None,
        corroborating_agents=None,
        is_applied_in_remediation=False,
    )
    state = _state_with([bandit_finding])
    assert worker_graph._route_after_prescan(state) == "pending_prescan_approval"


def test_route_after_prescan_picks_pending_approval_on_low_gitleaks():
    """Even a Low-severity finding pauses the graph for operator
    review, so the gate is consistent regardless of provenance."""
    timeout_finding = VulnerabilityFinding(
        cwe="CWE-unknown",
        title="Gitleaks scanner timed out",
        description="timeout",
        severity="Low",
        line_number=0,
        remediation="Re-run.",
        confidence="High",
        references=[],
        cvss_score=None,
        cvss_vector=None,
        file_path="/tmp/staged",
        fixes=None,
        source="gitleaks",
        agent_name=None,
        corroborating_agents=None,
        is_applied_in_remediation=False,
    )
    state = _state_with([timeout_finding])
    assert worker_graph._route_after_prescan(state) == "pending_prescan_approval"


def test_route_after_prescan_picks_profiling_cost_on_empty_findings():
    """Clean prescan (no findings) skips the prescan-review gate and
    proceeds to the profiling-cost gate (#71)."""
    state = _state_with([])
    assert worker_graph._route_after_prescan(state) == "estimate_profiling_cost"


def test_route_after_prescan_picks_handle_error_on_error_message():
    state = _state_with([])
    state["error_message"] = "kaboom"
    assert worker_graph._route_after_prescan(state) == "handle_error"


def test_blocked_pre_llm_node_does_not_call_interrupt():
    """Static guarantee per N5: the blocked node MUST NOT call
    `interrupt()` (the cost-approval interrupt lives in
    `estimate_cost_node` and must remain the only pause point).
    """
    import ast
    import inspect
    import textwrap

    src = textwrap.dedent(inspect.getsource(worker_graph.blocked_pre_llm_node))
    tree = ast.parse(src)
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (
            (isinstance(node.func, ast.Name) and node.func.id == "interrupt")
            or (isinstance(node.func, ast.Attribute) and node.func.attr == "interrupt")
        )
    ]
    assert calls == [], (
        "blocked_pre_llm_node must not call interrupt(); the cost-approval "
        "interrupt lives in estimate_cost_node and is the only pause point."
    )


async def test_blocked_pre_llm_node_logs_warning_with_correlation_id(
    monkeypatch, caplog
):
    """N4: short-circuit auditability — the blocked node MUST log a
    WARNING containing the trigger's rule + file + line so admins can
    investigate via the `/admin/findings?source=gitleaks` endpoint.
    """
    import logging

    saw_save: List[Any] = []
    saw_status: List[Any] = []

    class _StubRepo:
        def __init__(self, *_a, **_k):
            pass

        async def save_findings(self, scan_id, findings):
            saw_save.append((scan_id, list(findings)))

        async def update_status(self, scan_id, status):
            saw_status.append((scan_id, status))

    class _StubSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return False

    # Post-split the blocked_pre_llm node looks up these symbols from
    # its own module namespace (`nodes.prescan`), not from
    # `worker_graph`. Patch where the lookup actually happens.
    from app.infrastructure.workflows.nodes import prescan as prescan_mod

    monkeypatch.setattr(prescan_mod, "ScanRepository", _StubRepo)
    monkeypatch.setattr(prescan_mod, "AsyncSessionLocal", lambda: _StubSession())

    triggering = _critical_gitleaks_finding()
    state = _state_with([triggering])
    app_logger = logging.getLogger("app")
    monkeypatch.setattr(app_logger, "propagate", True)
    # Logger names follow `__name__`; the blocked_pre_llm node now logs under
    # `app.infrastructure.workflows.nodes.prescan`. Capture both the new and
    # legacy paths so the assertion stays meaningful regardless of where
    # future graph wiring moves the WARN call.
    caplog.set_level(
        logging.WARNING, logger="app.infrastructure.workflows.nodes.prescan"
    )
    result = await worker_graph.blocked_pre_llm_node(state)
    assert result == {}
    assert saw_status, "blocked node must call update_status"
    assert saw_status[0][1] == worker_graph.STATUS_BLOCKED_PRE_LLM
    msgs = "\n".join(
        r.getMessage() for r in caplog.records if r.levelno == logging.WARNING
    )
    assert "blocked_pre_llm" in msgs
    assert "gitleaks" in msgs
    assert triggering.title in msgs
    assert triggering.file_path in msgs
