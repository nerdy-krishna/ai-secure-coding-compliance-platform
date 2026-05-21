"""Focused unit tests for ``deterministic_prescan_node``.

A full end-to-end LangGraph compile-and-run is out of scope for a Low-risk
single-PR slice (would require seeding a Scan + ORIGINAL_SUBMISSION
snapshot in the test DB, plus driving the AsyncPostgresSaver through
the cost-approval interrupt). These tests instead exercise the node
in isolation and rely on:

- The graph wiring being verified at code-review / manual-smoke time.
- The node never calling ``interrupt()`` (asserted structurally below).
- Persistence happening EXACTLY ONCE per scan, in this node
  (``deterministic_prescan_node``). It used to live in the downstream
  ``pending_prescan_approval_node`` / ``user_decline_node`` /
  ``blocked_pre_llm_node`` / ``save_results_node`` — but those run
  multiple times per scan (LangGraph re-enters interrupted nodes from
  the top on resume, and ``save_results_node`` runs alongside the
  prescan rows again at the end), and each `save_findings` call was
  inserting the same prescan row another time. Three or four duped
  rows per finding showed up on the results page. Pinning persistence
  to this single never-re-entered node fixes that.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict

import pytest

# `worker_graph` pulls in `tree_sitter_languages`, which only ships in
# the worker container's venv. The API-container test environment used
# by `docker compose exec app pytest` lacks it, so collection fails
# unless we skip-mark the whole module up front.
pytest.importorskip("tree_sitter_languages")

from app.core.schemas import VulnerabilityFinding  # noqa: E402
from app.infrastructure.workflows import worker_graph  # noqa: E402


pytestmark = pytest.mark.asyncio


def _state(**overrides: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "scan_id": uuid.uuid4(),
        "scan_type": "AUDIT",
        "current_scan_status": "RUNNING_AGENTS",
        "reasoning_llm_config_id": None,
        "files": {},
        "initial_file_map": None,
        "final_file_map": None,
        "repository_map": None,
        "dependency_graph": None,
        "all_relevant_agents": {},
        "live_codebase": None,
        "findings": [],
        "proposed_fixes": None,
        "agent_results": None,
        "error_message": None,
    }
    base.update(overrides)
    return base


async def test_prescan_returns_empty_when_no_files():
    state = _state(files={})
    result = await worker_graph.deterministic_prescan_node(state)
    assert result == {}


async def test_prescan_skips_files_no_scanner_routes_to():
    """A file extension that maps to no scanner (e.g. a binary
    extension or an unknown one) is silently skipped. Note: most
    text-shaped files now route to Gitleaks even when Bandit/Semgrep
    don't apply, so we use an obviously non-text extension here.
    """
    state = _state(files={"asset.bin": "binary blob"})
    result = await worker_graph.deterministic_prescan_node(state)
    assert result == {}


async def test_prescan_skips_oversize_python_files():
    huge = "x = 1\n" * (worker_graph.PRESCAN_FILE_BYTE_LIMIT // 6 + 1)
    state = _state(files={"big.py": huge})
    result = await worker_graph.deterministic_prescan_node(state)
    assert result == {}


async def test_prescan_returns_findings_with_source_bandit_for_real_python(monkeypatch):
    """Integration of the node + Bandit subprocess. Requires the
    `bandit` binary to be present in the worker venv (it is in the
    runtime Docker image; locally pip-installed during dev).

    Stubs the persist path because the node now writes to the DB
    inline; the test scan_id isn't seeded as a row, so a real
    ``save_findings`` would FK-violate.
    """

    class _StubRepo:
        def __init__(self, *_a, **_k):
            pass

        async def save_findings(self, *_a, **_k):
            pass

        async def update_bom_cyclonedx(self, *_a, **_k):
            pass

    class _StubSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return False

    from app.infrastructure.workflows.nodes import prescan as prescan_mod

    monkeypatch.setattr(prescan_mod, "ScanRepository", _StubRepo)
    monkeypatch.setattr(prescan_mod, "AsyncSessionLocal", lambda: _StubSession())

    state = _state(
        files={
            "vuln.py": (
                "import subprocess\n"
                "def run(user_input):\n"
                "    subprocess.call(user_input, shell=True)\n"
            )
        }
    )
    result = await worker_graph.deterministic_prescan_node(state)
    findings = result.get("findings", [])
    assert findings, "Expected the deterministic pre-pass to flag at least one issue"
    assert all(isinstance(f, VulnerabilityFinding) for f in findings)
    # Semgrep is now DB-driven. The stub session causes the rule selection
    # to fail gracefully (caught exception → 0 rules → Semgrep skipped).
    # Only Bandit fires on this snippet.
    assert any(f.source == "bandit" for f in findings), (
        "Bandit must flag the shell=True call regardless of which other scanners corroborate"
    )
    assert all(f.source in {"bandit", "semgrep", "osv"} for f in findings), (
        "Only bandit/semgrep/osv should fire on this snippet (no secrets)"
    )
    assert all(f.confidence == "High" for f in findings)


async def test_prescan_failure_continues_to_estimate_cost(monkeypatch, caplog):
    """N15 (sast-prescan-followups) — the prescan-fail policy now logs
    a WARN and returns ``{"findings": []}`` so the LLM analysis still
    runs. It MUST NOT route to handle_error or embed scanner stdout in
    `Scan.error_message`.
    """
    import logging

    sentinel = "SECRET_SHAPED_STDOUT_DO_NOT_LEAK"

    def _explode(*_args, **_kwargs):
        raise RuntimeError(sentinel)

    # Make stage_files() itself raise so the outer try/except in the
    # node fires (the per-scanner try/except inside swallows runner
    # crashes; the outer one is for the staging / setup path).
    # Post-split the prescan node lives in `nodes.prescan`, so we patch
    # the symbol at the call site (where the node actually looks it up
    # via its module namespace), not on `worker_graph` (which only
    # re-exports the node function for back-compat).
    from app.infrastructure.workflows.nodes import prescan as prescan_mod

    monkeypatch.setattr(prescan_mod, "stage_files", _explode)
    state = _state(files={"x.py": "y = 1\n"})
    # The app logger sets `propagate=False` once `logging_config.setup`
    # has been called by an earlier DB-backed test, so caplog's
    # root-handler can't see records. Flip propagate for the test.
    app_logger = logging.getLogger("app")
    monkeypatch.setattr(app_logger, "propagate", True)
    caplog.set_level(
        logging.WARNING, logger="app.infrastructure.workflows.worker_graph"
    )
    result = await worker_graph.deterministic_prescan_node(state)
    # Post-ADR-009 the failure path also returns a `bom_cyclonedx` key
    # (None) so the worker state's bom is reset cleanly even when the
    # prescan crashes before OSV ran.
    assert result == {
        "findings": [],
        "bom_cyclonedx": None,
    }, "must continue with empty findings, not error"
    assert "error_message" not in result
    # Sentinel from the exception must NOT have been re-raised; the
    # WARN log mentions the failure but the orchestrator doesn't get
    # `error_message` so the graph proceeds to estimate_cost.
    msgs = "\n".join(r.getMessage() for r in caplog.records)
    assert "prescan_failed" in msgs


async def test_prescan_persists_findings_exactly_once_in_node(monkeypatch):
    """Persistence is now pinned to this node — the previous fan-out to
    ``pending_prescan_approval_node`` / ``user_decline_node`` /
    ``blocked_pre_llm_node`` / ``save_results_node`` was duplicating
    every prescan row 3-4× (LangGraph re-enters interrupted nodes from
    the top on resume, so a `save_findings` call before the interrupt
    ran twice). This test asserts the new contract: when the prescan
    node returns non-empty findings, it MUST call save_findings, and
    must do so exactly once.
    """
    saw_save_calls: list[Any] = []

    class _CountingScanRepository:
        def __init__(self, *_args, **_kwargs):
            pass

        async def save_findings(self, scan_id, findings):
            saw_save_calls.append((scan_id, list(findings)))

        async def update_bom_cyclonedx(self, *_a, **_k):
            pass

    class _StubSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return False

    from app.infrastructure.workflows.nodes import prescan as prescan_mod

    monkeypatch.setattr(prescan_mod, "ScanRepository", _CountingScanRepository)
    monkeypatch.setattr(prescan_mod, "AsyncSessionLocal", lambda: _StubSession())

    # A real Python file with a clear Bandit hit so we exercise the
    # "findings non-empty → must persist" branch.
    state = _state(
        files={
            "vuln.py": (
                "import subprocess\n"
                "def run(user_input):\n"
                "    subprocess.call(user_input, shell=True)\n"
            )
        }
    )
    result = await worker_graph.deterministic_prescan_node(state)
    findings = result.get("findings", [])
    assert findings, "Expected Bandit to flag at least one issue"
    assert len(saw_save_calls) == 1, (
        f"prescan must persist exactly once per scan, got {len(saw_save_calls)} calls"
    )
    assert saw_save_calls[0][1] == findings, (
        "save_findings must be called with the same findings list returned "
        "in state — that's how downstream nodes get back the DB-assigned ids"
    )


async def test_prescan_skips_persist_when_no_findings(monkeypatch):
    """The persist call is gated on findings being non-empty so a clean
    pre-pass doesn't open a DB session for nothing.
    """
    saw_save_calls: list[Any] = []

    class _CountingScanRepository:
        def __init__(self, *_args, **_kwargs):
            pass

        async def save_findings(self, scan_id, findings):
            saw_save_calls.append((scan_id, list(findings)))

        async def update_bom_cyclonedx(self, *_a, **_k):
            pass

    class _StubSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return False

    from app.infrastructure.workflows.nodes import prescan as prescan_mod

    monkeypatch.setattr(prescan_mod, "ScanRepository", _CountingScanRepository)
    monkeypatch.setattr(prescan_mod, "AsyncSessionLocal", lambda: _StubSession())

    state = _state(files={"clean.py": "x = 1\n"})
    await worker_graph.deterministic_prescan_node(state)
    assert saw_save_calls == [], (
        "prescan must not call save_findings when findings is empty"
    )


async def test_prescan_node_does_not_call_interrupt():
    """Static guarantee: the prescan node body must not invoke
    ``interrupt()`` (the cost-approval interrupt lives in
    ``estimate_cost_node`` and must not be duplicated). AST-based so
    a docstring mentioning the word ``interrupt`` does not trip the
    check.
    """
    import ast
    import inspect
    import textwrap

    src = textwrap.dedent(inspect.getsource(worker_graph.deterministic_prescan_node))
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
        "deterministic_prescan_node must not call interrupt(); the "
        "cost-approval interrupt lives in estimate_cost_node."
    )
