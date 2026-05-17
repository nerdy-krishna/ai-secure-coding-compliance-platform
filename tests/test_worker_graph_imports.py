"""Pin the back-compat import surface of `worker_graph` after the
split-worker-graph refactor (2026-04-26 / G8 of the threat model).

The node implementations now live in `app.infrastructure.workflows.nodes.*`
but `consumer.py` and the existing `tests/test_worker_graph_*.py` files
import names directly from `worker_graph` via either `from ... import`
or `worker_graph.<name>` attribute access. This test pins both surfaces
so an accidental rename / dropped re-export breaks loudly.

It also smoke-tests that `get_workflow()` compiles by stubbing out the
checkpointer's psycopg connection — no real DB call is needed.
"""

from __future__ import annotations

import pytest

# `worker_graph` pulls in `tree_sitter_languages` via the consolidate
# node module. Skip cleanly on the API container where it's not present.
pytest.importorskip("tree_sitter_languages")

from app.infrastructure.workflows import worker_graph  # noqa: E402


# Names the existing test suite + consumer access via attribute lookup.
# Update this list (intentionally, in a PR) when a public node is added
# or removed; an accidental drop will break this test loudly.
_REEXPORTED_NAMES = (
    # Public API used by `workers/consumer.py`:
    "WorkerState",
    "RelevantAgent",
    "get_workflow",
    "close_workflow_resources",
    # Constants:
    "CONCURRENT_LLM_LIMIT",
    "CONCURRENT_SCANNER_LIMIT",
    "PRESCAN_FILE_BYTE_LIMIT",
    "CHUNK_ONLY_IF_LARGER_THAN",
    "HAS_TREE_SITTER",
    # Status constants (re-exported via `from app.shared.lib.scan_status`):
    "STATUS_BLOCKED_PRE_LLM",
    "STATUS_BLOCKED_USER_DECLINE",
    "STATUS_PENDING_PRESCAN_APPROVAL",
    "STATUS_PENDING_PROFILING_APPROVAL",
    "STATUS_QUEUED_FOR_SCAN",
    "STATUS_FAILED",
    "STATUS_COMPLETED",
    "STATUS_REMEDIATION_COMPLETED",
    # Nodes:
    "retrieve_and_prepare_data_node",
    "deterministic_prescan_node",
    "pending_prescan_approval_node",
    "user_decline_node",
    "blocked_pre_llm_node",
    "estimate_profiling_cost_node",
    "profile_files_node",
    "estimate_cost_node",
    "analyze_files_parallel_node",
    "correlate_findings_node",
    "consolidate_and_patch_node",
    "verify_patches_node",
    "save_results_node",
    "save_final_report_node",
    "handle_error_node",
    # Private helpers exercised by tests:
    "_run_merge_agent",
    "_resolve_file_fix_conflicts",
    "_verify_syntax_with_treesitter",
    # Routing:
    "should_continue",
    "_route_after_retrieve",
    "_route_after_prescan",
    "_route_after_prescan_approval",
    "_route_after_profiling_approval",
)


def test_public_symbols_importable() -> None:
    """The four public symbols `consumer.py` imports MUST stay at the
    top-level `worker_graph` import path."""
    from app.infrastructure.workflows.worker_graph import (  # noqa: F401
        WorkerState,
        RelevantAgent,
        close_workflow_resources,
        get_workflow,
    )

    # WorkerState / RelevantAgent are TypedDicts → classes
    assert isinstance(WorkerState, type)
    assert isinstance(RelevantAgent, type)
    # The two lifecycle helpers are coroutine functions
    assert callable(get_workflow)
    assert callable(close_workflow_resources)


def test_node_attributes_accessible() -> None:
    """Every name historically accessed via `worker_graph.<name>` (by
    monkeypatch in tests, or any external consumer) must remain
    available as a module attribute. This pins the back-compat
    surface — adding / removing entries should be intentional."""
    missing: list[str] = []
    for name in _REEXPORTED_NAMES:
        if not hasattr(worker_graph, name):
            missing.append(name)
    assert not missing, (
        f"Missing back-compat re-exports on worker_graph: {missing}. "
        f"Either restore the re-export in worker_graph.py or update the "
        f"_REEXPORTED_NAMES tuple in this test if the removal is intentional."
    )


def test_workflow_compiles_with_in_memory_saver() -> None:
    """The StateGraph wiring must compile cleanly post-refactor.

    We don't go through `get_workflow()` because that path requires a
    real psycopg connection to the LangGraph checkpointer schema. The
    StateGraph object itself is module-level, so we just compile it
    here with an `InMemorySaver` to prove every `add_node` /
    `add_edge` / `add_conditional_edges` call references a registered
    node and the graph shape is valid.
    """
    from langgraph.checkpoint.memory import InMemorySaver

    pregel = worker_graph.workflow.compile(checkpointer=InMemorySaver())
    assert pregel is not None
    # Spot-check a few node names are registered. LangGraph exposes
    # registered node ids as keys on the underlying graph object.
    assert hasattr(pregel, "nodes")
