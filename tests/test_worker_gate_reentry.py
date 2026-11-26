"""A fresh-start delivery must not re-run a graph parked at a human gate.

`_WORKFLOW_ENTRY_STATUSES` deliberately includes the `pending_*` statuses (so a
legitimate queued delivery is accepted), which means the entry-status precheck
cannot tell "a gate is waiting for a decision" from "this scan is ready to run".
The checkpoint can.

Without this guard a submission-queue delivery for a scan parked at the prescan
gate re-ran the graph from `retrieve_and_prepare_data`: the deterministic
prescan ran again, persisted the same findings a second time, and re-parked at
the gate — the modal came back and the results page listed every semgrep and
gitleaks row twice.

Needs the worker runtime (aio-pika, LangGraph), so it is skipped in a bare
environment and runs in the Docker test pass.
"""

from __future__ import annotations

import asyncio

import pytest

consumer = pytest.importorskip(
    "app.workers.consumer",
    reason="needs the worker runtime dependencies; run the suite in Docker",
)

CONFIG = {"configurable": {"thread_id": "scan-thread"}}


class _Task:
    def __init__(self, interrupts) -> None:
        self.interrupts = interrupts


class _Snapshot:
    def __init__(self, tasks) -> None:
        self.tasks = tasks


class _Workflow:
    def __init__(self, snapshot=None, raises: bool = False) -> None:
        self._snapshot = snapshot
        self._raises = raises
        self.calls = 0

    async def aget_state(self, config):  # noqa: ANN001 - mirrors CompiledGraph
        self.calls += 1
        if self._raises:
            raise RuntimeError("checkpoint unavailable")
        return self._snapshot


def test_thread_waiting_on_interrupt_is_detected() -> None:
    workflow = _Workflow(_Snapshot([_Task((("kind", "prescan_approval"),))]))

    assert asyncio.run(consumer._thread_is_parked_at_interrupt(workflow, CONFIG))
    assert workflow.calls == 1


def test_thread_without_interrupt_is_not_parked() -> None:
    assert not asyncio.run(
        consumer._thread_is_parked_at_interrupt(
            _Workflow(_Snapshot([_Task(())])), CONFIG
        )
    )
    # No tasks at all (finished or never started) also means "not parked".
    assert not asyncio.run(
        consumer._thread_is_parked_at_interrupt(_Workflow(_Snapshot([])), CONFIG)
    )


def test_unreadable_checkpoint_does_not_block_the_delivery() -> None:
    """Failing open keeps a checkpoint hiccup from stranding a queued scan."""
    assert not asyncio.run(
        consumer._thread_is_parked_at_interrupt(_Workflow(raises=True), CONFIG)
    )
