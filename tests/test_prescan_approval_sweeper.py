"""Unit tests for the prescan-approval auto-decline sweeper.

ADR-009 / M7 / G9 — programmatic callers (CI bots, MCP) that submit
a scan with findings and never visit the UI must not accumulate
forever in `STATUS_PENDING_PRESCAN_APPROVAL`. The sweeper transitions
stuck scans to `STATUS_BLOCKED_USER_DECLINE` after 24 h.

These tests mock `AsyncSessionLocal` so the sweeper logic is unit-
tested in isolation; integration coverage of the actual SQL is part
of the manual smoke checklist.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = pytest.mark.asyncio


def _fake_session() -> Any:
    """A MagicMock standing in for an AsyncSessionLocal context manager."""
    fake = MagicMock()
    fake.__aenter__ = AsyncMock(return_value=fake)
    fake.__aexit__ = AsyncMock(return_value=False)
    fake.execute = AsyncMock()
    fake.commit = AsyncMock()
    fake.add = MagicMock()
    return fake


async def test_sweep_once_transitions_returned_rows() -> None:
    """`_sweep_once` issues an UPDATE per scan returned by the SELECT
    and writes an auto-declined scan_event for each."""
    import uuid

    from app.infrastructure.messaging import prescan_approval_sweeper as mod
    from app.shared.lib.scan_status import STATUS_PENDING_PRESCAN_APPROVAL

    fake = _fake_session()
    stuck_ids = [uuid.uuid4(), uuid.uuid4(), uuid.uuid4()]

    # The SELECT now returns (id, status) rows so the sweeper can pick
    # the right gate to flip and the right audit event name.
    select_result = MagicMock()
    select_result.all = MagicMock(
        return_value=[(sid, STATUS_PENDING_PRESCAN_APPROVAL) for sid in stuck_ids]
    )

    # Each UPDATE returns a Result whose `.rowcount` is 1 (the sweeper
    # uses `rowcount` for the race-with-operator check).
    update_results = []
    for _ in stuck_ids:
        u = MagicMock()
        u.rowcount = 1
        update_results.append(u)
    fake.execute.side_effect = [select_result] + update_results

    with patch.object(mod, "_delete_checkpointer_thread", AsyncMock()):
        with patch.object(mod, "AsyncSessionLocal", lambda: fake):
            n = await mod._sweep_once()

    assert n == len(stuck_ids)
    # SELECT + UPDATE per row.
    assert fake.execute.await_count == 1 + len(stuck_ids)
    # ScanEvent.add for each stuck row.
    assert fake.add.call_count == len(stuck_ids)
    # Single commit at the end.
    fake.commit.assert_awaited_once()


async def test_sweep_once_handles_the_profiling_cost_gate() -> None:
    """A scan stuck at the profiling-cost gate (#71) is also swept, and
    gets a PROFILING_AUTO_DECLINED audit event (not PRESCAN_)."""
    import uuid

    from app.infrastructure.messaging import prescan_approval_sweeper as mod
    from app.shared.lib.scan_status import STATUS_PENDING_PROFILING_APPROVAL

    fake = _fake_session()
    stuck_id = uuid.uuid4()

    select_result = MagicMock()
    select_result.all = MagicMock(
        return_value=[(stuck_id, STATUS_PENDING_PROFILING_APPROVAL)]
    )
    u = MagicMock()
    u.rowcount = 1
    fake.execute.side_effect = [select_result, u]

    with patch.object(mod, "_delete_checkpointer_thread", AsyncMock()):
        with patch.object(mod, "AsyncSessionLocal", lambda: fake):
            n = await mod._sweep_once()

    assert n == 1
    assert fake.add.call_count == 1
    event = fake.add.call_args.args[0]
    assert event.stage_name == "PROFILING_AUTO_DECLINED"


async def test_sweep_once_no_stuck_scans_is_a_noop() -> None:
    """When the SELECT returns zero rows, no UPDATEs / events / commits
    are needed beyond the no-op commit at the end."""
    from app.infrastructure.messaging import prescan_approval_sweeper as mod

    fake = _fake_session()
    select_result = MagicMock()
    select_result.all = MagicMock(return_value=[])
    fake.execute.return_value = select_result

    with patch.object(mod, "_delete_checkpointer_thread", AsyncMock()):
        with patch.object(mod, "AsyncSessionLocal", lambda: fake):
            n = await mod._sweep_once()

    assert n == 0
    assert fake.execute.await_count == 1
    assert fake.add.call_count == 0


async def test_sweep_once_skips_audit_event_on_race() -> None:
    """If the operator clicks Stop / Continue concurrently with a sweep,
    the conditional UPDATE returns rowcount=0 — the sweeper must NOT
    write a PRESCAN_AUTO_DECLINED ScanEvent for that scan."""
    import uuid

    from app.infrastructure.messaging import prescan_approval_sweeper as mod
    from app.shared.lib.scan_status import STATUS_PENDING_PRESCAN_APPROVAL

    fake = _fake_session()
    stuck_ids = [uuid.uuid4(), uuid.uuid4()]

    select_result = MagicMock()
    select_result.all = MagicMock(
        return_value=[(sid, STATUS_PENDING_PRESCAN_APPROVAL) for sid in stuck_ids]
    )

    # First UPDATE wins (rowcount=1), second loses the race (rowcount=0).
    u_win = MagicMock()
    u_win.rowcount = 1
    u_lost = MagicMock()
    u_lost.rowcount = 0
    fake.execute.side_effect = [select_result, u_win, u_lost]

    with patch.object(mod, "_delete_checkpointer_thread", AsyncMock()):
        with patch.object(mod, "AsyncSessionLocal", lambda: fake):
            n = await mod._sweep_once()

    # Only one transition counted; only one ScanEvent added.
    assert n == 1
    assert fake.add.call_count == 1


async def test_run_prescan_approval_sweeper_stops_on_event() -> None:
    """The outer loop exits cleanly when `stop_event` is set."""
    from app.infrastructure.messaging import prescan_approval_sweeper as mod

    stop_event = asyncio.Event()

    async def _stop_after_first_pass() -> int:
        stop_event.set()
        return 0

    with patch.object(mod, "_sweep_once", side_effect=_stop_after_first_pass):
        # Use a tiny interval so the await_for(stop_event.wait()) returns
        # quickly after `stop_event.set()`.
        with patch.object(mod, "SWEEPER_INTERVAL_SECONDS", 0.05):
            await asyncio.wait_for(
                mod.run_prescan_approval_sweeper(stop_event), timeout=2.0
            )
