"""Scan progress event model — `cache_status_for` (#84 / PRD #83).

`scan_events` is the source of truth; `scans.status` is a cache derived
from the latest event. These tests pin that derivation: the mapping
must be monotonic (never resolves to a status behind the stage) and
must park the column at the right PENDING_* value for each gate.
"""

from __future__ import annotations

from app.shared.lib import scan_status as st
from app.shared.lib.scan_progress import (
    EV_COMPLETED,
    EV_STARTED,
    EV_WAITING,
    STAGE_COST_REVIEW,
    STAGE_PRESCAN_REVIEW,
    STAGE_PROFILING_REVIEW,
    cache_status_for,
)


# --------------------------------------------------------------------------
# Gate WAITING events park scans.status at the matching PENDING_* value
# --------------------------------------------------------------------------


def test_prescan_gate_waiting_parks_pending_prescan_approval():
    assert (
        cache_status_for(STAGE_PRESCAN_REVIEW, EV_WAITING)
        == st.STATUS_PENDING_PRESCAN_APPROVAL
    )


def test_profiling_gate_waiting_parks_pending_profiling_approval():
    assert (
        cache_status_for(STAGE_PROFILING_REVIEW, EV_WAITING)
        == st.STATUS_PENDING_PROFILING_APPROVAL
    )


def test_cost_gate_waiting_parks_pending_cost_approval():
    assert cache_status_for(STAGE_COST_REVIEW, EV_WAITING) == st.STATUS_PENDING_APPROVAL


# --------------------------------------------------------------------------
# A resumed gate (COMPLETED) leaves the pause
# --------------------------------------------------------------------------


def test_gate_completed_moves_off_the_pause():
    for gate in (STAGE_PRESCAN_REVIEW, STAGE_PROFILING_REVIEW, STAGE_COST_REVIEW):
        assert cache_status_for(gate, EV_COMPLETED) == st.STATUS_QUEUED_FOR_SCAN


# --------------------------------------------------------------------------
# Non-gate stage STARTED → the live status it implies
# --------------------------------------------------------------------------


def test_stage_started_maps_to_live_status():
    assert (
        cache_status_for("ANALYZING_CONTEXT", EV_STARTED) == st.STATUS_ANALYZING_CONTEXT
    )
    assert cache_status_for("RUNNING_AGENTS", EV_STARTED) == st.STATUS_RUNNING_AGENTS
    assert cache_status_for("CONSOLIDATING", EV_STARTED) == st.STATUS_RUNNING_AGENTS
    assert (
        cache_status_for("GENERATING_REPORTS", EV_STARTED)
        == st.STATUS_GENERATING_REPORTS
    )


# --------------------------------------------------------------------------
# Events that should leave scans.status unchanged
# --------------------------------------------------------------------------


def test_non_gate_completed_leaves_status_unchanged():
    """A non-gate COMPLETED carries no status change — the next stage's
    STARTED advances the cache."""
    assert cache_status_for("RUNNING_AGENTS", EV_COMPLETED) is None
    assert cache_status_for("ANALYZING_CONTEXT", EV_COMPLETED) is None


def test_unknown_stage_started_leaves_status_unchanged():
    assert cache_status_for("FILE_ANALYZED", EV_STARTED) is None
    assert cache_status_for("SOMETHING_NEW", EV_STARTED) is None
