"""Scan progress event model (#84 / PRD #83).

``scan_events`` is the single source of truth for scan progress. Every
worker stage emits a ``STARTED`` event on node entry and a ``COMPLETED``
event on node exit; the three approval gates emit a ``WAITING`` event
when the graph suspends at ``interrupt()`` and ``COMPLETED`` when the
graph is resumed. ``scans.status`` is a denormalised **cache** derived
from the latest event via :func:`cache_status_for` and written in the
same transaction as the event (see ``ScanRepository.record_scan_event``).

The gate nodes are split into a *work* node + a *bare interrupt* node so
a LangGraph resume re-runs only the side-effect-free interrupt node —
the whole event stream is therefore ordered and never duplicated.
"""

from __future__ import annotations

from typing import Final, Optional

from app.shared.lib import scan_status as st

# --- ScanEvent.status vocabulary ------------------------------------------
EV_STARTED: Final[str] = "STARTED"
EV_COMPLETED: Final[str] = "COMPLETED"
EV_WAITING: Final[str] = "WAITING"
EV_FAILED: Final[str] = "FAILED"

EVENT_STATUSES: Final[frozenset[str]] = frozenset(
    {EV_STARTED, EV_COMPLETED, EV_WAITING, EV_FAILED}
)

# --- Gate stage names (the three human-in-the-loop approval gates) --------
STAGE_PRESCAN_REVIEW: Final[str] = "PRESCAN_REVIEW"
STAGE_PROFILING_REVIEW: Final[str] = "PROFILING_REVIEW"
STAGE_COST_REVIEW: Final[str] = "COST_REVIEW"

GATE_STAGES: Final[frozenset[str]] = frozenset(
    {STAGE_PRESCAN_REVIEW, STAGE_PROFILING_REVIEW, STAGE_COST_REVIEW}
)

# A gate's WAITING event maps to the scan's pause status.
_GATE_WAITING_STATUS: Final[dict[str, str]] = {
    STAGE_PRESCAN_REVIEW: st.STATUS_PENDING_PRESCAN_APPROVAL,
    STAGE_PROFILING_REVIEW: st.STATUS_PENDING_PROFILING_APPROVAL,
    STAGE_COST_REVIEW: st.STATUS_PENDING_APPROVAL,
}

# A non-gate stage's STARTED event maps to the live scans.status it
# implies. Stages absent from this map leave scans.status unchanged.
_STAGE_STARTED_STATUS: Final[dict[str, str]] = {
    "ANALYZING_CONTEXT": st.STATUS_ANALYZING_CONTEXT,
    "DETERMINISTIC_PRESCAN": st.STATUS_ANALYZING_CONTEXT,
    "ESTIMATING_PROFILING_COST": st.STATUS_ANALYZING_CONTEXT,
    "PROFILING_FILES": st.STATUS_QUEUED_FOR_SCAN,
    "ESTIMATING_COST": st.STATUS_QUEUED_FOR_SCAN,
    "RUNNING_AGENTS": st.STATUS_RUNNING_AGENTS,
    "CONSOLIDATING": st.STATUS_RUNNING_AGENTS,
    "CROSS_FILE_VALIDATION": st.STATUS_RUNNING_AGENTS,
    "PATCH_VERIFICATION": st.STATUS_RUNNING_AGENTS,
    "GENERATING_REPORTS": st.STATUS_GENERATING_REPORTS,
}


def cache_status_for(stage_name: str, event_status: str) -> Optional[str]:
    """The ``scans.status`` cache value implied by a scan event.

    Returns ``None`` when the event should leave ``scans.status``
    unchanged (e.g. the ``COMPLETED`` of a non-gate stage, or a
    sub-event like ``FILE_ANALYZED``). The mapping is intentionally
    monotonic — every value it returns is at or ahead of the prior
    stage, so the cache never moves backward.
    """
    if event_status == EV_WAITING:
        return _GATE_WAITING_STATUS.get(stage_name)
    if event_status == EV_STARTED:
        return _STAGE_STARTED_STATUS.get(stage_name)
    if event_status == EV_COMPLETED and stage_name in _GATE_WAITING_STATUS:
        # A resumed gate has left its pause — the next node's STARTED
        # event will set the precise live status moments later.
        return st.STATUS_QUEUED_FOR_SCAN
    return None
