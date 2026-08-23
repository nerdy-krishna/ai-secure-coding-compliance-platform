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

from typing import Any, Final, Mapping, Optional

from app.infrastructure.observability.mask import mask

from app.shared.lib import scan_status as st

# --- ScanEvent.status vocabulary ------------------------------------------
EV_STARTED: Final[str] = "STARTED"
EV_COMPLETED: Final[str] = "COMPLETED"
EV_WAITING: Final[str] = "WAITING"
EV_FAILED: Final[str] = "FAILED"
EV_RETRYING: Final[str] = "RETRYING"
EV_WARNING: Final[str] = "WARNING"
EV_DEGRADED: Final[str] = "DEGRADED"
EV_REQUESTED: Final[str] = "REQUESTED"
EV_OBSERVED: Final[str] = "OBSERVED"
EV_REJECTED: Final[str] = "REJECTED"

EVENT_STATUSES: Final[frozenset[str]] = frozenset(
    {
        EV_STARTED,
        EV_COMPLETED,
        EV_WAITING,
        EV_FAILED,
        EV_RETRYING,
        EV_WARNING,
        EV_DEGRADED,
        EV_REQUESTED,
        EV_OBSERVED,
        EV_REJECTED,
    }
)

EVENT_SCHEMA_VERSION: Final[int] = 1
ACTIVITY_KINDS: Final[frozenset[str]] = frozenset(
    {
        "workflow",
        "scanner",
        "llm_call",
        "retry",
        "warning",
        "degradation",
        "decision",
        "cancellation",
        "budget",
        "terminal",
    }
)
MAX_EVENT_DETAIL_KEYS: Final[int] = 64
MAX_EVENT_DETAIL_STRING_CHARS: Final[int] = 2000
MAX_EVENT_DETAIL_LIST_ITEMS: Final[int] = 50
_FORBIDDEN_DETAIL_KEYS: Final[frozenset[str]] = frozenset(
    {
        "source",
        "source_code",
        "content",
        "snippet",
        "prompt",
        "completion",
        "request_body",
        "response_body",
        "api_key",
        "password",
        "authorization",
        "access_token",
        "refresh_token",
        "secret",
    }
)


def activity_kind_for(stage_name: str, event_status: str) -> str:
    """Return the stable operator-facing taxonomy for an event."""
    stage = stage_name.upper()
    status = event_status.upper()
    if stage in {"CANCELLATION", "CANCELLED"}:
        return "cancellation"
    if stage in {
        "COMPLETED",
        "FAILED",
        "BLOCKED_PRE_LLM",
        "BLOCKED_USER_DECLINE",
        "BUDGET_EXHAUSTED",
    }:
        return "terminal"
    if status == EV_RETRYING or "RETRY" in stage:
        return "retry"
    if status == EV_DEGRADED or "DEGRADED" in stage:
        return "degradation"
    if status == EV_WARNING or "WARNING" in stage:
        return "warning"
    if "SCANNER" in stage or stage in {
        "DETERMINISTIC_PRESCAN",
        "PRESCAN_ANALYSIS",
        "PATCH_VERIFICATION",
    }:
        return "scanner"
    if "LLM" in stage or stage in {"FILE_ANALYZED", "PROFILING_FILES"}:
        return "llm_call"
    if status == EV_WAITING or "REVIEW" in stage or "APPROVAL" in stage:
        return "decision"
    return "workflow"


def validate_activity_envelope(
    stage_name: str, event_status: str, activity_kind: Optional[str] = None
) -> tuple[str, str, str]:
    """Validate and normalize the durable envelope vocabulary."""
    stage = stage_name.strip().upper()
    status = event_status.strip().upper()
    if not stage or len(stage) > 100:
        raise ValueError("scan activity stage_name must contain 1-100 characters")
    if status not in EVENT_STATUSES:
        raise ValueError(f"unsupported scan activity status: {status}")
    kind = activity_kind or activity_kind_for(stage, status)
    if kind not in ACTIVITY_KINDS:
        raise ValueError(f"unsupported scan activity kind: {kind}")
    return stage, status, kind


def _bounded_safe_value(value: Any, *, depth: int = 0) -> Any:
    if depth >= 4:
        return "[bounded]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return str(mask(value))[:MAX_EVENT_DETAIL_STRING_CHARS]
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key, nested in list(value.items())[:MAX_EVENT_DETAIL_KEYS]:
            key = str(raw_key)[:100]
            if key.lower() in _FORBIDDEN_DETAIL_KEYS:
                result[key] = "[REDACTED]"
            else:
                result[key] = _bounded_safe_value(nested, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple, set)):
        return [
            _bounded_safe_value(item, depth=depth + 1)
            for item in list(value)[:MAX_EVENT_DETAIL_LIST_ITEMS]
        ]
    return str(mask(str(value)))[:MAX_EVENT_DETAIL_STRING_CHARS]


def safe_event_details(
    details: Optional[Mapping[str, Any]],
) -> Optional[dict[str, Any]]:
    """Redact source/secrets and bound JSON before durable activity storage."""
    if not details:
        return None
    safe = _bounded_safe_value(details)
    return safe if isinstance(safe, dict) else None


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
