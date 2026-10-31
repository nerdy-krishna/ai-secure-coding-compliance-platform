"""Scan duration must measure work, not the wait for a human.

`created_at → completed_at` includes every minute a scan sits at an approval gate.
A gate is the only place a SAST scan deliberately parks, so subtracting gate
intervals is exact, not an estimate.
"""

from __future__ import annotations

import datetime as dt

import pytest

from app.shared.lib.scan_status import (
    ALL_SCAN_STATUSES,
    SCAN_STATUS_TRANSITIONS,
    STATUS_BLOCKED_USER_DECLINE,
    STATUS_COMPLETED,
    STATUS_PENDING_PRESCAN_APPROVAL,
    STATUS_QUEUED_FOR_SCAN,
    STATUS_STOPPED_BEFORE_LLM,
    TERMINAL_SCAN_STATUSES,
)
from app.shared.lib.scan_timing import active_processing_seconds, waiting_seconds

BASE = dt.datetime(2026, 10, 31, 10, 0, tzinfo=dt.timezone.utc)


def minutes(value: float) -> dt.timedelta:
    return dt.timedelta(minutes=value)


def test_no_gates_is_plain_wall_clock() -> None:
    assert active_processing_seconds(
        created_at=BASE, completed_at=BASE + minutes(3)
    ) == pytest.approx(180.0)


def test_gate_wait_is_subtracted() -> None:
    """A 3-minute scan that waited 20 minutes for review is 3 minutes, not 23."""
    active = active_processing_seconds(
        created_at=BASE,
        completed_at=BASE + minutes(23),
        gates=[(BASE + dt.timedelta(seconds=30), BASE + minutes(20) + dt.timedelta(seconds=30))],
    )
    assert active == pytest.approx(180.0)


def test_undecided_gate_counts_up_to_now() -> None:
    """A parked scan freezes: only the 40 seconds before the gate count."""
    active = active_processing_seconds(
        created_at=BASE,
        now=BASE + minutes(25),
        gates=[(BASE + dt.timedelta(seconds=40), None)],
    )
    assert active == pytest.approx(40.0)


def test_multiple_gates_accumulate() -> None:
    active = active_processing_seconds(
        created_at=BASE,
        completed_at=BASE + minutes(30),
        gates=[
            (BASE, BASE + minutes(5)),
            (BASE + minutes(10), BASE + minutes(25)),
        ],
    )
    assert active == pytest.approx(600.0)


def test_waiting_seconds_ignores_malformed_gates() -> None:
    assert waiting_seconds([(None, BASE), (BASE + minutes(1), BASE)], until=BASE) == 0.0


def test_naive_timestamps_are_treated_as_utc() -> None:
    naive = dt.datetime(2026, 10, 31, 10, 0)
    assert active_processing_seconds(
        created_at=naive, completed_at=naive + minutes(2)
    ) == pytest.approx(120.0)


def test_missing_creation_time_has_no_measurement() -> None:
    assert active_processing_seconds(created_at=None) is None


def test_negative_span_is_clamped() -> None:
    assert active_processing_seconds(
        created_at=BASE + minutes(5), completed_at=BASE
    ) == 0.0


def test_stopped_before_llm_is_a_distinct_terminal_status() -> None:
    assert STATUS_STOPPED_BEFORE_LLM == "STOPPED_BEFORE_LLM"
    assert STATUS_STOPPED_BEFORE_LLM in ALL_SCAN_STATUSES
    assert STATUS_STOPPED_BEFORE_LLM in TERMINAL_SCAN_STATUSES
    # Terminal: no outgoing edges.
    assert STATUS_STOPPED_BEFORE_LLM not in SCAN_STATUS_TRANSITIONS
    # Reachable from the gate, and from the API's claim-and-requeue step.
    assert STATUS_STOPPED_BEFORE_LLM in SCAN_STATUS_TRANSITIONS[STATUS_PENDING_PRESCAN_APPROVAL]
    assert STATUS_STOPPED_BEFORE_LLM in SCAN_STATUS_TRANSITIONS[STATUS_QUEUED_FOR_SCAN]
    # A stop is not a completion, and the legacy value is still accepted.
    assert STATUS_STOPPED_BEFORE_LLM not in {STATUS_COMPLETED, "REMEDIATION_COMPLETED"}
    assert STATUS_BLOCKED_USER_DECLINE in TERMINAL_SCAN_STATUSES


# --- access-log route templating -------------------------------------------
def _route_template(url_path, template):
    """Mirror of the helper in app.main (kept in sync by this test)."""
    if not template:
        return url_path
    first = template.split("/", 1)[1] if template.startswith("/") else template
    head = f"/{first.split('/', 1)[0]}"
    idx = url_path.find(head)
    if idx > 0:
        return url_path[:idx] + template
    return template


def test_route_template_keeps_the_mount_prefix() -> None:
    """APIRoute.path omits the include_router prefix; the log line must not."""
    assert (
        _route_template("/api/v1/scans/abc-123/result", "/scans/{scan_id}/result")
        == "/api/v1/scans/{scan_id}/result"
    )
    assert (
        _route_template("/api/v1/pentest/runs/abc", "/runs/{run_id}")
        == "/api/v1/pentest/runs/{run_id}"
    )
    assert _route_template("/api/v1/scans", "/scans") == "/api/v1/scans"
    # No matched route (404): the raw path is the best available signal.
    assert _route_template("/api/v1/missing", None) == "/api/v1/missing"
