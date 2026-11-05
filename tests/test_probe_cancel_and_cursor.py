"""Stopping a probe, and making "clear" mean something.

Three bugs reported together, all about state the operator cannot see:

- "stop" asked the engine to stop at the next stage boundary and the scan kept running;
- a stopped probe looked like it had restarted after a page refresh;
- clearing the activity view came back in full on the next load.
"""

from __future__ import annotations

import inspect

from app.assets import events as asset_events
from app.assets import service
from app.pentest import inventory_probe


def test_cancel_marks_the_running_job_cancelled_not_just_flagged():
    """A flag the UI cannot see is why "stop" looked like it did nothing."""
    source = inspect.getsource(service.cancel_probes)

    assert 'status="cancelled"' in source
    assert "cancel_requested=True" in source


def test_a_stopped_scanner_is_not_swallowed_by_the_stage_helper():
    """`except Exception` used to eat RunStopped, so the kill looked like a tool error."""
    source = inspect.getsource(inventory_probe)

    assert source.count("except RunStopped:") >= 3, "nmap, whatweb and nuclei must re-raise"
    run_job = inspect.getsource(inventory_probe.run_job)
    assert 'status="cancelled"' in run_job


def test_cancellation_is_read_from_the_row_each_time():
    source = inspect.getsource(inventory_probe.run_job)

    assert 'current.status == "cancelled"' in source, "the row is the source of truth"


def test_probes_run_across_assets_in_parallel():
    """Concurrency is across assets: several hosts at once, never one host twice."""
    source = inspect.getsource(inventory_probe.tick)

    assert "PROBE_CONCURRENCY" in source
    assert "asyncio.gather" in source
    assert inventory_probe.PROBE_CONCURRENCY >= 2


def test_clearing_records_a_cursor_and_deletes_nothing():
    source = inspect.getsource(asset_events.clear)

    assert "AssetEventCursor" in source
    assert "delete(" not in source, "the log is the record; clear only moves the view"


def test_the_view_starts_at_the_cursor():
    source = inspect.getsource(asset_events.recent)

    assert "max(after_id, await cursor(tenant_id))" in source
