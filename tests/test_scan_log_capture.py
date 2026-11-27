"""Per-scan log capture: attribution, redaction, and a queue that never blocks.

The contract:

* a record is captured only when it can be attributed to a scan — bound context
  first, then a validated `scan_id` extra. Everything else is ignored, so the
  table never fills with unrelated traffic;
* nothing that looks like a secret reaches the table;
* the handler is on the hot path of every request and every graph node: a full
  queue drops lines instead of waiting, and a broken record never raises.
"""

from __future__ import annotations

import logging
import uuid

import pytest

from app.infrastructure.observability import scan_logs
from app.infrastructure.observability.scan_logs import (
    ScanLogHandler,
    bind_scan_logging,
    format_scan_log_message,
    resolve_scan_id,
    set_scan_log_scan_id,
)

SCAN_ID = uuid.UUID("11111111-2222-3333-4444-555555555555")


def _record(
    message: str = "something happened",
    *,
    level: int = logging.INFO,
    name: str = "app.workers.consumer",
    exc_info=None,
    **extra,
) -> logging.LogRecord:
    record = logging.LogRecord(
        name=name,
        level=level,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=(),
        exc_info=exc_info,
    )
    for key, value in extra.items():
        setattr(record, key, value)
    return record


def test_attribution_prefers_bound_context() -> None:
    with bind_scan_logging(SCAN_ID):
        assert resolve_scan_id(_record()) == str(SCAN_ID)
    assert resolve_scan_id(_record()) is None


def test_attribution_falls_back_to_a_validated_extra() -> None:
    assert resolve_scan_id(_record(scan_id=str(SCAN_ID))) == str(SCAN_ID)
    # A junk extra must not become a failed insert against a UUID column.
    assert resolve_scan_id(_record(scan_id="../etc/passwd")) is None
    assert resolve_scan_id(_record(scan_id=None)) is None


def test_task_scoped_binding_sets_without_reset() -> None:
    set_scan_log_scan_id(SCAN_ID)
    try:
        assert resolve_scan_id(_record()) == str(SCAN_ID)
    finally:
        set_scan_log_scan_id(None)


def test_secrets_are_redacted_and_lines_stay_single_row() -> None:
    record = _record('login failed password="hunter2" token: "abc123"')
    line = format_scan_log_message(record)

    assert "hunter2" not in line
    assert "***REDACTED***" in line
    assert "\n" not in line


def test_exception_class_and_message_are_kept() -> None:
    """The line an operator reads first: what broke, not the whole traceback."""
    try:
        raise RuntimeError("greenlet_spawn has not been called")
    except RuntimeError:
        import sys

        record = _record(
            "WORKFLOW: Exception during worker_workflow invocation",
            level=logging.ERROR,
            exc_info=sys.exc_info(),
        )

    line = format_scan_log_message(record)

    assert "RuntimeError: greenlet_spawn has not been called" in line
    assert "Traceback" not in line
    assert "\n" not in line


def test_messages_are_length_capped() -> None:
    # Spaces keep the run below the high-entropy pattern so this measures the
    # length cap rather than the redactor.
    line = format_scan_log_message(
        _record("scan progress step " * (scan_logs.MAX_MESSAGE_CHARS // 10))
    )
    assert len(line) == scan_logs.MAX_MESSAGE_CHARS


def test_handler_captures_only_attributed_records() -> None:
    handler = ScanLogHandler(level=logging.INFO)

    handler.emit(_record("no scan — ignored"))
    with bind_scan_logging(SCAN_ID):
        handler.emit(_record("captured line"))
        handler.emit(_record("below level", level=logging.DEBUG))

    rows = handler.drain()

    assert [row["message"] for row in rows] == ["captured line"]
    assert rows[0]["scan_id"] == str(SCAN_ID)
    assert rows[0]["level"] == "INFO"
    assert rows[0]["logger_name"] == "app.workers.consumer"
    assert handler.drain() == []


def test_full_queue_drops_instead_of_blocking(monkeypatch) -> None:
    """A stalled database must never stall the worker that is logging."""
    monkeypatch.setattr(scan_logs, "_PENDING_MAX", 2)
    handler = ScanLogHandler(level=logging.INFO)

    with bind_scan_logging(SCAN_ID):
        for index in range(5):
            handler.emit(_record(f"line {index}"))

    rows = handler.drain()
    assert [row["message"] for row in rows] == ["line 0", "line 1"]
    assert handler.dropped == 3


def test_handler_never_raises_on_a_broken_record() -> None:
    handler = ScanLogHandler(level=logging.INFO)
    broken = _record("has %s but no args")
    broken.args = ("a", "b")  # formatting raises inside getMessage()

    with bind_scan_logging(SCAN_ID):
        handler.emit(broken)  # must not raise

    rows = handler.drain()
    assert len(rows) == 1
    assert "has %s but no args" in rows[0]["message"]


def test_capture_level_is_configurable(monkeypatch) -> None:
    handler = ScanLogHandler(level=logging.WARNING)
    with bind_scan_logging(SCAN_ID):
        handler.emit(_record("info line", level=logging.INFO))
        handler.emit(_record("warning line", level=logging.WARNING))

    assert [row["message"] for row in handler.drain()] == ["warning line"]


@pytest.mark.parametrize("level", ["INFO", "WARNING", "ERROR"])
def test_level_is_preserved_verbatim(level: str) -> None:
    handler = ScanLogHandler(level=logging.INFO)
    with bind_scan_logging(SCAN_ID):
        handler.emit(_record("x", level=getattr(logging, level)))

    assert handler.drain()[0]["level"] == level


def test_captured_rows_carry_the_record_timestamp() -> None:
    """A batched flush must not re-stamp every line with the flush time."""
    import time as _time
    from datetime import datetime

    handler = ScanLogHandler(level=logging.INFO)
    with bind_scan_logging(SCAN_ID):
        emitted_at = _time.time()
        handler.emit(_record("stamped at emit time"))
    rows = handler.drain()

    assert len(rows) == 1
    stamp = rows[0]["timestamp"]
    assert isinstance(stamp, datetime)
    assert stamp.tzinfo is not None
    assert (
        abs(stamp.timestamp() - emitted_at) < 1.0
    ), "the row must carry when the line was logged, not when the batch flushed"
