"""Per-scan application-log capture, so an operator never has to shell in.

The live event log on the scan page is the *audit* stream (`scan_events`): stage
transitions, decisions, gate state. When something breaks -- a worker node
raising `MissingGreenlet`, a scanner subprocess dying, a provider returning 429
-- the reason lives in the process log, not in a stage event. Until now that
meant an operator had to `docker compose logs` / query Loki to find out what
happened to their own scan.

This module keeps a bounded, redacted copy of the application log for whichever
scan the current task is processing, and the API serves it to the scan page when
the operator turns the "backend logs" view on.

Attribution
-----------
``bind_scan_logging(scan_id)`` (a context manager) sets a contextvar; the queue
consumer binds it per delivery and the API router binds it per scan-scoped
request. A record whose `extra` carries `scan_id` is attributed too, which
covers the call sites that already pass it. Records with neither are ignored, so
unrelated traffic is never stored.

Two hard constraints
--------------------
* Never block, never raise. This handler sits on the hot path of every request
  and every graph node. Records land in a bounded deque; a background task
  flushes them in batches. If the queue is full lines are dropped, not awaited.
* Never store a secret. Lines run through the same redaction the stdout handler
  uses, are capped in length, and a per-scan row cap keeps a runaway scan from
  growing the table without bound.

The full traceback still belongs in Loki; the line captured here carries the
exception class and message, which is what an operator reads first.
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
import uuid
from collections import deque
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Iterator

logger = logging.getLogger(__name__)

# Set by whoever is processing a scan (worker delivery, scan-scoped request).
scan_log_scan_id_var: ContextVar[str | None] = ContextVar(
    "scan_log_scan_id", default=None
)

MAX_MESSAGE_CHARS = int(os.getenv("SCAN_LOG_MAX_MESSAGE_CHARS", "4000"))
MAX_LINES_PER_SCAN = int(os.getenv("SCAN_LOG_MAX_LINES_PER_SCAN", "2000"))
CAPTURE_LEVEL = os.getenv("SCAN_LOG_CAPTURE_LEVEL", "INFO").upper()
FLUSH_INTERVAL_SECONDS = 1.0
FLUSH_BATCH_SIZE = 100
_PENDING_MAX = 5000
_RETENTION_INTERVAL_SECONDS = 10.0

# Anything at or above this level is worth showing; below it is library chatter.
_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}
_CAPTURE_LEVEL = _LEVELS.get(CAPTURE_LEVEL, logging.INFO)


@contextmanager
def bind_scan_logging(scan_id: str | uuid.UUID | None) -> Iterator[None]:
    """Attribute log records emitted in this scope to ``scan_id``."""
    token = scan_log_scan_id_var.set(str(scan_id) if scan_id else None)
    try:
        yield
    finally:
        scan_log_scan_id_var.reset(token)


def set_scan_log_scan_id(scan_id: str | uuid.UUID | None) -> None:
    """Bind without a reset, for task-scoped attribution.

    The queue consumer handles exactly one delivery per task, so setting the
    contextvar there is scoped by the task lifetime and does not leak into the
    next delivery.
    """
    scan_log_scan_id_var.set(str(scan_id) if scan_id else None)


def _as_uuid(value: Any) -> str | None:
    """Return the canonical UUID string, or None when it is not one.

    A log extra is caller-controlled, so it is validated rather than trusted:
    the column is a UUID and a junk value must not turn a log line into a failed
    insert.
    """
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, AttributeError, TypeError):
        return None


def resolve_scan_id(record: logging.LogRecord) -> str | None:
    """Which scan does this record belong to (if any)?"""
    bound = scan_log_scan_id_var.get()
    if bound:
        return _as_uuid(bound)
    return _as_uuid(record.__dict__.get("scan_id"))


def format_scan_log_message(record: logging.LogRecord) -> str:
    """Render one record into a single redacted, length-capped line."""
    from app.config.logging_config import scrub_text

    try:
        raw = record.getMessage()
    except Exception:  # noqa: BLE001 - a broken record must not break capture
        raw = str(record.msg)
    exc = record.exc_info[1] if record.exc_info else None
    if exc is not None:
        raw = f"{raw} — {type(exc).__name__}: {exc}"
    # Keep captured lines one-per-row: the panel renders them as log lines, and
    # a traceback with newlines would smuggle fake rows into the audit view.
    text = scrub_text(str(raw)).replace("\r", "\\r").replace("\n", "\\n")
    return text[:MAX_MESSAGE_CHARS]


class ScanLogHandler(logging.Handler):
    """Buffering handler that tags records with their scan and queues them."""

    def __init__(self, level: int = _CAPTURE_LEVEL) -> None:
        super().__init__(level=level)
        # `deque(maxlen=...)` drops the oldest silently instead of growing the
        # heap when the database is unreachable; a missing log line is always
        # better than a stalled worker.
        self._pending: deque[dict[str, Any]] = deque(maxlen=_PENDING_MAX)
        self._lock = threading.Lock()
        self.dropped = 0

    def emit(self, record: logging.LogRecord) -> None:  # noqa: D102 - logging API
        try:
            if record.levelno < self.level:
                return
            scan_id = resolve_scan_id(record)
            if scan_id is None:
                return
            row = {
                "scan_id": scan_id,
                "level": record.levelname[:10],
                "logger_name": (record.name or "unknown")[:120],
                "message": format_scan_log_message(record),
            }
            with self._lock:
                if len(self._pending) >= _PENDING_MAX:
                    self.dropped += 1
                    return
                self._pending.append(row)
        except Exception:  # noqa: BLE001 - logging must never raise
            self.handleError(record)

    def drain(self, limit: int = FLUSH_BATCH_SIZE) -> list[dict[str, Any]]:
        """Take up to ``limit`` buffered rows off the queue."""
        out: list[dict[str, Any]] = []
        with self._lock:
            while self._pending and len(out) < limit:
                out.append(self._pending.popleft())
        return out

    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)


class ScanLogCapture:
    """Owns the handler and the background flush task (one per process)."""

    def __init__(self, handler: ScanLogHandler | None = None) -> None:
        self.handler = handler or ScanLogHandler()
        self._task: asyncio.Task | None = None
        self._last_retention: dict[str, float] = {}
        self._installed_on: logging.Logger | None = None

    # -- lifecycle ------------------------------------------------------
    def install(self, logger_name: str = "app") -> None:
        """Attach the handler to ``logger_name`` (children propagate into it)."""
        target = logging.getLogger(logger_name)
        if self._installed_on is target:
            return
        target.addHandler(self.handler)
        # The handler has its own level; the logger's stays authoritative so
        # raising LOG_LEVEL still trims what gets captured.
        self.handler.setLevel(_CAPTURE_LEVEL)
        self._installed_on = target

    def start(self) -> None:
        """Install the handler and start the flush loop (idempotent)."""
        self.install()
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run(), name="scan-log-capture-flush")

    async def stop(self) -> None:
        """Flush what is buffered and detach cleanly (lifespan shutdown)."""
        task, self._task = self._task, None
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        await self.flush_once()

    async def _run(self) -> None:
        while True:
            try:
                await asyncio.sleep(FLUSH_INTERVAL_SECONDS)
                await self.flush_once()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - capture must never kill the loop
                logger.debug("scan-log-capture: flush failed", exc_info=True)

    # -- persistence ----------------------------------------------------
    async def flush_once(self) -> int:
        """Persist one batch. Returns the number of rows written."""
        rows = self.handler.drain()
        if not rows:
            return 0
        try:
            from sqlalchemy import delete, insert, select

            from app.infrastructure.database import AsyncSessionLocal
            from app.infrastructure.database.models import ScanLogLine

            async with AsyncSessionLocal() as db:
                await db.execute(insert(ScanLogLine).values(rows))
                for scan_id in {row["scan_id"] for row in rows}:
                    await self._apply_retention(db, scan_id, delete, select)
                await db.commit()
            return len(rows)
        except Exception:  # noqa: BLE001 - dropped lines are preferable to a crash
            logger.debug("scan-log-capture: could not persist %d line(s)", len(rows))
            return 0

    async def _apply_retention(self, db, scan_id: str, delete, select) -> None:
        """Keep only the newest ``MAX_LINES_PER_SCAN`` rows for one scan.

        Throttled per scan: the insert path is every second, and re-running the
        window on each batch would cost more than the writes.
        """
        from app.infrastructure.database.models import ScanLogLine

        now = time.monotonic()
        if now - self._last_retention.get(scan_id, 0.0) < _RETENTION_INTERVAL_SECONDS:
            return
        self._last_retention[scan_id] = now
        keep_ids = (
            select(ScanLogLine.id)
            .where(ScanLogLine.scan_id == scan_id)
            .order_by(ScanLogLine.id.desc())
            .limit(MAX_LINES_PER_SCAN)
            .scalar_subquery()
        )
        await db.execute(
            delete(ScanLogLine)
            .where(ScanLogLine.scan_id == scan_id)
            .where(ScanLogLine.id.notin_(keep_ids))
        )


# Process-wide singleton; `start()` is called from the API lifespan and from the
# queue consumer's startup so both processes capture their own log records.
scan_log_capture = ScanLogCapture()
