"""Stuck-scan sweeper — marks scans FAILED when the worker is down.

Scans that sit in QUEUED_FOR_SCAN or QUEUED for longer than
STUCK_SCAN_TIMEOUT_SECONDS (default 10 minutes) without being
processed by the worker are presumed crashed and transitioned to
FAILED.

This closes the gap where a worker import/syntax error causes the
whole process to die without ever ACKing or processing the message.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import func, select, update

from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database import models as db_models

logger = logging.getLogger(__name__)

# Workers start consuming within seconds; 10 minutes is generous enough
# to cover slow cold starts while being short enough that a genuinely
# crashed worker is noticed quickly.
STUCK_SCAN_TIMEOUT_SECONDS = 600  # 10 min

# Only these statuses indicate the scan was picked up but stalled.
_STUCK_STATUSES = {"QUEUED_FOR_SCAN", "QUEUED"}


async def _sweep_once() -> int:
    """Find and fail stuck scans.  Returns count of scans marked FAILED."""
    async with AsyncSessionLocal() as db:
        cutoff = datetime.fromtimestamp(
            datetime.now(timezone.utc).timestamp() - STUCK_SCAN_TIMEOUT_SECONDS,
            tz=timezone.utc,
        )
        # Find scans that are stuck in a non-terminal queue status AND
        # whose *most recent scan event* is older than the cutoff (not
        # just created_at — a scan that sat in PRESCAN_REVIEW WAITING
        # for 20 min before the user approved it is NOT stuck).
        #
        # We join scan_events and use the MAX(timestamp) per scan to
        # determine when the scan was last touched. Scans with no events
        # fall back to created_at.
        latest_event_subq = (
            select(
                db_models.ScanEvent.scan_id,
                func.max(db_models.ScanEvent.timestamp).label("last_event"),
            )
            .group_by(db_models.ScanEvent.scan_id)
            .subquery()
        )

        stuck_ids_subq = (
            select(db_models.Scan.id)
            .outerjoin(
                latest_event_subq,
                db_models.Scan.id == latest_event_subq.c.scan_id,
            )
            .where(
                db_models.Scan.status.in_(_STUCK_STATUSES),
                func.coalesce(
                    latest_event_subq.c.last_event,
                    db_models.Scan.created_at,
                )
                < cutoff,
            )
            .subquery()
        )

        result = await db.execute(
            update(db_models.Scan)
            .where(db_models.Scan.id.in_(stuck_ids_subq))
            .values(status="FAILED")
        )
        count = result.rowcount
        if count:
            await db.commit()
            logger.warning(
                "stuck_scan_sweeper: marked %d scans FAILED (stuck > %ds)",
                count,
                STUCK_SCAN_TIMEOUT_SECONDS,
            )
        return count or 0


async def run_stuck_scan_sweeper(stop_event: asyncio.Event) -> None:
    """Background loop — sweeps every 60 seconds."""
    logger.info(
        "stuck_scan_sweeper: started (timeout=%ds, interval=60s)",
        STUCK_SCAN_TIMEOUT_SECONDS,
    )
    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=60)
            break
        except asyncio.TimeoutError:
            pass
        except asyncio.CancelledError:
            break
        try:
            await _sweep_once()
        except Exception:
            logger.error("stuck_scan_sweeper: sweep failed", exc_info=True)
    logger.info("stuck_scan_sweeper: stopped")
