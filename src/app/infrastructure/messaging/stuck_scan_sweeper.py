"""Stuck-scan sweeper — marks scans FAILED when the worker is down.

Scans that sit in QUEUED_FOR_SCAN for longer than
STUCK_SCAN_TIMEOUT_SECONDS (default 10 minutes) without any scan
event being emitted are presumed crashed and transitioned to FAILED.

This closes the gap where a worker import/syntax error causes the
whole process to die without ever ACKing or processing the message.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import update

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
        cutoff = datetime.now(timezone.utc).timestamp() - STUCK_SCAN_TIMEOUT_SECONDS
        # Scans that were created (or had their status last changed) before
        # the cutoff, are in a stuck status, and have no scan events yet.
        result = await db.execute(
            update(db_models.Scan)
            .where(
                db_models.Scan.status.in_(_STUCK_STATUSES),
                db_models.Scan.created_at
                < datetime.fromtimestamp(cutoff, tz=timezone.utc),
            )
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
