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
from app.infrastructure.database.tenant_context import system_principal_task
from app.shared.lib.scan_status import (
    STATUS_CANCELLED,
    STATUS_FAILED,
    STATUS_QUEUED,
    STATUS_QUEUED_FOR_SCAN,
    scan_status_predecessors,
)

logger = logging.getLogger(__name__)

# Workers start consuming within seconds; 10 minutes is generous enough
# to cover slow cold starts while being short enough that a genuinely
# crashed worker is noticed quickly.
STUCK_SCAN_TIMEOUT_SECONDS = 600  # 10 min

# Only these statuses indicate the scan was picked up but stalled.
_STUCK_STATUSES = {STATUS_QUEUED_FOR_SCAN, STATUS_QUEUED}

# A cancellation is acknowledged by the worker that is running the scan (250 ms poll
# plus a 2 s SLO). When that worker is restarted or killed first - a deploy does
# exactly that - nothing is left to append the acknowledgement, the scan stays
# CANCELLED with an unfinished trail, and the UI keeps polling it every few seconds
# as if it were still working. Ten times the SLO is a safe grace window.
_CANCELLATION_RECONCILE_SECONDS = 120


@system_principal_task("stuck-scan-sweeper")
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

        stuck_ids = (
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
        )

        allowed_sources = _STUCK_STATUSES.intersection(
            scan_status_predecessors(STATUS_FAILED)
        )

        # Capture the ids first: the scan needs a visible reason on its own timeline,
        # not just a silent status flip. "Queued for 10 minutes" with no explanation is
        # exactly what made a worker that never consumed look like a stuck scan.
        doomed_ids = (
            (
                await db.execute(
                    select(db_models.Scan.id)
                    .where(
                        db_models.Scan.id.in_(stuck_ids),
                        db_models.Scan.status.in_(tuple(sorted(allowed_sources))),
                    )
                    .limit(50)
                )
            )
            .scalars()
            .all()
        )

        result = await db.execute(
            update(db_models.Scan)
            .where(
                db_models.Scan.id.in_(doomed_ids),
                db_models.Scan.status.in_(tuple(sorted(allowed_sources))),
            )
            .values(status=STATUS_FAILED)
        )
        count = result.rowcount
        if count:
            await db.commit()
            logger.warning(
                "stuck_scan_sweeper: marked %d scans FAILED (stuck > %ds)",
                count,
                STUCK_SCAN_TIMEOUT_SECONDS,
            )
            from app.infrastructure.database.repositories.scan_repo import (
                ScanRepository,
            )

            for scan_id in doomed_ids:
                try:
                    await ScanRepository(db).set_error_message(
                        scan_id,
                        "No worker picked this scan up within "
                        f"{STUCK_SCAN_TIMEOUT_SECONDS}s; it was marked FAILED. "
                        "Check that the worker container is running and consuming "
                        "code_submission_queue.",
                    )
                    await ScanRepository(db).create_scan_event(
                        scan_id=scan_id,
                        stage_name="WORKER_DELIVERY_TIMEOUT",
                        status="FAILED",
                        details={
                            "message": (
                                "No worker consumed this scan's queue message within "
                                f"{STUCK_SCAN_TIMEOUT_SECONDS}s. The scan never started."
                            ),
                            "timeout_seconds": STUCK_SCAN_TIMEOUT_SECONDS,
                            "queue": "code_submission_queue",
                        },
                        activity_kind="warning",
                        commit=False,
                    )
                except Exception:  # noqa: BLE001 - one scan must not stop the sweep
                    logger.warning(
                        "stuck_scan_sweeper: could not annotate scan %s",
                        scan_id,
                        exc_info=True,
                    )
            await db.commit()
        return count or 0


@system_principal_task("stuck-scan-sweeper")
async def _reconcile_incomplete_cancellations() -> int:
    """Finish cancelling scans whose worker never acknowledged the stop.

    Idempotent: `record_cancellation_phase` skips a phase that already exists, so a
    scan that *did* acknowledge is never touched.
    """
    from app.infrastructure.workflows.cancellation import record_cancellation_phase

    async with AsyncSessionLocal() as db:
        cutoff = datetime.fromtimestamp(
            datetime.now(timezone.utc).timestamp() - _CANCELLATION_RECONCILE_SECONDS,
            tz=timezone.utc,
        )
        acknowledged = (
            select(db_models.ScanEvent.scan_id)
            .where(
                db_models.ScanEvent.stage_name == "CANCELLATION",
                db_models.ScanEvent.status == "COMPLETED",
            )
            .scalar_subquery()
        )
        stale_ids = (
            (
                await db.execute(
                    select(db_models.Scan.id)
                    .where(
                        db_models.Scan.status == STATUS_CANCELLED,
                        db_models.Scan.id.notin_(acknowledged),
                        func.coalesce(
                            db_models.Scan.completed_at, db_models.Scan.created_at
                        )
                        < cutoff,
                    )
                    .limit(50)
                )
            )
            .scalars()
            .all()
        )

    reconciled = 0
    for scan_id in stale_ids:
        try:
            await record_cancellation_phase(scan_id, "OBSERVED")
            await record_cancellation_phase(scan_id, "COMPLETED")
            reconciled += 1
        except Exception:  # noqa: BLE001 - a sweep must not die on one scan
            logger.warning(
                "stuck_scan_sweeper: could not reconcile cancellation for %s",
                scan_id,
                exc_info=True,
            )
    if reconciled:
        logger.warning(
            "stuck_scan_sweeper: reconciled %d incomplete cancellation(s)",
            reconciled,
        )
    return reconciled


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
        try:
            await _reconcile_incomplete_cancellations()
        except Exception:
            logger.error(
                "stuck_scan_sweeper: cancellation reconciliation failed", exc_info=True
            )
    logger.info("stuck_scan_sweeper: stopped")
