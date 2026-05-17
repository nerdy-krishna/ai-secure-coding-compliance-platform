"""Auto-decline sweeper for stuck approval-gate interrupts.

ADR-009 / M7 / G9 — Programmatic callers (CI bots, the MCP
``sccap_submit_scan`` tool) can submit scans that pause at an
approval gate forever if no human ever visits the scan-status page.
This background task runs on the API container, mirrors the
``outbox_sweeper`` shape, and transitions any scan stuck at one of the
human-in-the-loop gate statuses — ``STATUS_PENDING_PRESCAN_APPROVAL``
(ADR-009) or ``STATUS_PENDING_PROFILING_APPROVAL`` (#71) — for more
than ``PRESCAN_APPROVAL_TIMEOUT_HOURS`` (default 24h) to
``STATUS_BLOCKED_USER_DECLINE``. A scan_event row
(``PRESCAN_AUTO_DECLINED`` / ``PROFILING_AUTO_DECLINED``) is written so
operators can correlate.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select, update

from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database import models as db_models
from app.shared.lib.scan_status import (
    STATUS_BLOCKED_USER_DECLINE,
    STATUS_PENDING_PRESCAN_APPROVAL,
    STATUS_PENDING_PROFILING_APPROVAL,
)

logger = logging.getLogger(__name__)

# Gate statuses this sweeper auto-declines, mapped to the audit
# scan_event stage name written when a stuck scan is transitioned.
_GATE_STATUS_EVENTS = {
    STATUS_PENDING_PRESCAN_APPROVAL: "PRESCAN_AUTO_DECLINED",
    STATUS_PENDING_PROFILING_APPROVAL: "PROFILING_AUTO_DECLINED",
}

# Default 24 h — matches ADR-009. Operators can tighten this for
# unattended deployments by editing the constant; full env-var
# parameterisation is filed as a follow-up.
PRESCAN_APPROVAL_TIMEOUT_HOURS = 24
SWEEPER_INTERVAL_SECONDS = 300  # 5 minutes — cheap polling


async def _delete_checkpointer_thread(scan_id: str) -> None:
    """Best-effort delete of the LangGraph checkpointer thread for a
    scan that the sweeper just transitioned to a terminal status.
    Imports lazily to avoid pulling the worker-only deps into the API
    process at module load. M5 / G7.
    """
    try:
        from app.infrastructure.workflows.worker_graph import get_workflow

        wf = await get_workflow()
        ckp = getattr(wf, "checkpointer", None)
        if ckp is None or not hasattr(ckp, "adelete_thread"):
            return
        await ckp.adelete_thread(thread_id=scan_id)
    except Exception as e:
        logger.warning(
            "prescan_approval_sweeper: checkpointer cleanup failed for %s: %s",
            scan_id,
            e,
        )


async def _sweep_once() -> int:
    """Single sweep pass. Returns the number of scans transitioned.

    Cutoff column choice: we want "time the scan entered the approval
    gate", not "time the scan was created" (a backed-up worker queue
    would otherwise auto-decline scans the moment they pause). The most
    recent ``scan_events.timestamp`` for each scan is the closest
    signal we have without adding an ``updated_at`` column to
    ``scans``. Critical-secret-blocked scans terminate via a different
    path so they never enter this query.

    Both gate statuses (prescan-approval and profiling-cost) are swept
    in one pass; the audit scan_event name is chosen per row.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(
        hours=PRESCAN_APPROVAL_TIMEOUT_HOURS
    )
    gate_statuses = list(_GATE_STATUS_EVENTS)
    transitioned = 0
    transitioned_ids: list[str] = []
    async with AsyncSessionLocal() as db:
        latest_event_ts = (
            select(func.max(db_models.ScanEvent.timestamp))
            .where(db_models.ScanEvent.scan_id == db_models.Scan.id)
            .correlate(db_models.Scan)
            .scalar_subquery()
        )
        stmt = (
            select(db_models.Scan.id, db_models.Scan.status)
            .where(db_models.Scan.status.in_(gate_statuses))
            .where(latest_event_ts < cutoff)
        )
        rows = (await db.execute(stmt)).all()
        for scan_id, gate_status in rows:
            # Atomic transition: only flip the status if the scan is
            # still at the SAME gate. Defends against a race with a
            # concurrent operator click on the approve / decline
            # endpoint. (Phase-9 Medium finding.)
            res = await db.execute(
                update(db_models.Scan)
                .where(db_models.Scan.id == scan_id)
                .where(db_models.Scan.status == gate_status)
                .values(status=STATUS_BLOCKED_USER_DECLINE)
            )
            if res.rowcount != 1:
                # Operator beat us to it — skip the audit row.
                continue
            db.add(
                db_models.ScanEvent(
                    scan_id=scan_id,
                    stage_name=_GATE_STATUS_EVENTS[gate_status],
                    status="COMPLETED",
                )
            )
            transitioned += 1
            transitioned_ids.append(str(scan_id))
            logger.info(
                "prescan_approval_sweeper: scan_id=%s timed out after %dh -> %s",
                scan_id,
                PRESCAN_APPROVAL_TIMEOUT_HOURS,
                STATUS_BLOCKED_USER_DECLINE,
            )
        await db.commit()

    # Best-effort: drop checkpointer thread for each scan we
    # transitioned. Runs OUTSIDE the DB session to avoid holding the
    # connection during a network round-trip. (M5 / G7.)
    for sid in transitioned_ids:
        await _delete_checkpointer_thread(sid)

    return transitioned


async def run_prescan_approval_sweeper(stop_event: asyncio.Event) -> None:
    """Background task entry point. Runs until ``stop_event`` is set."""
    logger.info(
        "prescan_approval_sweeper: starting (interval=%ds, timeout=%dh)",
        SWEEPER_INTERVAL_SECONDS,
        PRESCAN_APPROVAL_TIMEOUT_HOURS,
    )
    while not stop_event.is_set():
        try:
            count = await _sweep_once()
            if count:
                logger.info(
                    "prescan_approval_sweeper: transitioned %d scan(s) to "
                    "BLOCKED_USER_DECLINE",
                    count,
                )
        except Exception as e:
            logger.error(
                "prescan_approval_sweeper: sweep pass failed: %s",
                e,
                exc_info=True,
            )
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=SWEEPER_INTERVAL_SECONDS)
        except asyncio.TimeoutError:
            pass
    logger.info("prescan_approval_sweeper: stopped")
