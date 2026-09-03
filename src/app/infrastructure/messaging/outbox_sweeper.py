"""Background task that re-publishes unpublished scan_outbox rows.

Started from the FastAPI lifespan. Runs forever on a fixed interval until the
app shuts down. Each tick:
  1. Selects up to `BATCH_SIZE` committed unpublished rows.
  2. For each, calls publish_message; on success marks published_at, on
     failure increments attempts and leaves the row for the next tick.
"""

import asyncio
import logging

from app.config.config import settings
from app.infrastructure.database.database import AsyncSessionLocal
from app.infrastructure.database.repositories.scan_outbox_repo import (
    ScanOutboxRepository,
)
from app.infrastructure.database.repositories.pentesting import (
    PentestEngagementRepository,
)
from app.infrastructure.database.tenant_context import principal_scope
from app.infrastructure.messaging.publisher import publish_message

logger = logging.getLogger(__name__)

SWEEP_INTERVAL_SECONDS = 1
MIN_AGE_SECONDS = 0
BATCH_SIZE = 50


async def _reconcile_capability13_governance(db) -> int:
    """Reuse the existing sweeper topology for DB-time waiver transitions."""

    if not settings.PENTEST_CAPABILITY13_GOVERNANCE_WRITES:
        return 0
    from app.core.services.pentesting.capability13_authorities import (
        SqlCapability13GovernanceSubjectAuthority,
    )
    from app.core.services.pentesting.capability13_governance_service import (
        Capability13GovernanceService,
    )
    from app.infrastructure.database.repositories.pentesting.capability13_governance_repo import (
        SqlCapability13GovernanceRepository,
    )

    transitions = await Capability13GovernanceService(
        SqlCapability13GovernanceRepository(db),
        SqlCapability13GovernanceSubjectAuthority(db),
    ).reconcile_due(limit=BATCH_SIZE)
    return len(transitions)


async def _tick() -> None:
    with principal_scope(
        tenant_id=None,
        principal_kind="system",
        principal_id="outbox-sweeper",
        system_scope=True,
    ):
        async with AsyncSessionLocal() as db:
            governance_count = await _reconcile_capability13_governance(db)
            repo = ScanOutboxRepository(db)
            pentest_repo = PentestEngagementRepository(db)
            rows = await repo.list_unpublished(
                older_than_seconds=MIN_AGE_SECONDS, limit=BATCH_SIZE
            )
            for row in rows:
                try:
                    payload = dict(row.payload)
                    correlation_id = payload.pop("correlation_id", None)
                    published = await publish_message(
                        queue_name=row.queue_name,
                        message_body=payload,
                        correlation_id=correlation_id,
                    )
                    if published:
                        await repo.mark_published(row.id)
                        logger.info(
                            "outbox_sweep.republished",
                            extra={
                                "scan_id": str(row.scan_id),
                                "attempts": row.attempts + 1,
                            },
                        )
                    else:
                        await repo.record_failed_attempt(row.id)
                except Exception:
                    logger.error(
                        "outbox_sweep.republish_failed",
                        extra={"scan_id": str(row.scan_id)},
                        exc_info=True,
                    )
                    try:
                        await repo.record_failed_attempt(row.id)
                    except Exception:
                        pass
            # Scan outbox repository methods commit per row. Acquire Pentesting
            # locks only after those commits so they remain held until each
            # Pentesting row is published or recorded as failed.
            pentest_rows = await pentest_repo.list_unpublished(limit=BATCH_SIZE)
            if not rows and not pentest_rows and not governance_count:
                return
            logger.info(
                "outbox_sweep.batch",
                extra={
                    "scan_count": len(rows),
                    "pentest_count": len(pentest_rows),
                    "c13_governance_count": governance_count,
                },
            )
            for row in pentest_rows:
                engagement_id = str(row.engagement_id)
                try:
                    payload = dict(row.payload)
                    correlation_id = payload.pop("correlation_id", None)
                    published = await publish_message(
                        queue_name=row.queue_name,
                        message_body=payload,
                        correlation_id=correlation_id,
                    )
                    if published:
                        await pentest_repo.mark_published(row.id)
                    else:
                        await pentest_repo.record_publish_failure(row.id)
                    await db.commit()
                except Exception:
                    await db.rollback()
                    logger.error(
                        "outbox_sweep.pentest_republish_failed",
                        extra={"engagement_id": engagement_id},
                        exc_info=True,
                    )


async def run_outbox_sweeper(stop_event: asyncio.Event) -> None:
    """Main loop. Exits cleanly when stop_event is set."""
    logger.info(
        "outbox_sweeper.started",
        extra={"interval": SWEEP_INTERVAL_SECONDS, "min_age": MIN_AGE_SECONDS},
    )
    while not stop_event.is_set():
        try:
            await _tick()
        except Exception:
            logger.error("outbox_sweep.tick_failed", exc_info=True)

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=SWEEP_INTERVAL_SECONDS)
        except asyncio.TimeoutError:
            continue

    logger.info("Outbox sweeper stopped.")
