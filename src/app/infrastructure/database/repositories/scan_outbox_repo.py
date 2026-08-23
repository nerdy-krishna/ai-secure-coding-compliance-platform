"""Repository for the scan_outbox table.

The outbox is a transactional guarantee that every scan row has a
corresponding publish attempt. Writes to `scan_outbox` happen in the same
HTTP request that creates the Scan; a sweep task re-publishes any row with
`published_at IS NULL` older than a few seconds.
"""

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models

logger = logging.getLogger(__name__)


class ScanOutboxRepository:
    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    async def enqueue(
        self,
        scan_id: uuid.UUID,
        queue_name: str,
        payload: Dict,
        *,
        idempotency_key: str | None = None,
        commit: bool = True,
    ) -> db_models.ScanOutbox:
        """Insert an unpublished outbox row.

        ``commit=False`` lets an application service include dispatch intent in
        the same transaction as its aggregate state change.
        """
        attempt_id = await self.db.scalar(
            select(db_models.Scan.current_attempt_id).where(
                db_models.Scan.id == scan_id
            )
        )
        payload = dict(payload)
        if attempt_id is not None:
            payload.setdefault("attempt_id", str(attempt_id))
        row = db_models.ScanOutbox(
            scan_id=scan_id,
            attempt_id=attempt_id,
            queue_name=queue_name,
            payload=payload,
            idempotency_key=idempotency_key,
        )
        self.db.add(row)
        if commit:
            await self.db.commit()
        else:
            await self.db.flush()
        await self.db.refresh(row)
        logger.info(
            "scan_outbox.enqueued",
            extra={
                "outbox_id": str(row.id),
                "scan_id": str(scan_id),
                "queue_name": queue_name,
            },
        )
        return row

    async def mark_published(self, outbox_id: uuid.UUID) -> None:
        """Marks an outbox row published_at=now. Commits."""
        await self.db.execute(
            update(db_models.ScanOutbox)
            .where(db_models.ScanOutbox.id == outbox_id)
            .values(published_at=datetime.now(timezone.utc))
        )
        await self.db.commit()
        logger.info("scan_outbox.published", extra={"outbox_id": str(outbox_id)})

    async def record_failed_attempt(self, outbox_id: uuid.UUID) -> None:
        """Increments attempts on a publish failure. Commits."""
        await self.db.execute(
            update(db_models.ScanOutbox)
            .where(db_models.ScanOutbox.id == outbox_id)
            .values(attempts=db_models.ScanOutbox.attempts + 1)
        )
        await self.db.commit()
        logger.warning(
            "scan_outbox.publish_attempt_failed",
            extra={"outbox_id": str(outbox_id)},
        )

    async def list_unpublished(
        self, older_than_seconds: int = 30, limit: int = 50
    ) -> List[db_models.ScanOutbox]:
        """Returns unpublished rows that were created more than N seconds ago.

        ``older_than_seconds`` is an optional operational delay. Submission
        uses zero because request handlers never publish inline.

        Rows are locked with FOR UPDATE SKIP LOCKED so that concurrent sweeper
        replicas each claim a disjoint set of rows, eliminating the
        duplicate-publish race.  Callers must commit or rollback the same
        transaction that fetched the rows so the advisory lock is released only
        after mark_published has run.
        """
        cutoff = datetime.now(timezone.utc).timestamp() - older_than_seconds
        stmt = (
            select(db_models.ScanOutbox)
            .where(db_models.ScanOutbox.published_at.is_(None))
            .where(
                db_models.ScanOutbox.created_at
                < datetime.fromtimestamp(cutoff, tz=timezone.utc)
            )
            .order_by(db_models.ScanOutbox.created_at.asc())
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def purge_published(self, older_than_days: int) -> int:
        """Deletes published outbox rows older than the given retention window.

        Returns the number of rows deleted.  Intended to be called by the
        outbox sweeper once per day to prevent indefinite accumulation of
        already-published rows.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
        stmt = (
            delete(db_models.ScanOutbox)
            .where(db_models.ScanOutbox.published_at.isnot(None))
            .where(db_models.ScanOutbox.published_at < cutoff)
        )
        res = await self.db.execute(stmt)
        await self.db.commit()
        return res.rowcount or 0
