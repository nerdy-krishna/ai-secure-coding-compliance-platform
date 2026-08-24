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
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models
from app.infrastructure.observability import inject_trace_context
from app.infrastructure.observability.otel import utc_timestamp

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
        scan_identity = (
            await self.db.execute(
                select(
                    db_models.Scan.current_attempt_id,
                    db_models.Scan.tenant_id,
                ).where(db_models.Scan.id == scan_id)
            )
        ).one_or_none()
        if scan_identity is None:
            raise ValueError("cannot enqueue dispatch for an unknown scan")
        attempt_id, tenant_id = scan_identity
        outbox_id = uuid.uuid4()
        payload = dict(payload)
        payload["outbox_id"] = str(outbox_id)
        payload["tenant_id"] = str(tenant_id)
        payload.setdefault("enqueued_at", utc_timestamp())
        inject_trace_context(payload)
        if attempt_id is not None:
            payload.setdefault("attempt_id", str(attempt_id))
        row = db_models.ScanOutbox(
            id=outbox_id,
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

    async def enqueue_once(
        self,
        scan_id: uuid.UUID,
        queue_name: str,
        payload: Dict,
        *,
        idempotency_key: str,
        commit: bool = True,
    ) -> db_models.ScanOutbox:
        """Idempotently enqueue one durable stage handoff.

        A replay may re-enter the graph node before its interrupt checkpoint is
        visible. PostgreSQL conflict handling guarantees that every replay
        observes the original outbox identity instead of publishing a second
        handoff.
        """
        scan_identity = (
            await self.db.execute(
                select(
                    db_models.Scan.current_attempt_id,
                    db_models.Scan.tenant_id,
                ).where(db_models.Scan.id == scan_id)
            )
        ).one_or_none()
        if scan_identity is None:
            raise ValueError("cannot enqueue dispatch for an unknown scan")
        attempt_id, tenant_id = scan_identity
        outbox_id = uuid.uuid4()
        prepared = dict(payload)
        prepared["outbox_id"] = str(outbox_id)
        prepared["tenant_id"] = str(tenant_id)
        prepared.setdefault("enqueued_at", utc_timestamp())
        if attempt_id is not None:
            prepared.setdefault("attempt_id", str(attempt_id))
        if str(prepared.get("attempt_id") or "") != str(attempt_id or ""):
            raise RuntimeError("handoff attempt does not match the current scan attempt")
        inject_trace_context(prepared)
        inserted_id = (
            await self.db.execute(
                pg_insert(db_models.ScanOutbox)
                .values(
                    id=outbox_id,
                    scan_id=scan_id,
                    attempt_id=attempt_id,
                    queue_name=queue_name,
                    payload=prepared,
                    idempotency_key=idempotency_key,
                    attempts=0,
                )
                .on_conflict_do_nothing(index_elements=["idempotency_key"])
                .returning(db_models.ScanOutbox.id)
            )
        ).scalar_one_or_none()
        if inserted_id is not None:
            row = await self.db.get(db_models.ScanOutbox, inserted_id)
            if row is None:  # pragma: no cover - same-transaction invariant
                raise RuntimeError("inserted outbox handoff is not readable")
        else:
            row = (
                await self.db.execute(
                    select(db_models.ScanOutbox).where(
                        db_models.ScanOutbox.idempotency_key == idempotency_key
                    )
                )
            ).scalar_one()
        if (
            row.scan_id != scan_id
            or row.attempt_id != attempt_id
            or row.queue_name != queue_name
            or row.payload.get("kind") != payload.get("kind")
        ):
            raise RuntimeError("outbox idempotency key is bound to another handoff")
        if commit:
            await self.db.commit()
        else:
            await self.db.flush()
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
