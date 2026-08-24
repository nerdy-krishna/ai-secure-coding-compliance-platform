"""Two-phase, legal-hold-aware deletion of expired evidence objects."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, text

from app.config.config import settings
from app.infrastructure.database import AsyncSessionLocal, models as db_models
from app.infrastructure.database.repositories.evidence_repo import EvidenceRepository
from app.infrastructure.database.tenant_context import system_principal_task
from app.infrastructure.evidence.object_store import EvidenceObjectStore

logger = logging.getLogger(__name__)
SWEEP_INTERVAL_SECONDS = 3600
BATCH_SIZE = 100


async def _schedule_expired() -> int:
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        rows = list(
            (
                await db.scalars(
                    select(db_models.EvidenceObject)
                    .where(
                        db_models.EvidenceObject.state == "available",
                        db_models.EvidenceObject.legal_hold.is_(False),
                        db_models.EvidenceObject.retain_until <= now,
                    )
                    .order_by(db_models.EvidenceObject.retain_until)
                    .limit(BATCH_SIZE)
                    .with_for_update(skip_locked=True)
                )
            ).all()
        )
        repo = EvidenceRepository(db)
        for evidence in rows:
            await repo.schedule_deletion(
                evidence,
                actor_user_id=None,
                reason="retention_policy_expired",
                commit=False,
            )
        await db.commit()
        return len(rows)


async def _process_deletions() -> int:
    store = EvidenceObjectStore()
    processed = 0
    async with AsyncSessionLocal() as db:
        intents = list(
            (
                await db.scalars(
                    select(db_models.EvidenceDeletionOutbox)
                    .where(db_models.EvidenceDeletionOutbox.processed_at.is_(None))
                    .order_by(db_models.EvidenceDeletionOutbox.created_at)
                    .limit(BATCH_SIZE)
                    .with_for_update(skip_locked=True)
                )
            ).all()
        )
        repo = EvidenceRepository(db, object_store=store)
        for intent in intents:
            evidence = await db.get(db_models.EvidenceObject, intent.evidence_id)
            if evidence is None:
                intent.processed_at = datetime.now(timezone.utc)
                continue
            await db.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                {"key": f"governance-delete-barrier:{evidence.tenant_id}"},
            )
            await db.refresh(evidence)
            if evidence.legal_hold:
                evidence.state = "available"
                intent.processed_at = datetime.now(timezone.utc)
                repo._audit(
                    evidence,
                    "DELETION_REJECTED_LEGAL_HOLD",
                    actor_user_id=None,
                    reason="legal_hold_placed_after_scheduling",
                )
                continue
            try:
                await store.delete(
                    object_key=evidence.object_key,
                    object_version=evidence.object_version,
                )
            except Exception as exc:  # noqa: BLE001
                intent.attempts += 1
                intent.last_error = exc.__class__.__name__
                repo._audit(
                    evidence,
                    "DELETION_RETRY",
                    actor_user_id=None,
                    reason="object_store_delete_failed",
                    details={"error_class": exc.__class__.__name__},
                )
                logger.warning(
                    "evidence_retention.delete_failed",
                    extra={"evidence_id": str(evidence.id)},
                    exc_info=True,
                )
                continue
            evidence.state = "deleted"
            evidence.deleted_at = datetime.now(timezone.utc)
            evidence.wrapped_data_key = b""
            evidence.nonce = b""
            intent.processed_at = evidence.deleted_at
            intent.last_error = None
            repo._audit(
                evidence,
                "EVIDENCE_DELETED",
                actor_user_id=None,
                reason="retention_or_governed_deletion",
                details={"object_version": evidence.object_version},
            )
            processed += 1
        await db.commit()
    return processed


async def _delete_orphan_uploads() -> int:
    """Remove create-only uploads that never gained a committed DB reference."""
    store = EvidenceObjectStore()
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    candidates = await store.list_versions_older_than(cutoff, limit=BATCH_SIZE)
    deleted = 0
    async with AsyncSessionLocal() as db:
        for object_key, object_version in candidates:
            exists = await db.scalar(
                select(db_models.EvidenceObject.id).where(
                    db_models.EvidenceObject.object_key == object_key,
                    db_models.EvidenceObject.object_version == object_version,
                )
            )
            if exists is not None:
                continue
            await store.delete(object_key=object_key, object_version=object_version)
            deleted += 1
            logger.info(
                "evidence_retention.orphan_deleted",
                extra={"object_key": object_key, "object_version": object_version},
            )
    return deleted


@system_principal_task("evidence-retention-sweeper")
async def _sweep_once() -> tuple[int, int, int]:
    if not settings.EVIDENCE_STORE_ENABLED:
        return (0, 0, 0)
    return (
        await _schedule_expired(),
        await _process_deletions(),
        await _delete_orphan_uploads(),
    )


async def run_evidence_retention_sweeper(stop_event: asyncio.Event) -> None:
    if not settings.EVIDENCE_STORE_ENABLED:
        logger.info("evidence_retention.disabled")
        return
    logger.info("evidence_retention.started")
    while not stop_event.is_set():
        try:
            scheduled, deleted, orphans = await _sweep_once()
            if scheduled or deleted or orphans:
                logger.info(
                    "evidence_retention.completed",
                    extra={
                        "scheduled": scheduled,
                        "deleted": deleted,
                        "orphans": orphans,
                    },
                )
        except Exception:  # noqa: BLE001
            logger.error("evidence_retention.tick_failed", exc_info=True)
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=SWEEP_INTERVAL_SECONDS)
        except asyncio.TimeoutError:
            continue
    logger.info("evidence_retention.stopped")
