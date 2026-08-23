"""Durable, transaction-bound replay claims for federation messages."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone

from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models


async def claim_message_once(
    db: AsyncSession,
    *,
    provider_id: uuid.UUID,
    kind: str,
    message_id: str,
    expires_at: datetime,
) -> bool:
    """Return True only for the first live claim of a provider message ID."""
    now = datetime.now(timezone.utc)
    await db.execute(
        delete(db_models.FederationReplayMarker).where(
            db_models.FederationReplayMarker.expires_at <= now
        )
    )
    message_hash = hashlib.sha256(message_id.encode("utf-8")).hexdigest()
    result = await db.execute(
        pg_insert(db_models.FederationReplayMarker)
        .values(
            provider_id=provider_id,
            kind=kind[:32],
            message_hash=message_hash,
            expires_at=expires_at,
        )
        .on_conflict_do_nothing(
            constraint="uq_federation_replay_provider_kind_message"
        )
        .returning(db_models.FederationReplayMarker.id)
    )
    return result.scalar_one_or_none() is not None
