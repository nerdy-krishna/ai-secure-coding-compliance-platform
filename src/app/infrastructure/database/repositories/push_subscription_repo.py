"""Repository for Web Push subscriptions (#90 / PRD #83)."""

from __future__ import annotations

import logging

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models

logger = logging.getLogger(__name__)


class PushSubscriptionRepository:
    """CRUD for a user's browser Web Push subscriptions."""

    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    async def upsert(self, user_id: int, endpoint: str, p256dh: str, auth: str) -> None:
        """Register (or refresh) a browser push subscription.

        Keyed on the unique `endpoint`: a browser re-subscribing — or a
        subscription moving to a different user on a shared machine —
        updates the row in place rather than duplicating it.
        """
        stmt = (
            pg_insert(db_models.PushSubscription)
            .values(
                user_id=user_id,
                endpoint=endpoint,
                p256dh=p256dh,
                auth=auth,
            )
            .on_conflict_do_update(
                index_elements=["endpoint"],
                set_={"user_id": user_id, "p256dh": p256dh, "auth": auth},
            )
        )
        await self.db.execute(stmt)
        await self.db.commit()

    async def delete_by_endpoint(self, endpoint: str) -> None:
        """Remove a subscription (the browser unsubscribed)."""
        await self.db.execute(
            delete(db_models.PushSubscription).where(
                db_models.PushSubscription.endpoint == endpoint
            )
        )
        await self.db.commit()

    async def list_for_user(self, user_id: int) -> list[db_models.PushSubscription]:
        """Every push subscription registered by a user."""
        result = await self.db.execute(
            select(db_models.PushSubscription).where(
                db_models.PushSubscription.user_id == user_id
            )
        )
        return list(result.scalars().all())
