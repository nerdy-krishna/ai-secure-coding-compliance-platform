"""Persistence boundary for server-side browser sessions."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models


class AuthSessionRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(self, **values) -> db_models.AuthSession:
        row = db_models.AuthSession(**values)
        self.db.add(row)
        await self.db.flush()
        return row

    async def get_for_update(
        self, session_id: uuid.UUID
    ) -> db_models.AuthSession | None:
        return await self.db.scalar(
            select(db_models.AuthSession)
            .where(db_models.AuthSession.id == session_id)
            .with_for_update()
        )

    async def get(self, session_id: uuid.UUID) -> db_models.AuthSession | None:
        return await self.db.get(db_models.AuthSession, session_id)

    async def list_for_user(
        self,
        user_id: int,
        *,
        include_revoked: bool = False,
    ) -> list[db_models.AuthSession]:
        now = datetime.now(timezone.utc)
        query = select(db_models.AuthSession).where(
            db_models.AuthSession.user_id == user_id
        )
        if not include_revoked:
            query = query.where(
                db_models.AuthSession.revoked_at.is_(None),
                db_models.AuthSession.idle_expires_at > now,
                db_models.AuthSession.absolute_expires_at > now,
            )
        result = await self.db.scalars(
            query.order_by(db_models.AuthSession.last_seen_at.desc())
        )
        return list(result.all())

    async def revoke(
        self,
        row: db_models.AuthSession,
        *,
        reason: str,
        now: datetime | None = None,
    ) -> bool:
        if row.revoked_at is not None:
            return False
        row.revoked_at = now or datetime.now(timezone.utc)
        row.revocation_reason = reason[:64]
        await self.db.flush()
        return True

    async def revoke_all_for_user(
        self,
        user_id: int,
        *,
        reason: str,
        except_session_id: uuid.UUID | None = None,
        now: datetime | None = None,
    ) -> int:
        conditions = [
            db_models.AuthSession.user_id == user_id,
            db_models.AuthSession.revoked_at.is_(None),
        ]
        if except_session_id is not None:
            conditions.append(db_models.AuthSession.id != except_session_id)
        result = await self.db.execute(
            update(db_models.AuthSession)
            .where(*conditions)
            .values(
                revoked_at=now or datetime.now(timezone.utc),
                revocation_reason=reason[:64],
            )
        )
        await self.db.flush()
        return int(result.rowcount or 0)

    async def revoke_all_for_user_ids(
        self,
        user_ids: list[int],
        *,
        reason: str,
        now: datetime | None = None,
    ) -> int:
        if not user_ids:
            return 0
        result = await self.db.execute(
            update(db_models.AuthSession)
            .where(
                db_models.AuthSession.user_id.in_(user_ids),
                db_models.AuthSession.revoked_at.is_(None),
            )
            .values(
                revoked_at=now or datetime.now(timezone.utc),
                revocation_reason=reason[:64],
            )
        )
        await self.db.flush()
        return int(result.rowcount or 0)

    async def revoke_all_for_provider(
        self,
        provider_id: uuid.UUID,
        *,
        reason: str,
        now: datetime | None = None,
    ) -> int:
        result = await self.db.execute(
            update(db_models.AuthSession)
            .where(
                db_models.AuthSession.provider_id == provider_id,
                db_models.AuthSession.revoked_at.is_(None),
            )
            .values(
                revoked_at=now or datetime.now(timezone.utc),
                revocation_reason=reason[:64],
            )
        )
        await self.db.flush()
        return int(result.rowcount or 0)
