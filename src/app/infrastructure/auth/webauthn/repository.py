"""Async CRUD over `webauthn_credentials`."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models


class WebAuthnRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def list_for_user(self, user_id: int) -> List[db_models.WebAuthnCredential]:
        result = await self.session.execute(
            select(db_models.WebAuthnCredential)
            .where(db_models.WebAuthnCredential.user_id == user_id)
            .order_by(db_models.WebAuthnCredential.created_at)
        )
        return list(result.scalars().all())

    async def get_by_credential_id(
        self, credential_id: bytes
    ) -> Optional[db_models.WebAuthnCredential]:
        result = await self.session.execute(
            select(db_models.WebAuthnCredential).where(
                db_models.WebAuthnCredential.credential_id == credential_id
            )
        )
        return result.scalar_one_or_none()

    async def get_by_id(
        self, credential_pk: uuid.UUID
    ) -> Optional[db_models.WebAuthnCredential]:
        result = await self.session.execute(
            select(db_models.WebAuthnCredential).where(
                db_models.WebAuthnCredential.id == credential_pk
            )
        )
        return result.scalar_one_or_none()

    async def create(
        self,
        *,
        user_id: int,
        credential_id: bytes,
        public_key: bytes,
        sign_count: int,
        transports: Optional[List[str]],
        friendly_name: str,
    ) -> db_models.WebAuthnCredential:
        row = db_models.WebAuthnCredential(
            user_id=user_id,
            credential_id=credential_id,
            public_key=public_key,
            sign_count=sign_count,
            transports=transports,
            friendly_name=friendly_name,
        )
        self.session.add(row)
        await self.session.flush()
        return row

    async def update_sign_count(self, credential_pk: uuid.UUID, new_count: int) -> None:
        await self.session.execute(
            update(db_models.WebAuthnCredential)
            .where(db_models.WebAuthnCredential.id == credential_pk)
            .values(
                sign_count=new_count,
                last_used_at=datetime.now(timezone.utc),
            )
        )
        await self.session.flush()

    async def delete(self, credential_pk: uuid.UUID, *, user_id: int) -> bool:
        """Delete a credential, scoped to the requesting user. Returns True
        on success; False if the credential doesn't exist or doesn't belong
        to the requester."""
        row = await self.get_by_id(credential_pk)
        if row is None or row.user_id != user_id:
            return False
        await self.session.delete(row)
        await self.session.flush()
        return True
