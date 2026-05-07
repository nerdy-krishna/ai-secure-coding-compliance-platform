"""Admin endpoints for SCIM token issuance + revocation.

Surface (all superuser-only):

  GET    /api/v1/admin/scim/tokens        — list (token plaintext NEVER returned)
  POST   /api/v1/admin/scim/tokens        — issue (plaintext returned ONCE)
  DELETE /api/v1/admin/scim/tokens/{id}   — revoke

The plaintext is returned only in the POST response body; it is not
re-derivable from anything stored. The frontend should display it once
+ encourage the operator to copy it immediately.
"""

from __future__ import annotations

import logging
import uuid as _uuid
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.auth.core import current_active_user
from app.infrastructure.auth.scim.auth import hash_token, issue_plaintext_token
from app.infrastructure.auth.sso import audit
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db


logger = logging.getLogger(__name__)


router = APIRouter(prefix="/admin/scim", tags=["Admin: SCIM"])


_VALID_SCOPES = {"users:read", "users:write"}


class ScimTokenCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(..., min_length=1, max_length=128)
    scopes: List[str] = Field(..., min_length=1, max_length=10)
    expires_at: Optional[datetime] = None


class ScimTokenRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: _uuid.UUID
    name: str
    scopes: List[str]
    created_at: datetime
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]


class ScimTokenIssued(ScimTokenRead):
    """Returned ONLY from POST. Carries the plaintext token; the caller is
    expected to copy it immediately because it can't be retrieved later."""

    plaintext_token: str


async def _require_superuser(
    current_user: db_models.User = Depends(current_active_user),
) -> db_models.User:
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Not enough privileges"
        )
    return current_user


@router.get("/tokens", response_model=List[ScimTokenRead])
async def list_tokens(
    db: AsyncSession = Depends(get_db),
    _user: db_models.User = Depends(_require_superuser),
):
    rows = (
        (
            await db.execute(
                select(db_models.ScimToken).order_by(db_models.ScimToken.created_at)
            )
        )
        .scalars()
        .all()
    )
    return [ScimTokenRead.model_validate(r) for r in rows]


@router.post(
    "/tokens",
    response_model=ScimTokenIssued,
    status_code=status.HTTP_201_CREATED,
)
async def create_token(
    request: Request,
    payload: ScimTokenCreate = Body(...),
    db: AsyncSession = Depends(get_db),
    user: db_models.User = Depends(_require_superuser),
):
    bad = [s for s in payload.scopes if s not in _VALID_SCOPES]
    if bad:
        raise HTTPException(
            status_code=400,
            detail=f"unknown scope(s): {bad}; allowed: {sorted(_VALID_SCOPES)}",
        )
    plaintext = issue_plaintext_token()
    row = db_models.ScimToken(
        name=payload.name,
        token_hash=hash_token(plaintext),
        scopes=list(payload.scopes),
        expires_at=payload.expires_at,
        created_by_user_id=user.id,
    )
    db.add(row)
    await db.flush()
    await audit.record(
        db,
        event="scim.token.created",
        user_id=user.id,
        request=request,
        details={"name": payload.name, "scopes": list(payload.scopes)},
    )
    await db.commit()
    return ScimTokenIssued(
        id=row.id,
        name=row.name,
        scopes=list(row.scopes),
        created_at=row.created_at,
        expires_at=row.expires_at,
        last_used_at=row.last_used_at,
        plaintext_token=plaintext,
    )


@router.delete("/tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_token(
    request: Request,
    token_id: _uuid.UUID = Path(...),
    db: AsyncSession = Depends(get_db),
    user: db_models.User = Depends(_require_superuser),
):
    row = (
        await db.execute(
            select(db_models.ScimToken).where(db_models.ScimToken.id == token_id)
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="token not found")
    name = row.name
    await db.delete(row)
    await audit.record(
        db,
        event="scim.token.revoked",
        user_id=user.id,
        request=request,
        details={"name": name, "token_uuid": str(token_id)},
    )
    await db.commit()


__all__ = ["router"]
