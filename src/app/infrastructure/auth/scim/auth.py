"""Bearer-token authentication for SCIM endpoints.

Tokens are admin-issued via a separate admin endpoint. Plaintext is
shown ONCE at issue time; the DB stores only ``sha256(token)``. On
every SCIM request we hash the incoming bearer and look it up.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db


logger = logging.getLogger(__name__)


# Plaintext token shape: "scim_" + 48 char URL-safe base64. Visually
# distinct from JWTs (no dots) so an operator pasting one into the wrong
# field gets caught at validation.
TOKEN_PREFIX = "scim_"


def hash_token(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def issue_plaintext_token() -> str:
    """Generate a fresh SCIM bearer token. Returned ONCE; never re-derivable."""
    return TOKEN_PREFIX + secrets.token_urlsafe(36)  # ~48 char body


async def scim_token_auth(
    db: AsyncSession = Depends(get_db),
    authorization: Optional[str] = Header(default=None),
) -> Tuple[db_models.ScimToken, List[str]]:
    """FastAPI dependency: validate the Authorization: Bearer header.

    Returns ``(token_row, scopes)``. Raises 401 on missing/invalid;
    422 on a non-Bearer scheme; 403 if the token is expired.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    parts = authorization.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Authorization must use the Bearer scheme",
        )
    bearer = parts[1].strip()
    if not bearer.startswith(TOKEN_PREFIX):
        # Reject early — this isn't a SCIM token. Helps operators who
        # mistakenly paste a JWT.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid SCIM token",
        )
    token_hash = hash_token(bearer)
    result = await db.execute(
        select(db_models.ScimToken).where(db_models.ScimToken.token_hash == token_hash)
    )
    row = result.scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid SCIM token",
        )
    if row.expires_at is not None and row.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="SCIM token expired",
        )
    # Bump last_used_at; best-effort.
    try:
        await db.execute(
            update(db_models.ScimToken)
            .where(db_models.ScimToken.id == row.id)
            .values(last_used_at=datetime.now(timezone.utc))
        )
        # Don't commit here — caller's transaction owns the boundary.
    except Exception:
        logger.warning("scim.token.last_used_update_failed", exc_info=True)
    return row, list(row.scopes or [])


def require_scope(required: str):
    """FastAPI dependency factory: assert the token carries ``required``."""

    async def _check(
        token: Tuple[db_models.ScimToken, List[str]] = Depends(scim_token_auth),
    ) -> Tuple[db_models.ScimToken, List[str]]:
        _row, scopes = token
        if required not in scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"SCIM token missing required scope: {required}",
            )
        return token

    return _check
