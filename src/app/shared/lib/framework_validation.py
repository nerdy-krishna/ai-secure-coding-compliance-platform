"""Shared validation: submitted framework names must be configured.

Scan submission and chat-session creation both accept a caller-supplied
list of framework names. They used to validate it against a *hardcoded*
allow-list of the original five frameworks — which silently rejected
every framework added later (CWE Essentials, ISVS) and every custom
framework an admin creates through Admin → Frameworks.

This validates against the live ``frameworks`` table instead, so any
configured framework is accepted with no code change. It is still a
strict positive-validation allow-list (V02.2.1) — the set is just
sourced from the database rather than frozen in code.
"""

from __future__ import annotations

from typing import Iterable

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models


async def validate_framework_selection(
    db: AsyncSession,
    frameworks: Iterable[str],
    *,
    require_non_empty: bool = True,
) -> None:
    """Raise HTTP 400 unless every name is a framework configured in the DB.

    Args:
        db: an active async session.
        frameworks: the caller-supplied framework names.
        require_non_empty: when True, an empty selection is itself a 400.
    """
    selected = list(frameworks or [])
    if require_non_empty and not selected:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="frameworks list must not be empty.",
        )
    known = set((await db.execute(select(db_models.Framework.name))).scalars().all())
    unknown = set(selected) - known
    if unknown:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Unknown framework(s): {sorted(unknown)}. "
                f"Configured frameworks: {sorted(known)}."
            ),
        )
