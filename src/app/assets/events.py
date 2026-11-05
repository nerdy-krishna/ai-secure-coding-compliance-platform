"""The inventory activity stream.

A check does a surprising amount of work — probing, fingerprinting, fetching a CVE that
was missing, matching, designing a template, testing it — and reported only the final
counts. This writes each step as it happens so the UI can tail it the way the pentest
run page tails a run.

Events are best-effort: emitting one must never fail the operation that is being
observed.
"""

from __future__ import annotations

import logging
from typing import Any, Optional
from uuid import UUID

from sqlalchemy import func, select

from app.assets import models as am
from app.infrastructure.database.database import AsyncSessionLocal

logger = logging.getLogger(__name__)

LEVELS = ("info", "success", "warning", "error", "detail")


async def emit(
    tenant_id: UUID,
    message: str,
    *,
    level: str = "info",
    kind: str = "info",
    payload: Optional[dict[str, Any]] = None,
    check_id: Optional[UUID] = None,
) -> None:
    try:
        async with AsyncSessionLocal() as db:
            db.add(
                am.AssetEvent(
                    tenant_id=tenant_id,
                    check_id=check_id,
                    level=level if level in LEVELS else "info",
                    kind=kind[:24],
                    message=message[:4000],
                    payload=payload,
                )
            )
            await db.commit()
    except Exception:  # noqa: BLE001 — observation must not break the work
        logger.warning("could not record an asset event", exc_info=True)


async def cursor(tenant_id: UUID) -> int:
    """Where the operator last cleared the view."""
    async with AsyncSessionLocal() as db:
        value = await db.scalar(
            select(am.AssetEventCursor.cleared_before).where(
                am.AssetEventCursor.tenant_id == tenant_id
            )
        )
    return int(value or 0)


async def recent(
    tenant_id: UUID, *, after_id: int = 0, limit: int = 300
) -> list[am.AssetEvent]:
    # The view starts where the operator left it, so clearing survives a reload.
    effective_after = max(after_id, await cursor(tenant_id))
    async with AsyncSessionLocal() as db:
        rows = await db.scalars(
            select(am.AssetEvent)
            .where(am.AssetEvent.tenant_id == tenant_id, am.AssetEvent.id > effective_after)
            .order_by(am.AssetEvent.id)
            .limit(limit)
        )
        return list(rows)


async def clear(tenant_id: UUID) -> int:
    """Hide the current log from the view. Nothing is deleted."""
    async with AsyncSessionLocal() as db:
        highest = await db.scalar(
            select(func.max(am.AssetEvent.id)).where(am.AssetEvent.tenant_id == tenant_id)
        )
        mark = int(highest or 0)
        existing = await db.get(am.AssetEventCursor, tenant_id)
        if existing is None:
            db.add(am.AssetEventCursor(tenant_id=tenant_id, cleared_before=mark))
        else:
            existing.cleared_before = mark
            existing.updated_at = func.now()
        await db.commit()
        return mark


def serialise(row: am.AssetEvent) -> dict[str, Any]:
    return {
        "id": row.id,
        "check_id": str(row.check_id) if row.check_id else None,
        "level": row.level,
        "kind": row.kind,
        "message": row.message,
        "payload": row.payload,
        "at": row.created_at.isoformat() if row.created_at else None,
    }
