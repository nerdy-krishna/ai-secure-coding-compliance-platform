"""Web Push subscription endpoints (#90 / PRD #83).

- ``GET  /push/vapid-public-key`` — the browser `applicationServerKey`
  (null when Web Push is disabled).
- ``POST /push/subscriptions``    — register a browser push subscription.
- ``DELETE /push/subscriptions``  — unregister one.

Scan-completion pushes themselves are sent worker-side by
`infrastructure/messaging/web_push.notify_scan_completed`.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.auth.core import current_active_user
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db
from app.infrastructure.database.repositories.push_subscription_repo import (
    PushSubscriptionRepository,
)
from app.infrastructure.messaging.web_push import vapid_public_key

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/push", tags=["Push"])


class _SubscriptionKeys(BaseModel):
    p256dh: str = Field(min_length=1, max_length=512)
    auth: str = Field(min_length=1, max_length=512)


class PushSubscriptionIn(BaseModel):
    """The browser `PushSubscription` JSON (endpoint + RFC-8291 keys)."""

    endpoint: str = Field(min_length=1, max_length=2048)
    keys: _SubscriptionKeys


class PushUnsubscribeIn(BaseModel):
    endpoint: str = Field(min_length=1, max_length=2048)


@router.get("/vapid-public-key")
async def get_vapid_public_key() -> dict:
    """The VAPID public key for the browser to subscribe with.

    `public_key` is null when Web Push is not configured — the frontend
    then skips service-worker registration and relies on the in-app +
    tab-open desktop notifications.
    """
    return {"public_key": vapid_public_key()}


@router.post("/subscriptions")
async def register_subscription(
    payload: PushSubscriptionIn,
    user: db_models.User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Register the caller's browser push subscription."""
    await PushSubscriptionRepository(db).upsert(
        user_id=user.id,
        endpoint=payload.endpoint,
        p256dh=payload.keys.p256dh,
        auth=payload.keys.auth,
    )
    return {"status": "registered"}


@router.delete("/subscriptions")
async def unregister_subscription(
    payload: PushUnsubscribeIn,
    user: db_models.User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Remove a browser push subscription."""
    await PushSubscriptionRepository(db).delete_by_endpoint(payload.endpoint)
    return {"status": "unregistered"}
