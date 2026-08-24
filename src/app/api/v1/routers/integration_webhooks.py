"""Narrow unauthenticated provider ingress with connector HMAC and replay checks."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.schemas.integrations import GithubWebhookReceiptRead
from app.core.services.integration_service import IntegrationService
from app.infrastructure.database.database import get_db
from app.infrastructure.database.repositories.integration_repo import IntegrationRepository
from app.infrastructure.database.tenant_context import (
    apply_session_context,
    principal_scope,
)
from app.shared.lib.integration_contract import IntegrationContractError


router = APIRouter(prefix="/integrations/webhooks", tags=["Integration webhooks"])
MAX_WEBHOOK_BYTES = 1024 * 1024


async def _bounded_body(request: Request) -> bytes:
    content_length = request.headers.get("content-length")
    if content_length and (not content_length.isdigit() or int(content_length) > MAX_WEBHOOK_BYTES):
        raise HTTPException(status_code=413, detail="Webhook payload too large.")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_WEBHOOK_BYTES:
            raise HTTPException(status_code=413, detail="Webhook payload too large.")
    return bytes(body)


@router.post(
    "/github/{tenant_id}/{principal_id}",
    response_model=GithubWebhookReceiptRead,
    status_code=status.HTTP_202_ACCEPTED,
)
async def receive_github_webhook(
    tenant_id: uuid.UUID,
    principal_id: uuid.UUID,
    request: Request,
    signature: str = Header(..., alias="X-Hub-Signature-256", max_length=80),
    delivery_id: str = Header(..., alias="X-GitHub-Delivery", max_length=128),
    event_type: str = Header(..., alias="X-GitHub-Event", max_length=96),
    db: AsyncSession = Depends(get_db),
) -> GithubWebhookReceiptRead:
    body = await _bounded_body(request)
    with principal_scope(
        tenant_id=tenant_id,
        principal_kind="service_principal",
        principal_id=str(principal_id),
    ):
        await apply_session_context(db)
        try:
            receipt, created, _ = await IntegrationService(
                IntegrationRepository(db)
            ).accept_github_webhook(
                tenant_id=tenant_id,
                principal_id=principal_id,
                delivery_id=delivery_id,
                event_type=event_type,
                signature=signature,
                body=body,
                received_at=datetime.now(timezone.utc),
            )
            await db.commit()
        except LookupError:
            await db.rollback()
            raise HTTPException(status_code=404, detail="Webhook endpoint not found.") from None
        except PermissionError:
            await db.rollback()
            raise HTTPException(status_code=403, detail="Webhook feature is disabled.") from None
        except (IntegrationContractError, ValueError):
            await db.rollback()
            raise HTTPException(status_code=401, detail="Webhook authentication failed.") from None
    return GithubWebhookReceiptRead(
        receipt_id=receipt.id,
        duplicate=not created,
        event_type=receipt.event_type,
    )
