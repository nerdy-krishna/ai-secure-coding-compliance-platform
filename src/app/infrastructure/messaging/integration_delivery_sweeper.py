"""Transactional enterprise-integration outbox delivery with retry and DLQ."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

import httpx

from app.infrastructure.database.database import AsyncSessionLocal
from app.infrastructure.database.repositories.integration_repo import IntegrationRepository
from app.infrastructure.database.tenant_context import system_principal_task
from app.infrastructure.integrations.clients import (
    DeliveryResult,
    configured_pinned_http_client,
)
from app.infrastructure.integrations.delivery import IntegrationDeliveryDispatcher
from app.shared.lib.integration_contract import retry_delay_seconds


logger = logging.getLogger(__name__)


async def deliver_integration_batch(*, limit: int = 20) -> int:
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        repo = IntegrationRepository(db)
        await repo.enqueue_due_ticket_lifecycle_events(now=now)
        rows = await repo.lease_due(now=now, limit=limit)
        await db.commit()
        if not rows:
            return 0
        async with configured_pinned_http_client() as http:
            dispatcher = IntegrationDeliveryDispatcher(repo=repo, http=http)
            for row in rows:
                try:
                    result = await dispatcher.deliver(row)
                except (httpx.HTTPError, ValueError, KeyError) as exc:
                    result = DeliveryResult(
                        delivered=False,
                        retryable=True,
                        http_status=None,
                        error_code=f"delivery_{type(exc).__name__.lower()}",
                    )
                completed_at = datetime.now(timezone.utc)
                if result.delivered:
                    await repo.complete_delivery(row=row, now=completed_at)
                    outcome = "delivered"
                else:
                    await repo.fail_delivery(
                        row=row,
                        now=completed_at,
                        error_code=result.error_code or "delivery_failed",
                        retryable=result.retryable,
                        retry_after_seconds=retry_delay_seconds(row.attempts),
                    )
                    outcome = "retry" if row.state == "retry" else "dead_letter"
                await repo.append_delivery_audit(
                    row=row,
                    outcome=outcome,
                    http_status=result.http_status,
                    response_excerpt=result.response_excerpt,
                    error_code=result.error_code,
                )
                await db.commit()
        return len(rows)


@system_principal_task("integration-delivery-sweeper")
async def run_integration_delivery_sweeper(stop_event: asyncio.Event) -> None:
    while not stop_event.is_set():
        try:
            await deliver_integration_batch()
        except Exception:  # noqa: BLE001 - background loop must remain live
            logger.exception("integration_delivery.batch_failed")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            continue
