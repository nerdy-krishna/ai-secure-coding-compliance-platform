"""Bounded scheduler for optional read-only provider reconciliation connectors."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from app.core.services.provider_reconciliation_service import ProviderReconciliationService
from app.infrastructure.database.database import AsyncSessionLocal
from app.infrastructure.database.repositories.provider_reconciliation_repo import (
    ProviderReconciliationRepository,
)
from app.infrastructure.database.tenant_context import system_principal_task


logger = logging.getLogger(__name__)
_INTERVAL_SECONDS = 60


@system_principal_task("provider-reconciliation-sweeper")
async def run_due_reconciliations() -> int:
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    async with AsyncSessionLocal() as db:
        due = await ProviderReconciliationRepository(db).list_due_connectors(now=now)
        targets = [(row.id, row.tenant_id, row.lookback_minutes) for row in due]
    completed = 0
    for connector_id, tenant_id, lookback_minutes in targets:
        async with AsyncSessionLocal() as db:
            try:
                await ProviderReconciliationService(
                    ProviderReconciliationRepository(db)
                ).run(
                    connector_id=connector_id,
                    tenant_id=tenant_id,
                    window_start=now - timedelta(minutes=lookback_minutes),
                    window_end=now,
                    trigger_kind="scheduled",
                    created_by_user_id=None,
                )
                completed += 1
            except Exception:
                await db.rollback()
                logger.error(
                    "provider_reconciliation_sweeper.connector_failed",
                    extra={"connector_id": str(connector_id)},
                    exc_info=True,
                )
    return completed


async def run_provider_reconciliation_sweeper(stop_event: asyncio.Event) -> None:
    logger.info("provider_reconciliation_sweeper.started")
    while not stop_event.is_set():
        try:
            await run_due_reconciliations()
        except Exception:
            logger.error("provider_reconciliation_sweeper.tick_failed", exc_info=True)
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=_INTERVAL_SECONDS)
        except asyncio.TimeoutError:
            continue
    logger.info("provider_reconciliation_sweeper.stopped")


__all__ = ["run_due_reconciliations", "run_provider_reconciliation_sweeper"]
