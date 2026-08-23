# src/app/infrastructure/messaging/semgrep_sync_sweeper.py
#
# Periodic sweeper that auto-syncs Semgrep rule sources whose sync_cron
# schedule is due. Mirrors the outbox_sweeper.py pattern exactly.

import asyncio
import logging
from datetime import datetime, timezone

from app.infrastructure.database.database import AsyncSessionLocal
from app.infrastructure.database.tenant_context import system_principal_task
from app.infrastructure.database.repositories.semgrep_rule_repo import (
    SemgrepRuleRepository,
)
from app.core.services.semgrep_ingestion.selector import _load_ingestion_settings

logger = logging.getLogger(__name__)

_DEFAULT_SWEEP_INTERVAL = 900  # 15 minutes


def _is_cron_due(cron_expr: str | None, last_synced_at: datetime | None) -> bool:
    """Return True if the cron schedule says a sync is due now."""
    if not cron_expr:
        return False
    try:
        from croniter import croniter

        now = datetime.now(tz=timezone.utc)
        base = last_synced_at or datetime(2000, 1, 1, tzinfo=timezone.utc)
        ci = croniter(cron_expr, base)
        next_run = ci.get_next(datetime)
        return next_run <= now
    except Exception as exc:
        logger.warning(
            "semgrep_sync_sweeper.cron_parse_error",
            extra={"expr": cron_expr, "error": str(exc)},
        )
        return False


@system_principal_task("semgrep-sync-sweeper")
async def _tick() -> None:
    """Check for due auto-sync sources and enqueue them."""
    from app.core.services.semgrep_ingestion.sync_service import run_sync

    async with AsyncSessionLocal() as db:
        settings = await _load_ingestion_settings(db)
        if not settings["global_enabled"]:
            return

        repo = SemgrepRuleRepository(db)
        sources = await repo.list_sources()

    due = [
        s
        for s in sources
        if s.enabled and s.auto_sync and _is_cron_due(s.sync_cron, s.last_synced_at)
    ]
    if not due:
        return

    logger.info("semgrep_sync_sweeper.due_sources", extra={"count": len(due)})
    for source in due:
        asyncio.create_task(
            run_sync(source.id, triggered_by="cron"),
            name=f"semgrep-sync-{source.slug}",
        )


async def run_semgrep_sync_sweeper(stop_event: asyncio.Event) -> None:
    """Main loop. Reads sweep_interval from DB each cycle so admin changes take effect."""
    logger.info("semgrep_sync_sweeper.started")
    while not stop_event.is_set():
        try:
            async with AsyncSessionLocal() as db:
                settings = await _load_ingestion_settings(db)
            interval = settings.get("sweep_interval_seconds", _DEFAULT_SWEEP_INTERVAL)
        except Exception:
            interval = _DEFAULT_SWEEP_INTERVAL

        try:
            await _tick()
        except Exception:
            logger.error("semgrep_sync_sweeper.tick_failed", exc_info=True)

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            continue

    logger.info("semgrep_sync_sweeper.stopped")
