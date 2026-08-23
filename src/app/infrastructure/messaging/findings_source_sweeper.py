"""Defensive backfill of `findings.source IS NULL` rows.

Feature-7 follow-up B3: the initial backfill admin script (run via
`scripts/backfill_findings_source.py`) closes historic NULLs. From
that point forward, the LLM-emitting agent stamps `source="agent"`
at write time (B1). This sweeper is a defense-in-depth catch for any
late-arriving NULL row — e.g. a future code path that forgets to set
the field, or a window where a long-running scan inserted a finding
between the backfill snapshot and the B1 fix being deployed.

Runs hourly on the API container. No-op when there are zero NULL
rows. Each pass updates a bounded batch and commits, so the sweeper
never holds long transactions.
"""

from __future__ import annotations

import asyncio
import logging
from sqlalchemy import text

from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database.tenant_context import system_principal_task

logger = logging.getLogger(__name__)

# 1 hour. Per-pass cost is one COUNT + one bounded UPDATE; the cycle
# is set so a freshly-NULL row is corrected within an hour without
# burning CPU on the common no-op path.
SWEEPER_INTERVAL_SECONDS = 3600

# Bound the per-pass UPDATE so the sweeper never holds a long
# transaction. Repeats next cycle if more rows remain.
BATCH_SIZE = 5000


@system_principal_task("findings-source-sweeper")
async def _sweep_once() -> int:
    """Single sweep pass. Returns the number of rows backfilled."""
    async with AsyncSessionLocal() as db:
        # Cheap precheck — if everything is already tagged, skip the
        # UPDATE entirely so the common case costs only one SELECT.
        count_stmt = text("SELECT count(*) FROM findings WHERE source IS NULL")
        null_count = (await db.execute(count_stmt)).scalar_one()
        if null_count == 0:
            return 0

        # Bounded UPDATE: only flip BATCH_SIZE rows per pass so a
        # large legacy backlog doesn't lock the table for minutes.
        # `WHERE id IN (subquery)` works on Postgres because the
        # subquery is evaluated once.
        update_stmt = text(
            """
            UPDATE findings
               SET source = 'agent'
             WHERE id IN (
                 SELECT id FROM findings
                  WHERE source IS NULL
                  LIMIT :batch_size
             )
            """
        )
        result = await db.execute(update_stmt, {"batch_size": BATCH_SIZE})
        await db.commit()
        updated = result.rowcount or 0
        logger.info(
            "findings_source_sweeper: backfilled %d row(s) (remaining=%d)",
            updated,
            max(0, null_count - updated),
        )
        return updated


async def run_findings_source_sweeper(stop_event: asyncio.Event) -> None:
    """Background task entry point. Runs until ``stop_event`` is set."""
    logger.info(
        "findings_source_sweeper: starting (interval=%ds, batch=%d)",
        SWEEPER_INTERVAL_SECONDS,
        BATCH_SIZE,
    )
    while not stop_event.is_set():
        try:
            await _sweep_once()
        except Exception as e:
            logger.error(
                "findings_source_sweeper: sweep pass failed: %s", e, exc_info=True
            )
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=SWEEPER_INTERVAL_SECONDS)
        except asyncio.TimeoutError:
            pass
    logger.info("findings_source_sweeper: stopped")
