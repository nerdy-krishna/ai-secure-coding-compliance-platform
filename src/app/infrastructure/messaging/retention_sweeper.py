"""Background task that purges rows whose `expires_at` is in the past.

V14.2.7 — retention sweeper. Started from the FastAPI lifespan, mirrors
the outbox_sweeper shape. Runs hourly until the app shuts down. Each
tick deletes expired rows from `llm_interactions`, `chat_messages`,
and `rag_preprocessing_jobs` in batches.

FK ordering matters: `LLMInteraction.chat_message_id` is an FK child
of `ChatMessage`, so we must delete `llm_interactions` before
`chat_messages`. The full per-tick order is:

    llm_interactions  ->  chat_messages  ->  rag_preprocessing_jobs

Each table runs a `DELETE ... WHERE expires_at < NOW() AND
expires_at IS NOT NULL` capped at `BATCH_SIZE` rows per statement,
committed per batch, until rowcount == 0. Logs the per-table delete
count at INFO.

Operators with valuable history should bump the
`system.retention.{kind}_days` config keys BEFORE the migration runs;
otherwise the first sweeper tick after deploy may delete the bulk of
historical chat / LLM / rag rows.

Set env var `RETENTION_SWEEPER_ENABLED=false` to disable the
sweeper at startup. Defaults to enabled.
"""

import asyncio
import logging
import os

from sqlalchemy import text

from app.infrastructure.database.database import AsyncSessionLocal
from app.infrastructure.database.tenant_context import system_principal_task

logger = logging.getLogger(__name__)

# Hourly cadence — retention is a slow process; no need to thrash the DB.
SWEEP_INTERVAL_SECONDS = 3600
# Per-statement delete batch — keeps locks short and lets the sweeper
# yield between batches if the backlog is large.
BATCH_SIZE = 1000

# FK-safe order: llm_interactions has chat_message_id pointing at
# chat_messages, so children before parents.
_TABLE_ORDER = (
    "llm_interactions",
    "chat_messages",
    "rag_preprocessing_jobs",
)


def _is_enabled() -> bool:
    raw = os.environ.get("RETENTION_SWEEPER_ENABLED", "true").strip().lower()
    return raw not in {"0", "false", "no", "off"}


async def _delete_expired_in(table: str) -> int:
    """Delete up to BATCH_SIZE expired rows from `table`. Returns the
    number deleted in a single statement; loops at the call site."""
    deleted = 0
    while True:
        async with AsyncSessionLocal() as db:
            # Postgres-only: ctid limit pattern keeps the delete bounded
            # and avoids holding row locks on rows we wouldn't have
            # touched.
            # `table` is interpolated into the SQL because asyncpg /
            # SQLAlchemy can't parameterise identifiers; the value
            # comes exclusively from `_TABLE_ORDER` (a module-level
            # tuple of hardcoded literals — not user input). The
            # `expires_at` filter is parameterised; only the bound
            # batch size flows in via the parameter binder.
            stmt = text(
                f"DELETE FROM {table} "  # nosec B608 — table is from hardcoded allowlist (`_TABLE_ORDER`), not user input
                f"WHERE ctid IN ("
                f"  SELECT ctid FROM {table} "
                f"  WHERE expires_at IS NOT NULL AND expires_at < NOW() "
                f"  ORDER BY expires_at "
                f"  LIMIT :batch"
                f")"
            )
            result = await db.execute(stmt, {"batch": BATCH_SIZE})
            await db.commit()
            batch_count = result.rowcount or 0
            deleted += batch_count
            if batch_count < BATCH_SIZE:
                return deleted
        # yield between batches so other DB work isn't starved
        await asyncio.sleep(0)


@system_principal_task("retention-sweeper")
async def _sweep_once() -> None:
    """Run one full pass across all retention tables."""
    for table in _TABLE_ORDER:
        try:
            count = await _delete_expired_in(table)
        except Exception:
            logger.error(
                "retention_sweeper.delete_failed",
                extra={"table": table},
                exc_info=True,
            )
            continue
        if count:
            logger.info(
                "retention_sweeper.purged",
                extra={"table": table, "deleted": count},
            )


async def run_retention_sweeper(stop_event: asyncio.Event) -> None:
    """Main loop. Exits cleanly when stop_event is set."""
    if not _is_enabled():
        logger.info("retention_sweeper: disabled via RETENTION_SWEEPER_ENABLED=false")
        return
    logger.info(
        "retention_sweeper.started",
        extra={"interval": SWEEP_INTERVAL_SECONDS, "batch_size": BATCH_SIZE},
    )
    while not stop_event.is_set():
        try:
            await _sweep_once()
        except Exception:
            logger.error("retention_sweeper.tick_failed", exc_info=True)

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=SWEEP_INTERVAL_SECONDS)
        except asyncio.TimeoutError:
            continue

    logger.info("retention_sweeper.stopped")
