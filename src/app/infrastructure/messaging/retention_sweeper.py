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

# Correlated active-hold guards. These are static SQL fragments paired with
# the hardcoded allowlist above; no identifier or expression is user supplied.
_HOLD_GUARDS = {
    "llm_interactions": """
      NOT EXISTS (
        SELECT 1 FROM governance_legal_holds h
        LEFT JOIN scans s ON s.id = t.scan_id
        LEFT JOIN chat_messages cm ON cm.id = t.chat_message_id
        LEFT JOIN chat_sessions cs ON cs.id = cm.session_id
        WHERE h.released_at IS NULL
          AND h.tenant_id = COALESCE(s.tenant_id, cs.tenant_id)
          AND (
            (h.scope_type = 'tenant' AND h.scope_id = h.tenant_id::text) OR
            (s.id IS NOT NULL AND h.scope_type = 'project' AND h.scope_id = s.project_id::text) OR
            (s.id IS NOT NULL AND h.scope_type = 'scan' AND h.scope_id = s.id::text) OR
            (s.id IS NOT NULL AND h.scope_type = 'attempt' AND EXISTS (
              SELECT 1 FROM scan_attempts held_attempt
              WHERE held_attempt.id::text = h.scope_id AND held_attempt.scan_id = s.id
            )) OR
            (s.id IS NOT NULL AND h.scope_type = 'evidence' AND EXISTS (
              SELECT 1 FROM evidence_objects held_evidence
              WHERE held_evidence.id::text = h.scope_id AND held_evidence.scan_id = s.id
            ))
          )
      )
    """,
    "chat_messages": """
      NOT EXISTS (
        SELECT 1 FROM chat_sessions cs
        JOIN governance_legal_holds h ON h.tenant_id = cs.tenant_id
        WHERE cs.id = t.session_id AND h.released_at IS NULL
          AND h.scope_type = 'tenant' AND h.scope_id = h.tenant_id::text
      )
    """,
    "rag_preprocessing_jobs": """
      NOT EXISTS (
        SELECT 1 FROM "user" u
        JOIN governance_legal_holds h ON h.tenant_id = u.tenant_id
        WHERE u.id = t.user_id AND h.released_at IS NULL
          AND h.scope_type = 'tenant' AND h.scope_id = h.tenant_id::text
      )
    """,
}
_TENANT_JOIN_AND_KEY = {
    "llm_interactions": (
        "LEFT JOIN scans tenant_scan ON tenant_scan.id = t.scan_id "
        "LEFT JOIN chat_messages tenant_message ON tenant_message.id = t.chat_message_id "
        "LEFT JOIN chat_sessions tenant_chat ON tenant_chat.id = tenant_message.session_id",
        "COALESCE(tenant_scan.tenant_id::text, tenant_chat.tenant_id::text, 'global')",
    ),
    "chat_messages": (
        "JOIN chat_sessions tenant_chat ON tenant_chat.id = t.session_id",
        "tenant_chat.tenant_id::text",
    ),
    "rag_preprocessing_jobs": (
        'JOIN "user" tenant_user ON tenant_user.id = t.user_id',
        "tenant_user.tenant_id::text",
    ),
}


def _is_enabled() -> bool:
    raw = os.environ.get("RETENTION_SWEEPER_ENABLED", "true").strip().lower()
    return raw not in {"0", "false", "no", "off"}


async def _delete_expired_in(table: str) -> int:
    """Delete expired rows only after acquiring the tenant deletion barrier.

    Tenant discovery deliberately does not evaluate expiry or holds. Each
    bounded DELETE is a later statement, after the advisory lock has been
    acquired, so PostgreSQL READ COMMITTED takes a fresh snapshot that sees a
    legal hold which committed while this worker waited for the barrier.
    """
    deleted = 0
    async with AsyncSessionLocal() as discovery_db:
        tenant_keys = list(
            (
                await discovery_db.scalars(
                    text("SELECT id::text FROM tenants UNION ALL SELECT 'global'")
                )
            ).all()
        )
        await discovery_db.rollback()

    for selected_tenant_key in tenant_keys:
        while True:
            async with AsyncSessionLocal() as db:
                await db.execute(
                    text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                    {"key": f"governance-delete-barrier:{selected_tenant_key}"},
                )
                # Postgres-only: ctid limit pattern keeps the delete bounded.
                # The table and SQL fragments come only from module allowlists.
                # Eligibility and legal-hold evaluation occur in this distinct
                # statement after the barrier statement above.
                tenant_join, tenant_key = _TENANT_JOIN_AND_KEY[table]
                stmt = text(
                    f"WITH candidates AS MATERIALIZED ("  # nosec B608 -- hardcoded allowlists only
                    f"  SELECT t.ctid FROM {table} t "
                    f"  {tenant_join} "
                    f"  WHERE {tenant_key} = :tenant_key "
                    f"  AND t.expires_at IS NOT NULL AND t.expires_at < NOW() "
                    f"  AND {_HOLD_GUARDS[table]} "
                    f"  ORDER BY t.expires_at "
                    f"  LIMIT :batch"
                    f") DELETE FROM {table} target USING candidates "
                    f"WHERE target.ctid = candidates.ctid"
                )
                result = await db.execute(
                    stmt,
                    {"batch": BATCH_SIZE, "tenant_key": selected_tenant_key},
                )
                await db.commit()
                batch_count = result.rowcount or 0
                deleted += batch_count
                if batch_count < BATCH_SIZE:
                    break
            # yield between batches so other DB work isn't starved
            await asyncio.sleep(0)
    return deleted


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
