"""Dynamic concurrency limits — read from system_config, fall back to settings.

Workflow nodes call :func:`get_concurrency_limit` at scan start so admin
changes to the ``system.concurrency.*`` rows take effect on the next scan
without a worker restart.
"""

from __future__ import annotations

import logging
from typing import Dict

from sqlalchemy import select

from app.config.config import settings
from app.infrastructure.database import models as db_models

logger = logging.getLogger(__name__)

# system_config key prefix for concurrency overrides
_PREFIX = "system.concurrency."

# Mapping of env var field name → system_config suffix
_KEYS: Dict[str, str] = {
    "CONCURRENT_LLM_LIMIT": "llm_limit",
    "CONCURRENT_PROFILER_LIMIT": "profiler_limit",
    "CONCURRENT_SCANNER_LIMIT": "scanner_limit",
    "CONCURRENT_CONSOLIDATION_LIMIT": "consolidation_limit",
    "CONCURRENT_VALIDATION_LIMIT": "validation_limit",
}


def db_pool_capacity() -> int:
    """Connections this process may hold open at once."""
    return int(getattr(settings, "DB_POOL_SIZE", 10)) + int(
        getattr(settings, "DB_MAX_OVERFLOW", 20)
    )


# A stage needs a connection for the call itself (usage accounting reads/writes, task
# ledger, events), so its concurrency cannot exceed the pool: beyond that, every extra
# task merely waits for a connection. Leave headroom for the workflow's own writes.
_DB_POOL_RESERVE = 4


def db_bound_concurrency(configured: int) -> tuple[int, bool]:
    """Cap a stage's concurrency at what the connection pool can actually serve.

    Returns ``(effective, clamped)``. A 500-way profiling fan-out against a 5+10 pool is
    what produced hundreds of `QueuePool limit ... connection timed out` warnings and
    failed the scan; the fan-out is bounded by capacity rather than by hope.
    """
    capacity = max(1, db_pool_capacity() - _DB_POOL_RESERVE)
    effective = max(1, min(int(configured), capacity))
    return effective, effective < int(configured)


async def get_concurrency_limit(
    db,
    setting_name: str,
) -> int:
    """Read a concurrency limit from ``system_config``, falling back to settings.

    *setting_name* is one of ``CONCURRENT_LLM_LIMIT`` etc.  Returns the
    configured integer, clamped to the range allowed by the settings field.
    """
    key = _KEYS.get(setting_name)
    if not key:
        logger.warning("Unknown concurrency setting: %s", setting_name)
        return getattr(settings, setting_name)

    system_config_key = f"{_PREFIX}{key}"
    try:
        result = await db.execute(
            select(db_models.SystemConfiguration.value).where(
                db_models.SystemConfiguration.key == system_config_key
            )
        )
        row = result.scalar_one_or_none()
        if row is not None:
            # value is a JSONB dict: {"enabled": 50} or {"value": 50}
            val = _extract_int(row)
            if val is not None:
                # Clamp to the settings field range. The bounds live in
                # `field.metadata` as separate Ge/Le constraint objects, in
                # declaration order - reading `metadata[0].le` assumed Le came first
                # and raised AttributeError for every field declared `ge=` before
                # `le=`, which is all of them. The broad `except` below then fell
                # back to the environment default, so the admin "Concurrency limits"
                # panel silently changed nothing.
                field = type(settings).model_fields[setting_name]
                lower = next((m.ge for m in field.metadata if hasattr(m, "ge")), None)
                upper = next((m.le for m in field.metadata if hasattr(m, "le")), None)
                lo = lower if lower is not None else 1
                hi = upper if upper is not None else 10_000
                return max(lo, min(val, hi))
    except Exception:
        logger.debug(
            "Failed to read concurrency setting %s from DB, using default",
            system_config_key,
            exc_info=True,
        )

    return getattr(settings, setting_name)


def _extract_int(raw) -> int | None:
    """Extract an int from a JSONB value that could be a dict or bare int."""
    if isinstance(raw, int):
        return raw
    if isinstance(raw, dict):
        for key in ("value", "limit", "enabled"):
            v = raw.get(key)
            if isinstance(v, (int, float)):
                return int(v)
    if isinstance(raw, float):
        return int(raw)
    return None
