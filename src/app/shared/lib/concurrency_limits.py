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
    "CONCURRENT_SCANNER_LIMIT": "scanner_limit",
    "CONCURRENT_CONSOLIDATION_LIMIT": "consolidation_limit",
    "CONCURRENT_VALIDATION_LIMIT": "validation_limit",
}


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
                # Clamp to the settings field range
                field = settings.model_fields[setting_name]
                lo = field.metadata[0].ge if field.metadata else 1
                hi = field.metadata[0].le if field.metadata else 500
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
