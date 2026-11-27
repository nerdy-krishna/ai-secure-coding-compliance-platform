"""Runtime settings an admin can change from the UI, without editing `.env`.

Everything that gates scan *speed* used to live in the environment, which meant an
operator had to ssh in, edit `.env` and restart the worker to change a number. This
module gives those settings a `system_config` row each, resolves them once per
process into a small in-memory cache, and republishes the live ones:

* per-stage concurrency (`system.concurrency.*`) — read by the node that uses them;
* provider rate limits (`system.ratelimit.<provider>.rpm|tpm`) — pushed into the
  in-process limiter registry on every refresh, so raising them takes effect while a
  scan is running (the worker refreshes every `REFRESH_SECONDS`);
* worker capacity (`system.worker.*`) — applied when the worker starts, because
  semaphores and prefetch cannot be resized under a live consumer.

Resolution order is always: `system_config` row → environment/`.env` → the field's
declared default. Values are clamped to the field's own bounds, so a typo in the
admin UI cannot push a limit to zero or past what the code can handle.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Dict, Iterable

from sqlalchemy import select

from app.config.config import settings

logger = logging.getLogger(__name__)

SYSTEM_CONFIG_PREFIX = "system."

# How often a process re-reads the rows. Thirty seconds is fast enough that an
# operator sees the effect during a scan, slow enough to be a rounding error.
REFRESH_SECONDS = 30


@dataclass(frozen=True)
class SettingSpec:
    """One admin-managed number."""

    name: str  # attribute on `settings`
    key: str  # `system_config` key
    kind: str = "int"  # "int" only for now; the reader validates the shape
    live: bool = False  # True when a refresh applies it to a running process


def _spec(name: str, key: str, *, live: bool = False) -> SettingSpec:
    return SettingSpec(name=name, key=key, live=live)


# Provider rate limits: local guards, not provider requirements. Raising them tells
# the platform to stop throttling itself and let the provider answer (the HTTP client
# still backs off on 429).
_PROVIDER_FIELDS: Dict[str, tuple[str, str]] = {
    "openai": ("OPENAI_REQUESTS_PER_MINUTE", "OPENAI_TOKENS_PER_MINUTE"),
    "google": ("GOOGLE_REQUESTS_PER_MINUTE", "GOOGLE_TOKENS_PER_MINUTE"),
    "anthropic": ("ANTHROPIC_REQUESTS_PER_MINUTE", "ANTHROPIC_TOKENS_PER_MINUTE"),
    "deepseek": ("DEEPSEEK_REQUESTS_PER_MINUTE", "DEEPSEEK_TOKENS_PER_MINUTE"),
    "xai": ("XAI_REQUESTS_PER_MINUTE", "XAI_TOKENS_PER_MINUTE"),
    "custom_openai": (
        "CUSTOM_OPENAI_REQUESTS_PER_MINUTE",
        "CUSTOM_OPENAI_TOKENS_PER_MINUTE",
    ),
}

_PROVIDER_LIMIT_SPECS: tuple[SettingSpec, ...] = tuple(
    spec
    for provider, (rpm_name, tpm_name) in _PROVIDER_FIELDS.items()
    for spec in (
        _spec(rpm_name, f"system.ratelimit.{provider}.rpm", live=True),
        _spec(tpm_name, f"system.ratelimit.{provider}.tpm", live=True),
    )
)

SPECS: tuple[SettingSpec, ...] = (
    # per-stage concurrency (read by the node on entry)
    _spec("CONCURRENT_LLM_LIMIT", "system.concurrency.llm_limit"),
    _spec("CONCURRENT_PROFILER_LIMIT", "system.concurrency.profiler_limit"),
    _spec("CONCURRENT_SCANNER_LIMIT", "system.concurrency.scanner_limit"),
    _spec("CONCURRENT_CONSOLIDATION_LIMIT", "system.concurrency.consolidation_limit"),
    _spec("CONCURRENT_VALIDATION_LIMIT", "system.concurrency.validation_limit"),
    # worker capacity (applied at worker start)
    _spec("WORKER_ANALYSIS_SLOTS", "system.worker.analysis_slots"),
    _spec("WORKER_SUBMISSION_SLOTS", "system.worker.submission_slots"),
    _spec("WORKER_PREFETCH_COUNT", "system.worker.prefetch_count"),
    # provider rate limits (applied live)
    *_PROVIDER_LIMIT_SPECS,
)

_BY_NAME: Dict[str, SettingSpec] = {spec.name: spec for spec in SPECS}
_BY_KEY: Dict[str, SettingSpec] = {spec.key: spec for spec in SPECS}

# Resolved values, keyed by settings attribute. Empty until the first refresh.
_cache: Dict[str, int] = {}
_cache_lock = asyncio.Lock()


def _bounds(spec: SettingSpec) -> tuple[int, int]:
    """The field's declared range, used to clamp an admin-supplied value."""
    field = type(settings).model_fields[spec.name]
    lower = next((m.ge for m in field.metadata if hasattr(m, "ge")), 1)
    upper = next((m.le for m in field.metadata if hasattr(m, "le")), 10_000_000)
    return int(lower or 1), int(upper if upper is not None else 10_000_000)


def _extract_int(raw: Any) -> int | None:
    """A `system_config` JSONB value is `{"value": n}` (or a bare number)."""
    if isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        return int(raw)
    if isinstance(raw, dict):
        for key in ("value", "limit", "enabled", "count", "slots"):
            candidate = raw.get(key)
            if isinstance(candidate, (int, float)) and not isinstance(candidate, bool):
                return int(candidate)
    return None


def effective(name: str) -> int:
    """The current value for `name`: refreshed override, else the environment."""
    if name in _cache:
        return _cache[name]
    spec = _BY_NAME.get(name)
    if spec is None:
        return int(getattr(settings, name))
    lower, upper = _bounds(spec)
    return max(lower, min(int(getattr(settings, name)), upper))


def resolved_snapshot() -> Dict[str, int]:
    """Every managed setting as this process currently sees it (for logs/diagnostics)."""
    return {spec.name: effective(spec.name) for spec in SPECS}


def _apply_live(snapshot: Dict[str, int]) -> None:
    """Push the live settings into the running rate-limit registry."""
    from app.infrastructure.llm_client_rate_limiter import set_provider_limits

    for provider, (rpm_name, tpm_name) in _PROVIDER_FIELDS.items():
        rpm = snapshot.get(rpm_name, effective(rpm_name))
        tpm = snapshot.get(tpm_name, effective(tpm_name))
        try:
            changed = set_provider_limits(provider, rpm=int(rpm), tpm=int(tpm))
        except Exception:  # noqa: BLE001 - a limiter refresh must never break work
            logger.debug("runtime_settings: limiter refresh failed", exc_info=True)
            continue
        if changed:
            logger.info(
                "runtime_settings.applied provider=%s rpm=%s tpm=%s",
                provider,
                rpm,
                tpm,
            )


async def seed_missing_maximums(db=None) -> list[str]:
    """Fill in any managed key that has no row yet, at its maximum.

    An operator should not have to discover which numbers gate scan speed and type
    them in one by one: the limits this platform applies to itself are seeded at the
    top of their declared range, and the admin UI exists to lower them for a provider
    tier that cannot take it. Concurrency and worker capacity seed at the field
    maximum; provider rate limits seed at the configured (environment or default)
    value, because "no local throttle" is a provider-quota decision, not ours.

    Idempotent: an existing row is never touched.
    """
    from app.infrastructure.database import AsyncSessionLocal

    async with _cache_lock:
        own_session = db is None
        if own_session:
            db = AsyncSessionLocal()
        seeded: list[str] = []
        try:
            from app.infrastructure.database import models as db_models

            existing = set(
                (
                    await db.execute(
                        select(db_models.SystemConfiguration.key).where(
                            db_models.SystemConfiguration.key.in_(tuple(_BY_KEY))
                        )
                    )
                )
                .scalars()
                .all()
            )
            for spec in SPECS:
                if spec.key in existing:
                    continue
                lower, upper = _bounds(spec)
                from_env = int(getattr(settings, spec.name))
                value = from_env if spec.key.startswith("system.ratelimit.") else upper
                value = max(lower, min(value, upper))
                db.add(
                    db_models.SystemConfiguration(key=spec.key, value={"value": value})
                )
                seeded.append(f"{spec.key}={value}")
            if seeded:
                await db.commit()
                logger.warning(
                    "runtime_settings.seeded %d limit(s) at their maximum: %s",
                    len(seeded),
                    ", ".join(seeded),
                )
        except Exception:  # noqa: BLE001 - seeding must never block boot
            logger.debug("runtime_settings: seeding failed", exc_info=True)
            if own_session and db is not None:
                await db.rollback()
        finally:
            if own_session and db is not None:
                await db.close()
        return seeded


async def refresh(db=None) -> Dict[str, int]:
    """Re-read the rows and publish the live ones. Returns the new snapshot."""
    from app.infrastructure.database import AsyncSessionLocal

    async with _cache_lock:
        own_session = db is None
        if own_session:
            db = AsyncSessionLocal()
        try:
            from app.infrastructure.database import models as db_models

            result = await db.execute(
                select(
                    db_models.SystemConfiguration.key,
                    db_models.SystemConfiguration.value,
                ).where(db_models.SystemConfiguration.key.in_(tuple(_BY_KEY)))
            )
            rows = result.all()
        except Exception:  # noqa: BLE001 - fall back to the environment silently
            logger.debug("runtime_settings: read failed", exc_info=True)
            rows = []
        finally:
            if own_session:
                await db.close()

        snapshot: Dict[str, int] = {}
        for key, raw in rows:
            spec = _BY_KEY.get(key)
            if spec is None:
                continue
            value = _extract_int(raw)
            if value is None:
                continue
            lower, upper = _bounds(spec)
            snapshot[spec.name] = max(lower, min(value, upper))

        _cache.clear()
        _cache.update(snapshot)
        resolved = resolved_snapshot()
        _apply_live(resolved)
        return resolved


async def run_refresh_loop(stop_event: asyncio.Event | None = None) -> None:
    """Keep the cache fresh in a long-lived process (app and worker)."""
    while True:
        try:
            if stop_event is not None and stop_event.is_set():
                return
            await refresh()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.debug(
                "runtime_settings: refresh loop iteration failed", exc_info=True
            )
        if stop_event is None:
            await asyncio.sleep(REFRESH_SECONDS)
            continue
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=REFRESH_SECONDS)
            return
        except asyncio.TimeoutError:
            continue


def managed_keys() -> Iterable[str]:
    """The `system_config` keys this module owns (for docs/tests)."""
    return tuple(_BY_KEY)
