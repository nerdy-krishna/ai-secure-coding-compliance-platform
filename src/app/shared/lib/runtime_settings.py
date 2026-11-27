"""Resolve, cache, and apply the settings an admin manages from the UI.

`settings_catalog` says *which* settings are admin-managed, what their bounds are and
when a change takes effect. This module does the mechanical part:

* resolve each key as `system_config` row -> `.env`/defaults, clamped to the catalog
  range, into a small in-process cache;
* republish the live ones on a refresh loop (provider rate limits, applied to the
  existing limiter objects in place);
* overlay the rest onto the `settings` singleton at process start
  (`apply_to_settings`), so every existing `settings.X` reader honours the database
  value without touching each call site - the catalog's `applies` field tells the
  operator that this lands on the next restart;
* seed a fresh install with every managed key at its maximum, so nothing is throttled
  out of the box and the admin UI shows real numbers instead of empty fields.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Dict

from sqlalchemy import select

from app.config.config import settings
from app.shared.lib.settings_catalog import BY_ENV, BY_KEY, DESCRIPTORS

logger = logging.getLogger(__name__)

# How often a process re-reads the rows. Thirty seconds is fast enough that an operator
# sees the effect during a scan, slow enough to be a rounding error.
REFRESH_SECONDS = 30


@dataclass(frozen=True)
class SettingSpec:
    name: str  # attribute on `settings`
    key: str  # `system_config` key
    kind: str = "int"  # int | bool | enum
    minimum: float | None = None
    maximum: float | None = None
    applies: str = "next-scan"

    @property
    def live(self) -> bool:
        return self.applies == "live"


SPECS: tuple[SettingSpec, ...] = tuple(
    SettingSpec(
        name=descriptor.env,
        key=descriptor.key,
        kind=descriptor.kind,
        minimum=descriptor.minimum,
        maximum=descriptor.maximum,
        applies=descriptor.applies,
    )
    for descriptor in DESCRIPTORS
    if descriptor.env is not None
)

_BY_NAME: Dict[str, SettingSpec] = {spec.name: spec for spec in SPECS}

# Resolved values: by env name (what most consumers ask for) and by system key.
_cache: Dict[str, Any] = {}
_cache_by_key: Dict[str, Any] = {}
_cache_lock = asyncio.Lock()


# ----------------------------------------------------------------------
# coercion / validation
# ----------------------------------------------------------------------
def _extract_raw(raw: Any) -> Any:
    """A `system_config` value is `{"value": n}` (other shapes exist for legacy keys)."""
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, (int, float, str)):
        return raw
    if isinstance(raw, dict):
        for key in ("value", "limit", "enabled", "count", "slots", "level"):
            if key in raw:
                return raw[key]
    return None


def _coerce(spec: SettingSpec, raw: Any) -> Any:
    """Turn a stored value into the type the consumer expects, or None when unusable."""
    value = _extract_raw(raw)
    if value is None:
        return None
    if spec.kind == "bool":
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"true", "1", "yes", "on"}:
                return True
            if lowered in {"false", "0", "no", "off"}:
                return False
        if isinstance(value, (int, float)):
            return bool(value)
        return None
    if spec.kind == "enum":
        return str(value) if isinstance(value, str) else None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    low = int(spec.minimum) if spec.minimum is not None else None
    high = int(spec.maximum) if spec.maximum is not None else None
    if low is not None:
        number = max(low, number)
    if high is not None:
        number = min(high, number)
    return number


def _declared_default(spec: SettingSpec) -> Any:
    value = getattr(settings, spec.name, None)
    return value


def validate_write(key: str, value: Any) -> Any:
    """Validate an admin-supplied value against the catalog.

    Raises `ValueError` with an operator-facing message; returns the normalised value.
    """
    descriptor = BY_KEY.get(key)
    if descriptor is None:
        return value
    if descriptor.kind == "int":
        try:
            number = int(_extract_raw(value))
        except (TypeError, ValueError):
            raise ValueError(f"{descriptor.label} must be a whole number.") from None
        if descriptor.minimum is not None and number < descriptor.minimum:
            raise ValueError(
                f"{descriptor.label} must be at least {int(descriptor.minimum)}."
            )
        if descriptor.maximum is not None and number > descriptor.maximum:
            raise ValueError(
                f"{descriptor.label} must be at most {int(descriptor.maximum)}."
            )
        return number
    if descriptor.kind == "bool":
        raw = _extract_raw(value)
        if isinstance(raw, bool):
            return raw
        if isinstance(raw, str):
            lowered = raw.strip().lower()
            if lowered in {"true", "1", "yes", "on"}:
                return True
            if lowered in {"false", "0", "no", "off"}:
                return False
        raise ValueError(f"{descriptor.label} must be true or false.")
    if descriptor.kind == "enum":
        text = str(_extract_raw(value)).strip()
        if descriptor.choices and text not in descriptor.choices:
            raise ValueError(
                f"{descriptor.label} must be one of: {', '.join(descriptor.choices)}."
            )
        return text
    return value


# ----------------------------------------------------------------------
# resolution
# ----------------------------------------------------------------------
def effective(name: str) -> Any:
    """The current value of a `settings` attribute, honouring the admin override."""
    if name in _cache:
        return _cache[name]
    return _declared_default(
        _BY_NAME.get(name) or SettingSpec(name=name, key="", kind="raw")
    )


def effective_key(key: str) -> Any:
    """The current value of a `system_config` key, honouring the admin override."""
    if key in _cache_by_key:
        return _cache_by_key[key]
    spec = next((s for s in SPECS if s.key == key), None)
    if spec is None:
        return None
    return _declared_default(spec)


def resolved_snapshot() -> Dict[str, Any]:
    """Every managed setting as this process currently sees it (for logs/diagnostics)."""
    return {spec.name: effective(spec.name) for spec in SPECS}


def _apply_live(snapshot: Dict[str, Any]) -> None:
    """Push the live settings into the running subsystems."""
    from app.infrastructure.llm_client_rate_limiter import set_provider_limits

    for spec in SPECS:
        if not spec.live:
            continue
        descriptor = BY_KEY.get(spec.key) or BY_ENV.get(spec.name)
        if descriptor is None or not spec.key.startswith("system.ratelimit."):
            continue
        provider = spec.key.split(".")[2]
        rpm_key = f"system.ratelimit.{provider}.rpm"
        tpm_key = f"system.ratelimit.{provider}.tpm"
        try:
            changed = set_provider_limits(
                provider,
                rpm=int(
                    _cache_by_key.get(rpm_key)
                    or effective(next(s.name for s in SPECS if s.key == rpm_key))
                ),
                tpm=int(
                    _cache_by_key.get(tpm_key)
                    or effective(next(s.name for s in SPECS if s.key == tpm_key))
                ),
            )
        except Exception:  # noqa: BLE001 - a limiter refresh must never break work
            logger.debug("runtime_settings: limiter refresh failed", exc_info=True)
            continue
        if changed:
            logger.info(
                "runtime_settings.applied provider=%s rpm=%s tpm=%s",
                provider,
                _cache_by_key.get(rpm_key),
                _cache_by_key.get(tpm_key),
            )


def apply_to_settings(snapshot: Dict[str, Any]) -> None:
    """Overlay the resolved values onto the `settings` singleton.

    Call this once, at process start, before the code that reads them runs. It is what
    makes an admin change effective for a setting whose consumer still says
    `settings.SOMETHING` - the catalog's `applies: app-restart` / `worker-restart` is the
    operator-facing promise that this lands on the next start rather than immediately.
    """
    applied = 0
    for spec in SPECS:
        value = snapshot.get(spec.name)
        if value is None:
            continue
        try:
            # `Settings` is a frozen pydantic model, so plain assignment raises
            # `frozen_instance`. The overlay is the one place that must write into it:
            # it runs once, before the services read these values, and bypassing the
            # model's `__setattr__` is what makes a restart-scoped key effective for
            # consumers that still say `settings.X`.
            object.__setattr__(settings, spec.name, value)
            applied += 1
        except Exception:  # noqa: BLE001 - a field that refuses the value is not fatal
            logger.debug(
                "runtime_settings: cannot overlay %s", spec.name, exc_info=True
            )
    if applied:
        logger.info("runtime_settings.applied_to_settings count=%d", applied)


async def refresh(db=None) -> Dict[str, Any]:
    """Re-read the rows, refresh the cache, and publish the live ones."""
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
                ).where(db_models.SystemConfiguration.key.in_(tuple(BY_KEY)))
            )
            rows = result.all()
        except Exception:  # noqa: BLE001 - fall back to the environment silently
            logger.debug("runtime_settings: read failed", exc_info=True)
            rows = []
        finally:
            if own_session:
                await db.close()

        _cache.clear()
        _cache_by_key.clear()
        for key, raw in rows:
            spec = next((s for s in SPECS if s.key == key), None)
            if spec is None:
                continue
            value = _coerce(spec, raw)
            if value is None:
                continue
            _cache[spec.name] = value
            _cache_by_key[key] = value

        resolved = resolved_snapshot()
        _apply_live(resolved)
        return resolved


async def seed_missing_maximums(db=None) -> list[str]:
    """Fill in any managed key that has no row yet.

    Concurrency and worker capacity seed at the top of their range ("do not throttle
    yourself"); booleans and enums seed at the configured value, because "on" is a
    policy decision, not a performance one. Idempotent: an existing row is never touched.
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
                            db_models.SystemConfiguration.key.in_(tuple(BY_KEY))
                        )
                    )
                )
                .scalars()
                .all()
            )
            for descriptor in DESCRIPTORS:
                if descriptor.env is None or descriptor.key in existing:
                    continue
                if descriptor.kind == "int":
                    value = (
                        int(descriptor.maximum)
                        if descriptor.maximum is not None
                        else int(getattr(settings, descriptor.env, 0))
                    )
                else:
                    value = getattr(settings, descriptor.env, descriptor.default)
                    if isinstance(value, bool):
                        value = bool(value)
                    elif value is not None:
                        value = str(value)
                db.add(
                    db_models.SystemConfiguration(
                        key=descriptor.key, value={"value": value}
                    )
                )
                seeded.append(f"{descriptor.key}={value}")
            if seeded:
                await db.commit()
                logger.warning(
                    "runtime_settings.seeded %d limit(s): %s",
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


def managed_keys() -> tuple[str, ...]:
    """The `system_config` keys this module owns (for docs/tests)."""
    return tuple(BY_KEY)
