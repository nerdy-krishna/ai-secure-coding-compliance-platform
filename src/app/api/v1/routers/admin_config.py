"""
Admin router for ``system_config`` rows.

Protection contract (V14.1.2 / V14.2.4):

* ``is_secret=True`` => the ``value`` field MUST be masked on read. The list
  endpoint never returns plaintext for these rows; a future explicit reveal
  endpoint is the only sanctioned path for retrieving plaintext.
* ``encrypted=True`` => the value MUST be Fernet-decrypted via
  ``SystemConfigRepository.decrypt_value`` before being surfaced, and MUST be
  re-encrypted via the repository's encrypt path before persistence. The
  router never persists plaintext for these rows.
* Mutations of security-impacting keys (``security.allowed_origins``,
  ``security.cors_enabled``, ``system.smtp``) are audit-logged at WARN and
  the in-memory ``SystemConfigCache`` update is wrapped so that a cache
  failure rolls back the DB row (V02.3.3).
"""

import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Path, status
from pydantic import AnyHttpUrl, BaseModel, Field, ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1 import models as api_models
from app.infrastructure.auth.core import current_active_user
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db
from app.infrastructure.database.repositories.system_config_repo import (
    SystemConfigRepository,
)


def get_system_config_repo(
    db: AsyncSession = Depends(get_db),
) -> SystemConfigRepository:
    """Per-request SystemConfigRepository (replaces the dropped class-level singleton)."""
    return SystemConfigRepository(db)


logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/admin/system-config",
    tags=["admin"],
    responses={404: {"description": "Not found"}},
)

# Sentinel returned in place of plaintext for is_secret / encrypted rows.
_REDACTED_VALUE = {"_redacted": True}


class _AllowedOriginsValue(BaseModel):
    """Strict shape for the ``security.allowed_origins`` config value."""

    origins: List[AnyHttpUrl] = Field(..., min_length=0, max_length=50)


class _CorsEnabledValue(BaseModel):
    """Strict shape for the dict-form ``security.cors_enabled`` config value."""

    enabled: bool


class _SessionLifetimeValue(BaseModel):
    """Strict shape for ``security.session_lifetime_hours`` (1..168 — capped
    at 7 days to match REFRESH_TOKEN_LIFETIME_SECONDS; M11)."""

    hours: int = Field(..., ge=1, le=168)


async def get_admin_user(current_user: db_models.User = Depends(current_active_user)):
    if not current_user.is_superuser:
        logger.warning(
            "admin.system_config.access_denied",
            extra={"user_id": current_user.id},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Not enough privileges"
        )
    return current_user


@router.get("/", response_model=List[api_models.SystemConfigurationRead])
async def get_all_system_configs(
    repo: SystemConfigRepository = Depends(get_system_config_repo),
    current_user: db_models.User = Depends(get_admin_user),
):
    """
    Get all system configurations. Only accessible by admins.

    Field-level rule: rows with ``is_secret=True`` or ``encrypted=True`` MUST
    have their ``value`` redacted before being returned. The plaintext is never
    serialised on the list endpoint (V08.1.2 / V13.3.1 / V14.1.1 / V14.2.4 /
    V14.2.6 / V15.1.5 / V15.3.1 / V16.2.5).
    """
    configs = await repo.get_all()
    out: List[api_models.SystemConfigurationRead] = []
    for config in configs:
        item = api_models.SystemConfigurationRead.model_validate(
            config, from_attributes=True
        )
        if getattr(config, "is_secret", False) or getattr(config, "encrypted", False):
            item = item.model_copy(update={"value": _REDACTED_VALUE})
        out.append(item)
    return out


@router.put("/{key}", response_model=api_models.SystemConfigurationRead)
async def set_system_config(
    key: str = Path(..., min_length=1, max_length=200, pattern=r"^[a-zA-Z0-9_.\-]+$"),
    config: api_models.SystemConfigurationUpdate = ...,
    repo: SystemConfigRepository = Depends(get_system_config_repo),
    current_user: db_models.User = Depends(get_admin_user),
):
    """
    Create or update a system configuration.
    """
    # Check if exists
    existing = await repo.get_by_key(key)

    # Merge update data into create model
    create_data = {}
    if existing:
        create_data = {
            "key": key,
            "value": config.value if config.value is not None else existing.value,
            "description": (
                config.description
                if config.description is not None
                else existing.description
            ),
            "is_secret": (
                config.is_secret if config.is_secret is not None else existing.is_secret
            ),
            "encrypted": (
                config.encrypted if config.encrypted is not None else existing.encrypted
            ),
        }
    else:
        if config.value is None:
            raise HTTPException(status_code=400, detail="Value is required for new key")
        create_data = {
            "key": key,
            "value": config.value,
            "description": config.description,
            "is_secret": config.is_secret if config.is_secret is not None else False,
            "encrypted": config.encrypted if config.encrypted is not None else False,
        }

    system_config = api_models.SystemConfigurationCreate(**create_data)
    # V02.3.4 — thread expected_version through to the repo for optimistic
    # locking on UPDATEs. Insert path ignores the parameter.
    from app.shared.lib.optimistic_lock import OptimisticLockError

    try:
        result = await repo.set_value(
            system_config, expected_version=config.expected_version
        )
    except OptimisticLockError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "version_mismatch",
                "current_version": e.current_version,
            },
        )

    logger.info(
        "admin.system_config.upserted",
        extra={
            "actor_id": current_user.id,
            "key": key,
            "is_secret": system_config.is_secret,
        },
    )

    # Validate inner shape for security-critical keys before mutating the cache (V02.1.2)
    if key == "security.allowed_origins" and isinstance(system_config.value, dict):
        try:
            _AllowedOriginsValue.model_validate(system_config.value)
        except ValidationError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid allowed_origins payload: {exc}",
            )
    elif key == "security.cors_enabled" and isinstance(system_config.value, dict):
        try:
            _CorsEnabledValue.model_validate(system_config.value)
        except ValidationError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid cors_enabled payload: {exc}",
            )
    elif key == "security.session_lifetime_hours" and isinstance(
        system_config.value, dict
    ):
        try:
            _SessionLifetimeValue.model_validate(system_config.value)
        except ValidationError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid session_lifetime_hours payload: {exc}",
            )

    # Dynamic updates to cache. If a cache update raises, roll back the DB
    # write so cache and DB cannot drift out of sync (V02.3.3).
    from app.core.config_cache import SystemConfigCache

    try:
        if key == "system.smtp":
            SystemConfigCache.set_smtp_config(system_config.value)
            logger.warning(
                "admin.system_config.cache_updated",
                extra={"actor_id": current_user.id, "key": key},
            )
        elif key == "security.allowed_origins" and isinstance(
            system_config.value, dict
        ):
            if "origins" in system_config.value:
                SystemConfigCache.set_allowed_origins(system_config.value["origins"])
                logger.warning(
                    "admin.system_config.cache_updated",
                    extra={"actor_id": current_user.id, "key": key},
                )
        elif key == "security.cors_enabled":
            val = system_config.value
            if isinstance(val, dict) and "enabled" in val:
                SystemConfigCache.set_cors_enabled(bool(val["enabled"]))
            else:
                SystemConfigCache.set_cors_enabled(bool(val))
            logger.warning(
                "admin.system_config.cache_updated",
                extra={"actor_id": current_user.id, "key": key},
            )
        elif key == "security.session_lifetime_hours":
            val = system_config.value
            if isinstance(val, dict) and "hours" in val:
                SystemConfigCache.set_session_lifetime_hours(int(val["hours"]))
                logger.warning(
                    "admin.system_config.cache_updated",
                    extra={"actor_id": current_user.id, "key": key},
                )
    except Exception:
        # Roll back the DB write so cache and DB stay consistent (V02.3.3).
        try:
            if existing is not None:
                rollback_payload = api_models.SystemConfigurationCreate(
                    key=existing.key,
                    value=existing.value,
                    description=existing.description,
                    is_secret=existing.is_secret,
                    encrypted=existing.encrypted,
                )
                await repo.set_value(rollback_payload)
            else:
                await repo.delete(key)
        except Exception:
            logger.exception(
                "admin.system_config.rollback_failed",
                extra={"actor_id": current_user.id, "key": key},
            )
        raise

    return result


@router.delete("/{key}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_system_config(
    key: str = Path(..., min_length=1, max_length=200, pattern=r"^[a-zA-Z0-9_.\-]+$"),
    repo: SystemConfigRepository = Depends(get_system_config_repo),
    current_user: db_models.User = Depends(get_admin_user),
):
    """
    Delete a system configuration.
    """
    deleted = await repo.delete(key)
    if not deleted:
        raise HTTPException(status_code=404, detail="Configuration not found")
    logger.info(
        "admin.system_config.deleted",
        extra={"actor_id": current_user.id, "key": key},
    )
    return None
