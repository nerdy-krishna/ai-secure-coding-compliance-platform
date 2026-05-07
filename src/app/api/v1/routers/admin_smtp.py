"""
Admin SMTP profile management.

Profiles are stored in two system_configuration keys:
  - smtp.profiles  (unencrypted): {"active_id": str|null, "profiles": [...metadata...]}
  - smtp.password.<id> (encrypted, is_secret): {"password": "..."}

The non-sensitive metadata is kept unencrypted so the UI can display it
without the GET endpoint redacting it. Only the password stays encrypted.
"""

import logging
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.api.v1 import models as api_models
from app.infrastructure.auth.core import current_superuser
from app.infrastructure.database.database import get_db
from app.infrastructure.database.repositories.system_config_repo import (
    SystemConfigRepository,
)
from app.core.config_cache import SystemConfigCache
from sqlalchemy.ext.asyncio import AsyncSession


def get_system_config_repo(
    db: AsyncSession = Depends(get_db),
) -> SystemConfigRepository:
    return SystemConfigRepository(db)


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/smtp", tags=["Admin: SMTP"])

_PROFILES_KEY = "smtp.profiles"

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class SmtpProfileMeta(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str
    host: str
    port: int = 587
    user: str
    from_addr: str = Field(alias="from")
    tls: bool = True
    ssl: bool = False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "user": self.user,
            "from": self.from_addr,
            "tls": self.tls,
            "ssl": self.ssl,
        }


class SmtpProfilesPayload(BaseModel):
    active_id: Optional[str] = None
    profiles: List[SmtpProfileMeta] = []


class SmtpProfilesResponse(BaseModel):
    active_id: Optional[str] = None
    profiles: List[dict] = []


class CreateSmtpProfileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=80)
    host: str = Field(..., min_length=1, max_length=256)
    port: int = Field(587, ge=1, le=65535)
    user: str = Field(..., min_length=1, max_length=256)
    from_addr: str = Field(..., alias="from")
    tls: bool = True
    ssl: bool = False
    password: str = Field(..., min_length=1, max_length=512)

    @field_validator("host", "user", "from_addr", mode="before")
    @classmethod
    def no_crlf(cls, v: str) -> str:
        if "\r" in v or "\n" in v:
            raise ValueError("Field contains CR/LF characters.")
        return v

    @field_validator("tls", "ssl")
    @classmethod
    def one_transport(cls, v: bool, info) -> bool:
        return v


class UpdateSmtpProfileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    name: Optional[str] = Field(None, max_length=80)
    host: Optional[str] = Field(None, max_length=256)
    port: Optional[int] = Field(None, ge=1, le=65535)
    user: Optional[str] = Field(None, max_length=256)
    from_addr: Optional[str] = Field(None, alias="from")
    tls: Optional[bool] = None
    ssl: Optional[bool] = None
    password: Optional[str] = Field(None, max_length=512)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _load_profiles(repo: SystemConfigRepository) -> SmtpProfilesPayload:
    row = await repo.get_by_key(_PROFILES_KEY)
    if row and isinstance(row.value, dict):
        data = row.value
        profiles = [SmtpProfileMeta.model_validate(p) for p in data.get("profiles", [])]
        return SmtpProfilesPayload(active_id=data.get("active_id"), profiles=profiles)
    return SmtpProfilesPayload()


async def _save_profiles(
    repo: SystemConfigRepository, payload: SmtpProfilesPayload
) -> None:
    data = {
        "active_id": payload.active_id,
        "profiles": [p.to_dict() for p in payload.profiles],
    }
    cfg = api_models.SystemConfigurationCreate(
        key=_PROFILES_KEY,
        value=data,
        description="SMTP named profiles (metadata; passwords stored separately)",
        is_secret=False,
        encrypted=False,
    )
    await repo.set_value(cfg)


async def _reload_smtp_cache(
    repo: SystemConfigRepository, active_id: Optional[str]
) -> None:
    """Rebuild SystemConfigCache._smtp_config from the active profile."""
    if not active_id:
        SystemConfigCache.set_smtp_config(None)
        return

    payload = await _load_profiles(repo)
    profile = next((p for p in payload.profiles if p.id == active_id), None)
    if not profile:
        SystemConfigCache.set_smtp_config(None)
        return

    pw_row = await repo.get_by_key(f"smtp.password.{active_id}")
    password = ""
    if pw_row and isinstance(pw_row.value, dict):
        password = pw_row.value.get("password", "")

    SystemConfigCache.set_smtp_config(
        {
            "host": profile.host,
            "port": profile.port,
            "user": profile.user,
            "from": profile.from_addr,
            "tls": profile.tls,
            "ssl": profile.ssl,
            "password": password,
        }
    )
    logger.info("admin.smtp.cache_reloaded", extra={"active_id": active_id})


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/profiles",
    response_model=SmtpProfilesResponse,
    dependencies=[Depends(current_superuser)],
)
async def list_smtp_profiles(
    repo: SystemConfigRepository = Depends(get_system_config_repo),
):
    """Return all SMTP profiles (metadata only — no passwords)."""
    payload = await _load_profiles(repo)

    return SmtpProfilesResponse(
        active_id=payload.active_id,
        profiles=[p.to_dict() for p in payload.profiles],
    )


@router.post(
    "/profiles",
    response_model=SmtpProfilesResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(current_superuser)],
)
async def create_smtp_profile(
    body: CreateSmtpProfileRequest,
    repo: SystemConfigRepository = Depends(get_system_config_repo),
):
    """Create a new SMTP profile. Stores password encrypted separately."""
    if body.tls and body.ssl:
        raise HTTPException(400, detail="STARTTLS and SSL are mutually exclusive.")
    if not body.tls and not body.ssl:
        raise HTTPException(
            400, detail="Enable STARTTLS or SSL — cleartext SMTP is not allowed."
        )

    payload = await _load_profiles(repo)

    # Reject duplicate names
    if any(p.name.lower() == body.name.lower() for p in payload.profiles):
        raise HTTPException(400, detail="A profile with this name already exists.")

    profile_id = str(uuid.uuid4())[:8]
    new_profile = SmtpProfileMeta(
        id=profile_id,
        name=body.name,
        host=body.host,
        port=body.port,
        user=body.user,
        **{"from": body.from_addr},
        tls=body.tls,
        ssl=body.ssl,
    )
    payload.profiles.append(new_profile)

    # First profile is automatically activated
    if len(payload.profiles) == 1:
        payload.active_id = profile_id

    await _save_profiles(repo, payload)

    # Store password encrypted
    pw_cfg = api_models.SystemConfigurationCreate(
        key=f"smtp.password.{profile_id}",
        value={"password": body.password},
        description=f"SMTP password for profile {profile_id}",
        is_secret=True,
        encrypted=True,
    )
    await repo.set_value(pw_cfg)

    if payload.active_id == profile_id:
        await _reload_smtp_cache(repo, profile_id)

    logger.info("admin.smtp.profile_created", extra={"profile_id": profile_id})
    return SmtpProfilesResponse(
        active_id=payload.active_id,
        profiles=[p.to_dict() for p in payload.profiles],
    )


@router.patch(
    "/profiles/{profile_id}",
    response_model=SmtpProfilesResponse,
    dependencies=[Depends(current_superuser)],
)
async def update_smtp_profile(
    profile_id: str,
    body: UpdateSmtpProfileRequest,
    repo: SystemConfigRepository = Depends(get_system_config_repo),
):
    """Update a profile's metadata and optionally its password."""
    payload = await _load_profiles(repo)
    profile = next((p for p in payload.profiles if p.id == profile_id), None)
    if not profile:
        raise HTTPException(404, detail="Profile not found.")

    if body.name is not None:
        profile.name = body.name
    if body.host is not None:
        profile.host = body.host
    if body.port is not None:
        profile.port = body.port
    if body.user is not None:
        profile.user = body.user
    if body.from_addr is not None:
        profile.from_addr = body.from_addr
    if body.tls is not None:
        profile.tls = body.tls
    if body.ssl is not None:
        profile.ssl = body.ssl

    if profile.tls and profile.ssl:
        raise HTTPException(400, detail="STARTTLS and SSL are mutually exclusive.")
    if not profile.tls and not profile.ssl:
        raise HTTPException(
            400, detail="Enable STARTTLS or SSL — cleartext SMTP is not allowed."
        )

    await _save_profiles(repo, payload)

    if body.password:
        pw_cfg = api_models.SystemConfigurationCreate(
            key=f"smtp.password.{profile_id}",
            value={"password": body.password},
            description=f"SMTP password for profile {profile_id}",
            is_secret=True,
            encrypted=True,
        )
        await repo.set_value(pw_cfg)

    if payload.active_id == profile_id:
        await _reload_smtp_cache(repo, profile_id)

    logger.info("admin.smtp.profile_updated", extra={"profile_id": profile_id})
    return SmtpProfilesResponse(
        active_id=payload.active_id,
        profiles=[p.to_dict() for p in payload.profiles],
    )


@router.delete(
    "/profiles/{profile_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(current_superuser)],
)
async def delete_smtp_profile(
    profile_id: str,
    repo: SystemConfigRepository = Depends(get_system_config_repo),
):
    """Delete a profile and its password. Clears the active config if it was active."""
    payload = await _load_profiles(repo)
    before = len(payload.profiles)
    payload.profiles = [p for p in payload.profiles if p.id != profile_id]
    if len(payload.profiles) == before:
        raise HTTPException(404, detail="Profile not found.")

    was_active = payload.active_id == profile_id
    if was_active:
        payload.active_id = payload.profiles[0].id if payload.profiles else None

    await _save_profiles(repo, payload)
    await repo.delete(f"smtp.password.{profile_id}")

    if was_active:
        await _reload_smtp_cache(repo, payload.active_id)

    logger.info("admin.smtp.profile_deleted", extra={"profile_id": profile_id})


@router.post(
    "/profiles/{profile_id}/activate",
    response_model=SmtpProfilesResponse,
    dependencies=[Depends(current_superuser)],
)
async def activate_smtp_profile(
    profile_id: str,
    repo: SystemConfigRepository = Depends(get_system_config_repo),
):
    """Set the active SMTP profile."""
    payload = await _load_profiles(repo)
    if not any(p.id == profile_id for p in payload.profiles):
        raise HTTPException(404, detail="Profile not found.")

    payload.active_id = profile_id
    await _save_profiles(repo, payload)
    await _reload_smtp_cache(repo, profile_id)

    logger.info("admin.smtp.profile_activated", extra={"profile_id": profile_id})
    return SmtpProfilesResponse(
        active_id=payload.active_id,
        profiles=[p.to_dict() for p in payload.profiles],
    )
