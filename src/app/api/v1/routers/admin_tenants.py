"""Permission-scoped endpoints for tenant metadata and verified domains.

Surface (all superuser-only):

  GET    /api/v1/admin/tenants            — list all tenants
  POST   /api/v1/admin/tenants            — create a tenant
  GET    /api/v1/admin/tenants/{id}       — read a tenant
  PATCH  /api/v1/admin/tenants/{id}       — rename display_name only
  DELETE /api/v1/admin/tenants/{id}       — delete (default tenant is protected)

Tenant scoping today is *foundation only* (Chunk 7) — every existing
aggregate row is backfilled to the seeded ``default`` tenant
(``00000000-0000-0000-0000-000000000001``). The schema, repo, and admin
surface are in place so future enforcement work (scoped queries,
per-tenant SSO/SCIM) only needs to plug in the visibility layer.

Slug constraints
- ASCII alphanumerics + dash + underscore, 1–64 chars, lowercased.
- Slug is immutable after creation — anything that may end up in a
  URL or a downstream system should not change identity.
"""

from __future__ import annotations

import logging
import re
import uuid as _uuid
from datetime import datetime
from typing import List

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Request, status
from fastapi_users.password import PasswordHelper
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import get_current_user_tenant_id, require_permission
from app.infrastructure.auth.core import current_active_user
from app.infrastructure.auth.tenant_entry import (
    MAX_AGE_SECONDS as TENANT_ENTRY_MAX_AGE_SECONDS,
    issue_tenant_entry_grant,
)
from app.infrastructure.auth.sso import audit
from app.infrastructure.auth.sso.domains import (
    DomainVerificationError,
    mark_verified,
    new_challenge,
    normalize_domain,
    verify_dns_challenge,
)
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db
from app.infrastructure.database.repositories.authorization_repo import (
    AuthorizationRepository,
    target_fingerprint,
)
from app.shared.lib.permissions import PLATFORM_TENANT_MANAGE, TENANT_POLICY_MANAGE


logger = logging.getLogger(__name__)


router = APIRouter(prefix="/admin/tenants", tags=["Admin: Tenants"])


# UUID of the seeded default tenant (see migration
# 2026_05_08_0200_add_tenants_foundation.py). Treated specially:
# cannot be renamed (slug immutable across the board) and cannot be
# deleted (every backfilled row points to it; deleting would orphan
# them via the SET NULL FK).
DEFAULT_TENANT_ID = _uuid.UUID("00000000-0000-0000-0000-000000000001")
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class TenantRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: _uuid.UUID
    slug: str
    display_name: str
    session_concurrency_limit: int | None
    session_concurrency_mode: str
    created_at: datetime
    updated_at: datetime
    is_default: bool = False


class TenantCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    slug: str = Field(..., min_length=1, max_length=64)
    display_name: str = Field(..., min_length=1, max_length=128)
    session_concurrency_limit: int | None = Field(default=None, ge=1, le=100)
    session_concurrency_mode: str = Field(
        default="deny_new", pattern=r"^(deny_new|revoke_oldest)$"
    )


class TenantUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    display_name: str | None = Field(default=None, min_length=1, max_length=128)
    session_concurrency_limit: int | None = Field(default=None, ge=1, le=100)
    session_concurrency_mode: str | None = Field(
        default=None, pattern=r"^(deny_new|revoke_oldest)$"
    )


class DomainCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domain: str = Field(..., min_length=3, max_length=253)


class DomainRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: _uuid.UUID
    tenant_id: _uuid.UUID
    domain: str
    status: str
    verified_at: datetime | None
    created_at: datetime


class DomainChallengeRead(DomainRead):
    txt_name: str
    txt_value: str


class TenantEntryCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: _uuid.UUID
    password: str = Field(..., min_length=1, max_length=256)


class TenantEntryRead(BaseModel):
    tenant_id: _uuid.UUID
    entry_token: str
    expires_in: int


def _to_read(row: db_models.Tenant) -> TenantRead:
    return TenantRead(
        id=row.id,
        slug=row.slug,
        display_name=row.display_name,
        session_concurrency_limit=row.session_concurrency_limit,
        session_concurrency_mode=row.session_concurrency_mode,
        created_at=row.created_at,
        updated_at=row.updated_at,
        is_default=(row.id == DEFAULT_TENANT_ID),
    )


async def _get_tenant_or_404(
    db: AsyncSession, tenant_id: _uuid.UUID
) -> db_models.Tenant:
    row = await db.get(db_models.Tenant, tenant_id)
    if row is None:
        raise HTTPException(status_code=404, detail="tenant not found")
    return row


def _require_path_tenant(tenant_id: _uuid.UUID, active_tenant_id: _uuid.UUID) -> None:
    if tenant_id != active_tenant_id:
        raise HTTPException(status_code=404, detail="tenant not found")


@router.get(
    "/{tenant_id}/domains",
    response_model=List[DomainRead],
    dependencies=[Depends(require_permission(TENANT_POLICY_MANAGE))],
)
async def list_verified_domains(
    tenant_id: _uuid.UUID = Path(...),
    active_tenant_id: _uuid.UUID = Depends(get_current_user_tenant_id),
    db: AsyncSession = Depends(get_db),
) -> List[DomainRead]:
    _require_path_tenant(tenant_id, active_tenant_id)
    await _get_tenant_or_404(db, tenant_id)
    rows = (
        await db.scalars(
            select(db_models.TenantVerifiedDomain)
            .where(db_models.TenantVerifiedDomain.tenant_id == tenant_id)
            .order_by(db_models.TenantVerifiedDomain.domain)
        )
    ).all()
    return [DomainRead.model_validate(row) for row in rows]


@router.post(
    "/{tenant_id}/domains",
    response_model=DomainChallengeRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(TENANT_POLICY_MANAGE))],
)
async def create_domain_challenge(
    request: Request,
    payload: DomainCreate,
    tenant_id: _uuid.UUID = Path(...),
    active_tenant_id: _uuid.UUID = Depends(get_current_user_tenant_id),
    db: AsyncSession = Depends(get_db),
    user: db_models.User = Depends(current_active_user),
) -> DomainChallengeRead:
    _require_path_tenant(tenant_id, active_tenant_id)
    await _get_tenant_or_404(db, tenant_id)
    try:
        normalized = normalize_domain(payload.domain)
    except DomainVerificationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    existing = await db.scalar(
        select(db_models.TenantVerifiedDomain).where(
            db_models.TenantVerifiedDomain.domain == normalized
        )
    )
    if existing is not None:
        raise HTTPException(status_code=409, detail="domain is already claimed")
    challenge = new_challenge(normalized)
    row = db_models.TenantVerifiedDomain(
        tenant_id=tenant_id,
        domain=normalized,
        verification_token_hash=challenge.token_hash,
    )
    db.add(row)
    await db.flush()
    await audit.record(
        db,
        event="tenant.domain.challenge_created",
        actor_user_id=user.id,
        tenant_id=tenant_id,
        outcome="success",
        request=request,
        details={"domain": normalized},
    )
    await db.commit()
    return DomainChallengeRead(
        **DomainRead.model_validate(row).model_dump(),
        txt_name=challenge.txt_name,
        txt_value=challenge.txt_value,
    )


@router.post(
    "/{tenant_id}/domains/{domain_id}/verify",
    response_model=DomainRead,
    dependencies=[Depends(require_permission(TENANT_POLICY_MANAGE))],
)
async def verify_tenant_domain(
    request: Request,
    tenant_id: _uuid.UUID = Path(...),
    domain_id: _uuid.UUID = Path(...),
    active_tenant_id: _uuid.UUID = Depends(get_current_user_tenant_id),
    db: AsyncSession = Depends(get_db),
    user: db_models.User = Depends(current_active_user),
) -> DomainRead:
    _require_path_tenant(tenant_id, active_tenant_id)
    row = await db.scalar(
        select(db_models.TenantVerifiedDomain).where(
            db_models.TenantVerifiedDomain.id == domain_id,
            db_models.TenantVerifiedDomain.tenant_id == tenant_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="domain challenge not found")
    verified = row.status == "verified" or await verify_dns_challenge(row)
    if not verified:
        await audit.record(
            db,
            event="tenant.domain.verification_failed",
            actor_user_id=user.id,
            tenant_id=tenant_id,
            outcome="denied",
            request=request,
            details={"domain": row.domain},
        )
        await db.commit()
        raise HTTPException(status_code=409, detail="DNS TXT challenge not found")
    if row.status != "verified":
        mark_verified(row)
    await audit.record(
        db,
        event="tenant.domain.verified",
        actor_user_id=user.id,
        tenant_id=tenant_id,
        outcome="success",
        request=request,
        details={"domain": row.domain},
    )
    await db.commit()
    return DomainRead.model_validate(row)


@router.delete(
    "/{tenant_id}/domains/{domain_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission(TENANT_POLICY_MANAGE))],
)
async def delete_tenant_domain(
    request: Request,
    tenant_id: _uuid.UUID = Path(...),
    domain_id: _uuid.UUID = Path(...),
    active_tenant_id: _uuid.UUID = Depends(get_current_user_tenant_id),
    db: AsyncSession = Depends(get_db),
    user: db_models.User = Depends(current_active_user),
) -> None:
    _require_path_tenant(tenant_id, active_tenant_id)
    row = await db.scalar(
        select(db_models.TenantVerifiedDomain).where(
            db_models.TenantVerifiedDomain.id == domain_id,
            db_models.TenantVerifiedDomain.tenant_id == tenant_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="domain not found")
    domain = row.domain
    await db.delete(row)
    await audit.record(
        db,
        event="tenant.domain.deleted",
        actor_user_id=user.id,
        tenant_id=tenant_id,
        outcome="success",
        request=request,
        details={"domain": domain},
    )
    await db.commit()


@router.get(
    "",
    response_model=List[TenantRead],
    dependencies=[Depends(require_permission(PLATFORM_TENANT_MANAGE))],
)
async def list_tenants(
    db: AsyncSession = Depends(get_db),
) -> List[TenantRead]:
    rows = (
        (
            await db.execute(
                select(db_models.Tenant).order_by(db_models.Tenant.created_at)
            )
        )
        .scalars()
        .all()
    )
    return [_to_read(r) for r in rows]


@router.post(
    "",
    response_model=TenantRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(PLATFORM_TENANT_MANAGE))],
)
async def create_tenant(
    request: Request,
    payload: TenantCreate = Body(...),
    db: AsyncSession = Depends(get_db),
    user: db_models.User = Depends(current_active_user),
) -> TenantRead:
    slug = payload.slug.strip().lower()
    if not _SLUG_RE.match(slug):
        raise HTTPException(
            status_code=400,
            detail=(
                "slug must be 1–64 chars, lowercase ASCII letters / digits / "
                "dashes / underscores, starting with a letter or digit"
            ),
        )
    if slug == "default":
        raise HTTPException(
            status_code=400, detail="'default' is reserved for the seeded tenant"
        )
    existing = (
        await db.execute(select(db_models.Tenant).where(db_models.Tenant.slug == slug))
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status_code=409, detail="slug already in use")

    row = db_models.Tenant(
        slug=slug,
        display_name=payload.display_name.strip(),
        session_concurrency_limit=payload.session_concurrency_limit,
        session_concurrency_mode=payload.session_concurrency_mode,
    )
    db.add(row)
    await db.flush()
    await audit.record(
        db,
        event="tenant.created",
        user_id=user.id,
        request=request,
        details={
            "tenant_id": str(row.id),
            "slug": slug,
            "display_name": row.display_name,
        },
    )
    await db.commit()
    return _to_read(row)


@router.post(
    "/entry",
    response_model=TenantEntryRead,
    dependencies=[Depends(require_permission(PLATFORM_TENANT_MANAGE))],
)
async def create_tenant_entry(
    request: Request,
    payload: TenantEntryCreate = Body(...),
    db: AsyncSession = Depends(get_db),
    user: db_models.User = Depends(current_active_user),
) -> TenantEntryRead:
    """Reauthenticate a platform owner and bind a short-lived selected tenant."""

    tenant = await db.scalar(
        select(db_models.Tenant).where(db_models.Tenant.id == payload.tenant_id)
    )
    if tenant is None:
        raise HTTPException(status_code=404, detail="tenant not found")

    verified, updated_hash = PasswordHelper().verify_and_update(
        payload.password,
        user.hashed_password,
    )
    authz = AuthorizationRepository(db)
    fingerprint = target_fingerprint(
        resource_type="tenant_entry",
        target_id=str(payload.tenant_id),
    )
    if not verified:
        authz.record_audit(
            tenant_id=payload.tenant_id,
            principal_kind="human",
            principal_id=str(user.id),
            permission=PLATFORM_TENANT_MANAGE,
            resource_type="tenant_entry",
            target_fingerprint_value=fingerprint,
            outcome="denied",
            reason_code="step_up_failed",
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tenant entry denied.",
        )
    if updated_hash is not None:
        user.hashed_password = updated_hash

    token = issue_tenant_entry_grant(
        request,
        user_id=user.id,
        tenant_id=payload.tenant_id,
    )
    authz.record_audit(
        tenant_id=payload.tenant_id,
        principal_kind="human",
        principal_id=str(user.id),
        permission=PLATFORM_TENANT_MANAGE,
        resource_type="tenant_entry",
        target_fingerprint_value=fingerprint,
        outcome="allowed",
        reason_code="step_up_verified",
    )
    await db.commit()
    return TenantEntryRead(
        tenant_id=payload.tenant_id,
        entry_token=token,
        expires_in=TENANT_ENTRY_MAX_AGE_SECONDS,
    )


@router.get(
    "/{tenant_id}",
    response_model=TenantRead,
    dependencies=[Depends(require_permission(PLATFORM_TENANT_MANAGE))],
)
async def get_tenant(
    tenant_id: _uuid.UUID = Path(...),
    db: AsyncSession = Depends(get_db),
) -> TenantRead:
    row = (
        await db.execute(
            select(db_models.Tenant).where(db_models.Tenant.id == tenant_id)
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="tenant not found")
    return _to_read(row)


@router.patch(
    "/{tenant_id}",
    response_model=TenantRead,
    dependencies=[Depends(require_permission(PLATFORM_TENANT_MANAGE))],
)
async def update_tenant(
    request: Request,
    tenant_id: _uuid.UUID = Path(...),
    payload: TenantUpdate = Body(...),
    db: AsyncSession = Depends(get_db),
    user: db_models.User = Depends(current_active_user),
) -> TenantRead:
    """Rename a tenant. Slug is immutable so external references and audit
    history stay stable; if a slug change is genuinely needed, create a
    new tenant + migrate ownership."""
    row = (
        await db.execute(
            select(db_models.Tenant).where(db_models.Tenant.id == tenant_id)
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="tenant not found")
    old_name = row.display_name
    new_name = old_name
    if payload.display_name is not None:
        new_name = payload.display_name.strip()
        if not new_name:
            raise HTTPException(status_code=400, detail="display_name cannot be empty")
        row.display_name = new_name
    if "session_concurrency_limit" in payload.model_fields_set:
        row.session_concurrency_limit = payload.session_concurrency_limit
    if payload.session_concurrency_mode is not None:
        row.session_concurrency_mode = payload.session_concurrency_mode
    await audit.record(
        db,
        event="tenant.updated",
        user_id=user.id,
        request=request,
        details={
            "tenant_id": str(row.id),
            "slug": row.slug,
            "old_display_name": old_name,
            "new_display_name": new_name,
            "session_concurrency_limit": row.session_concurrency_limit,
            "session_concurrency_mode": row.session_concurrency_mode,
        },
    )
    await db.commit()
    return _to_read(row)


@router.delete(
    "/{tenant_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission(PLATFORM_TENANT_MANAGE))],
)
async def delete_tenant(
    request: Request,
    tenant_id: _uuid.UUID = Path(...),
    db: AsyncSession = Depends(get_db),
    user: db_models.User = Depends(current_active_user),
) -> None:
    """Delete a tenant. The default tenant is protected — every backfilled
    row points to it and dropping it would orphan that data via the SET
    NULL FK. Deleting any other tenant detaches its rows (tenant_id
    becomes NULL); operators are expected to reassign first."""
    if tenant_id == DEFAULT_TENANT_ID:
        raise HTTPException(
            status_code=400,
            detail="the default tenant is protected and cannot be deleted",
        )
    row = (
        await db.execute(
            select(db_models.Tenant).where(db_models.Tenant.id == tenant_id)
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="tenant not found")
    slug = row.slug
    name = row.display_name
    await db.delete(row)
    await audit.record(
        db,
        event="tenant.deleted",
        user_id=user.id,
        request=request,
        details={
            "tenant_id": str(tenant_id),
            "slug": slug,
            "display_name": name,
        },
    )
    await db.commit()


__all__ = ["router", "DEFAULT_TENANT_ID"]
