"""Admin endpoints for the multi-tenant foundation.

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
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.auth.core import current_active_user
from app.infrastructure.auth.sso import audit
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db


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
    created_at: datetime
    updated_at: datetime
    is_default: bool = False


class TenantCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    slug: str = Field(..., min_length=1, max_length=64)
    display_name: str = Field(..., min_length=1, max_length=128)


class TenantUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    display_name: str = Field(..., min_length=1, max_length=128)


async def _require_superuser(
    current_user: db_models.User = Depends(current_active_user),
) -> db_models.User:
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Not enough privileges"
        )
    return current_user


def _to_read(row: db_models.Tenant) -> TenantRead:
    return TenantRead(
        id=row.id,
        slug=row.slug,
        display_name=row.display_name,
        created_at=row.created_at,
        updated_at=row.updated_at,
        is_default=(row.id == DEFAULT_TENANT_ID),
    )


@router.get("", response_model=List[TenantRead])
async def list_tenants(
    db: AsyncSession = Depends(get_db),
    _user: db_models.User = Depends(_require_superuser),
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
)
async def create_tenant(
    request: Request,
    payload: TenantCreate = Body(...),
    db: AsyncSession = Depends(get_db),
    user: db_models.User = Depends(_require_superuser),
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

    row = db_models.Tenant(slug=slug, display_name=payload.display_name.strip())
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


@router.get("/{tenant_id}", response_model=TenantRead)
async def get_tenant(
    tenant_id: _uuid.UUID = Path(...),
    db: AsyncSession = Depends(get_db),
    _user: db_models.User = Depends(_require_superuser),
) -> TenantRead:
    row = (
        await db.execute(
            select(db_models.Tenant).where(db_models.Tenant.id == tenant_id)
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="tenant not found")
    return _to_read(row)


@router.patch("/{tenant_id}", response_model=TenantRead)
async def update_tenant(
    request: Request,
    tenant_id: _uuid.UUID = Path(...),
    payload: TenantUpdate = Body(...),
    db: AsyncSession = Depends(get_db),
    user: db_models.User = Depends(_require_superuser),
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
    new_name = payload.display_name.strip()
    if not new_name:
        raise HTTPException(status_code=400, detail="display_name cannot be empty")
    old_name = row.display_name
    row.display_name = new_name
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
        },
    )
    await db.commit()
    return _to_read(row)


@router.delete("/{tenant_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_tenant(
    request: Request,
    tenant_id: _uuid.UUID = Path(...),
    db: AsyncSession = Depends(get_db),
    user: db_models.User = Depends(_require_superuser),
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
