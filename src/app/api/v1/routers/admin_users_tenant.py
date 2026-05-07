"""Admin endpoint for assigning a user to a tenant (F14 follow-up).

Surface (superuser-only):

  PATCH  /api/v1/admin/users/{user_id}/tenant   {"tenant_id": "<uuid>" | null}

Today the multi-tenant foundation (Chunks 7 + 8 + 9) is in place but
operators had no way to move a user between tenants without an SQL
shell. This endpoint plugs that gap. Body shape:

  {"tenant_id": "11111111-..."}   → assign user to that tenant
  {"tenant_id": null}              → unassign (collapses to default
                                     tenant view via the dep's NULL →
                                     DEFAULT fallback)

Defenses
- Superuser-only (mirrors ``admin_tenants.py``'s ``_require_superuser``).
- Target tenant existence is verified before the UPDATE; 404 on missing.
- An admin cannot reassign their own row (defense in depth — superusers
  bypass tenant scope, so this is mostly a footgun guard, but encoded).
- Every successful UPDATE writes an ``auth_audit_events`` row in the
  same transaction with old + new tenant ids and the actor's id.
"""

from __future__ import annotations

import logging
import uuid as _uuid
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Request, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.auth.core import current_active_user
from app.infrastructure.auth.sso import audit
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db


logger = logging.getLogger(__name__)


router = APIRouter(prefix="/admin/users", tags=["Admin: Users"])


class UserTenantUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Optional[UUID]: null means "unassign" (the dep then coerces the
    # absent tenant to DEFAULT_TENANT_ID for non-admin reads).
    tenant_id: Optional[_uuid.UUID] = None


class UserTenantRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: str
    tenant_id: Optional[_uuid.UUID]


async def _require_superuser(
    current_user: db_models.User = Depends(current_active_user),
) -> db_models.User:
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Not enough privileges"
        )
    return current_user


@router.patch("/{user_id}/tenant", response_model=UserTenantRead)
async def update_user_tenant(
    request: Request,
    user_id: int = Path(..., ge=1),
    payload: UserTenantUpdate = Body(...),
    db: AsyncSession = Depends(get_db),
    actor: db_models.User = Depends(_require_superuser),
) -> UserTenantRead:
    """Assign or clear a user's tenant.

    Superuser-only. Validates the target tenant exists when non-null,
    refuses self-target, and writes an audit event in the same
    transaction as the UPDATE.
    """
    if user_id == actor.id:
        # Defense in depth: a superuser bypasses tenant scope on reads
        # anyway, so this is mostly a footgun guard, but locking it
        # closed prevents an admin from accidentally orphaning their
        # own row mid-operation.
        raise HTTPException(
            status_code=400,
            detail=(
                "an admin cannot reassign their own tenant — ask another "
                "admin or update the row directly"
            ),
        )

    target = (
        await db.execute(select(db_models.User).where(db_models.User.id == user_id))
    ).scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="user not found")

    new_tenant_id = payload.tenant_id
    if new_tenant_id is not None:
        tenant_exists = (
            await db.execute(
                select(db_models.Tenant.id).where(db_models.Tenant.id == new_tenant_id)
            )
        ).scalar_one_or_none()
        if tenant_exists is None:
            raise HTTPException(status_code=404, detail="tenant not found")

    old_tenant_id = target.tenant_id
    if old_tenant_id == new_tenant_id:
        # No-op write — return the current shape without an audit event
        # so the audit log reflects only real privilege changes.
        return UserTenantRead(
            id=target.id, email=target.email, tenant_id=target.tenant_id
        )

    target.tenant_id = new_tenant_id

    await audit.record(
        db,
        event="auth.privilege.user_tenant_changed",
        user_id=actor.id,
        request=request,
        details={
            "target_user_id": target.id,
            "target_email": target.email,
            "old_tenant_id": (str(old_tenant_id) if old_tenant_id else None),
            "new_tenant_id": (str(new_tenant_id) if new_tenant_id else None),
        },
    )
    await db.commit()
    return UserTenantRead(id=target.id, email=target.email, tenant_id=target.tenant_id)


__all__ = ["router"]
