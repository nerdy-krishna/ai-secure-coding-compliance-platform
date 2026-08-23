"""Explicit platform-owner operation for moving a human between tenants.

Surface (platform tenant management + explicit source tenant):

  PATCH  /api/v1/admin/users/{user_id}/tenant   {"tenant_id": "<uuid>"}

Defenses
- The source is the active tenant, selected through a step-up grant for foreign tenants.
- The destination is mandatory; users can no longer become tenant-less.
- Critical-mode tenants fail closed until the two-person action workflow approves the move.
- Existing tenant roles are dropped and the destination starts with analyst only.
"""

from __future__ import annotations

import logging
import uuid as _uuid

from fastapi import APIRouter, Body, Depends, HTTPException, Path, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import get_current_user_tenant_id, require_permission
from app.infrastructure.auth.core import current_active_user
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db
from app.infrastructure.database.repositories.auth_session_repo import (
    AuthSessionRepository,
)
from app.infrastructure.database.repositories.authorization_repo import (
    AuthorizationRepository,
    target_fingerprint,
)
from app.infrastructure.database.tenant_context import (
    apply_session_context,
    principal_scope,
)
from app.shared.lib.permissions import ANALYST, PLATFORM_TENANT_MANAGE


logger = logging.getLogger(__name__)


router = APIRouter(prefix="/admin/users", tags=["Admin: Users"])


class UserTenantUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: _uuid.UUID


class UserTenantRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: str
    tenant_id: _uuid.UUID


@router.patch(
    "/{user_id}/tenant",
    response_model=UserTenantRead,
    dependencies=[Depends(require_permission(PLATFORM_TENANT_MANAGE))],
)
async def update_user_tenant(
    user_id: int = Path(..., ge=1),
    payload: UserTenantUpdate = Body(...),
    source_tenant_id: _uuid.UUID = Depends(get_current_user_tenant_id),
    db: AsyncSession = Depends(get_db),
    actor: db_models.User = Depends(current_active_user),
) -> UserTenantRead:
    """Move a non-acting user from the selected source to one destination."""
    if user_id == actor.id:
        raise HTTPException(
            status_code=400,
            detail=(
                "an admin cannot reassign their own tenant — ask another "
                "admin or update the row directly"
            ),
        )

    target = (
        await db.execute(
            select(db_models.User).where(
                db_models.User.id == user_id,
                db_models.User.tenant_id == source_tenant_id,
            )
        )
    ).scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="user not found")

    new_tenant_id = payload.tenant_id
    tenant_exists = await db.scalar(
        select(db_models.Tenant.id).where(db_models.Tenant.id == new_tenant_id)
    )
    if tenant_exists is None:
        raise HTTPException(status_code=404, detail="tenant not found")

    if source_tenant_id == new_tenant_id:
        # No-op write — return the current shape without an audit event
        # so the audit log reflects only real privilege changes.
        return UserTenantRead(
            id=target.id, email=target.email, tenant_id=target.tenant_id
        )

    authz = AuthorizationRepository(db)
    source_mode = await authz.separation_of_duties_mode(tenant_id=source_tenant_id)
    destination_mode = await authz.separation_of_duties_mode(tenant_id=new_tenant_id)
    if "critical" in {source_mode, destination_mode}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Tenant reassignment requires an approved action request.",
        )

    with principal_scope(
        tenant_id=None,
        principal_kind="system",
        principal_id="platform-user-tenant-move",
        system_scope=True,
    ):
        await apply_session_context(db)
        target.tenant_id = new_tenant_id
        await db.flush()
        await db.execute(
            delete(db_models.RoleAssignment).where(
                db_models.RoleAssignment.user_id == target.id
            )
        )
        db.add(
            db_models.RoleAssignment(
                user_id=target.id,
                tenant_id=new_tenant_id,
                role_key=ANALYST,
                created_by_user_id=actor.id,
            )
        )
        await AuthSessionRepository(db).revoke_all_for_user(
            target.id,
            reason="tenant_changed",
        )
        authz.record_audit(
            tenant_id=new_tenant_id,
            principal_kind="human",
            principal_id=str(actor.id),
            permission=PLATFORM_TENANT_MANAGE,
            resource_type="user_tenant_assignment",
            target_fingerprint_value=target_fingerprint(
                resource_type="user_tenant_assignment",
                target_id=str(target.id),
            ),
            outcome="executed",
            reason_code="tenant_changed_roles_reset",
        )
        await db.commit()
    return UserTenantRead(id=target.id, email=target.email, tenant_id=target.tenant_id)


__all__ = ["router"]
