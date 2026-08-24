# src/app/api/v1/routers/admin_groups.py
"""Tenant-scoped CRUD for user groups + memberships.

Path prefix `/admin/user-groups`. Tenant administrators manage every group in
their active tenant; a group membership with role ``owner`` manages only that
group and never grants tenant-administration authority.

Data protection
---------------
``MemberRead.email`` and ``MemberAdd.email`` are PII (classification:
internal-personal).  Log lines emitted by this module MUST NOT contain
raw email addresses — use only hashed or redacted representations (see
``hashlib.sha256`` pattern in ``add_member``).  Emails SHOULD be
deleted within a reasonable retention window after membership is removed
via the ``remove_member`` path.  See the project log-redaction policy
for full V14.1.2 compliance requirements.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from typing import List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Response, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.auth.core import current_active_user
from app.api.v1.dependencies import (
    get_current_permissions,
    get_current_user_tenant_id,
    require_permission,
)
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db
from app.infrastructure.database.repositories.user_group_repo import (
    UserGroupRepository,
)
from app.shared.lib.permissions import GROUP_MANAGE

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/user-groups", tags=["Admin: User Groups"])

# Business limits (V02.3.2) — prevent unbounded resource creation.
MAX_USER_GROUPS = 1000
MAX_MEMBERS_PER_GROUP = 5000


# --- Schemas -------------------------------------------------------------


class MemberRead(BaseModel):
    user_id: int
    # PII: classification=internal-personal; retain only while membership active; redact in logs
    email: str
    role: str


class UserGroupRead(BaseModel):
    id: uuid.UUID
    name: str
    description: Optional[str] = None
    created_by: int
    member_count: int
    members: List[MemberRead] = Field(default_factory=list)
    # V02.3.4 — exposes the row's current version so the client can pass it
    # back in a subsequent UserGroupUpdate as `expected_version`.
    version: int = 1


class UserGroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: Optional[str] = None


class UserGroupUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    description: Optional[str] = None
    # V02.3.4 — caller-supplied row version. Optional; when omitted the legacy
    # unsafe-overwrite path is used.
    expected_version: Optional[int] = Field(default=None, ge=1)


class MemberAdd(BaseModel):
    # PII: classification=internal-personal; retain only while membership active; redact in logs
    email: EmailStr
    role: str = Field(default="member", pattern="^(member|owner)$")


# --- Helpers -------------------------------------------------------------


def _repo(db: AsyncSession = Depends(get_db)) -> UserGroupRepository:
    return UserGroupRepository(db)


async def _hydrate(
    group: db_models.UserGroup,
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
) -> UserGroupRead:
    # Batch-fetch emails for all members so UI can render them without a
    # per-row round-trip.
    user_ids = [m.user_id for m in (group.memberships or [])]
    email_by_id: dict[int, str] = {}
    if user_ids:
        rows = await db.execute(
            select(db_models.User.id, db_models.User.email).where(
                db_models.User.id.in_(user_ids),
                db_models.User.tenant_id == tenant_id,
            )
        )
        email_by_id = {uid: email for uid, email in rows.all()}

    members = [
        MemberRead(
            user_id=m.user_id,
            email=email_by_id.get(m.user_id, "(unknown)"),
            role=m.role,
        )
        for m in (group.memberships or [])
    ]
    return UserGroupRead(
        id=group.id,
        name=group.name,
        description=group.description,
        created_by=group.created_by,
        member_count=len(members),
        members=members,
        version=getattr(group, "version", 1),
    )


async def _require_manageable_group(
    *,
    group_id: uuid.UUID,
    user: db_models.User,
    permissions: frozenset[str],
    tenant_id: uuid.UUID,
    repo: UserGroupRepository,
) -> db_models.UserGroup:
    group = await repo.get_group(group_id, tenant_id=tenant_id)
    if group is None:
        raise HTTPException(status_code=404, detail="Group not found.")
    if GROUP_MANAGE not in permissions and not await repo.is_group_owner(
        group_id=group_id,
        user_id=user.id,
        tenant_id=tenant_id,
    ):
        raise HTTPException(status_code=404, detail="Group not found.")
    return group


# --- Endpoints -----------------------------------------------------------


@router.get("", response_model=List[UserGroupRead])
async def list_groups(
    user: db_models.User = Depends(current_active_user),
    permissions: frozenset[str] = Depends(get_current_permissions),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    repo: UserGroupRepository = Depends(_repo),
    db: AsyncSession = Depends(get_db),
) -> List[UserGroupRead]:
    if GROUP_MANAGE in permissions:
        groups = await repo.list_groups(tenant_id=tenant_id)
    else:
        groups = await repo.list_groups_for_user(
            user.id,
            tenant_id=tenant_id,
            owner_only=True,
        )
    return [await _hydrate(g, db, tenant_id=tenant_id) for g in groups]


@router.post(
    "",
    response_model=UserGroupRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(GROUP_MANAGE))],
)
async def create_group(
    payload: UserGroupCreate = Body(...),
    user: db_models.User = Depends(current_active_user),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    repo: UserGroupRepository = Depends(_repo),
    db: AsyncSession = Depends(get_db),
) -> UserGroupRead:
    existing = await repo.list_groups(tenant_id=tenant_id)
    if len(existing) >= MAX_USER_GROUPS:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Maximum number of user groups has been reached.",
        )
    try:
        group = await repo.create_group(
            name=payload.name,
            description=payload.description,
            created_by=user.id,
            tenant_id=tenant_id,
        )
    except Exception as e:
        # Most likely: unique violation on `name`.
        logger.warning("Group create failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A group with that name already exists.",
        )
    # Reload with memberships relationship hydrated.
    fresh = await repo.get_group(group.id, tenant_id=tenant_id)
    assert fresh is not None
    logger.info(
        "admin.group.created",
        extra={
            "actor_id": user.id,
            "group_id": str(group.id),
            "group_name": payload.name,
        },
    )
    return await _hydrate(fresh, db, tenant_id=tenant_id)


@router.patch("/{group_id}", response_model=UserGroupRead)
async def update_group(
    group_id: uuid.UUID,
    payload: UserGroupUpdate = Body(...),
    user: db_models.User = Depends(current_active_user),
    permissions: frozenset[str] = Depends(get_current_permissions),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    repo: UserGroupRepository = Depends(_repo),
    db: AsyncSession = Depends(get_db),
) -> UserGroupRead:
    from app.shared.lib.optimistic_lock import OptimisticLockError

    await _require_manageable_group(
        group_id=group_id,
        user=user,
        permissions=permissions,
        tenant_id=tenant_id,
        repo=repo,
    )
    try:
        group = await repo.update_group(
            group_id,
            tenant_id=tenant_id,
            name=payload.name,
            description=payload.description,
            expected_version=payload.expected_version,
        )
    except OptimisticLockError as e:
        # V02.3.4 — surface the conflict so the frontend can refetch + retry.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "version_mismatch",
                "current_version": e.current_version,
            },
        )
    if group is None:
        raise HTTPException(status_code=404, detail="Group not found.")
    logger.info(
        "admin.group.updated",
        extra={"actor_id": user.id, "group_id": str(group_id)},
    )
    fresh = await repo.get_group(group.id, tenant_id=tenant_id)
    assert fresh is not None
    return await _hydrate(fresh, db, tenant_id=tenant_id)


@router.delete(
    "/{group_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
async def delete_group(
    group_id: uuid.UUID,
    user: db_models.User = Depends(current_active_user),
    permissions: frozenset[str] = Depends(get_current_permissions),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    repo: UserGroupRepository = Depends(_repo),
) -> Response:
    await _require_manageable_group(
        group_id=group_id,
        user=user,
        permissions=permissions,
        tenant_id=tenant_id,
        repo=repo,
    )
    ok = await repo.delete_group(group_id, tenant_id=tenant_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Group not found.")
    logger.info(
        "admin.group.deleted",
        extra={"actor_id": user.id, "group_id": str(group_id)},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{group_id}/members", response_model=UserGroupRead)
async def add_member(
    group_id: uuid.UUID,
    payload: MemberAdd = Body(...),
    actor: db_models.User = Depends(current_active_user),
    permissions: frozenset[str] = Depends(get_current_permissions),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    repo: UserGroupRepository = Depends(_repo),
    db: AsyncSession = Depends(get_db),
) -> UserGroupRead:
    group = await _require_manageable_group(
        group_id=group_id,
        user=actor,
        permissions=permissions,
        tenant_id=tenant_id,
        repo=repo,
    )

    if len(group.memberships or []) >= MAX_MEMBERS_PER_GROUP:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Group has reached the maximum allowed members.",
        )

    # Resolve email → user_id. We intentionally don't expose enumeration:
    # if the user doesn't exist we return 404 without distinguishing from
    # "group not found".
    result = await db.execute(
        select(db_models.User).where(
            db_models.User.email == payload.email,
            db_models.User.tenant_id == tenant_id,
        )
    )
    user = result.scalars().first()
    if user is None:
        logger.warning(
            "admin.group.add_member_failed",
            extra={
                "actor_id": actor.id,
                "email_hash": hashlib.sha256(payload.email.encode()).hexdigest()[:16],
            },
        )
        raise HTTPException(
            status_code=404, detail="User with that email does not exist."
        )

    await repo.add_member(
        group_id,
        user.id,
        tenant_id=tenant_id,
        role=payload.role,
    )
    logger.info(
        "admin.group.member_added",
        extra={
            "actor_id": actor.id,
            "group_id": str(group_id),
            "user_id": user.id,
            "role": payload.role,
        },
    )
    fresh = await repo.get_group(group_id, tenant_id=tenant_id)
    assert fresh is not None
    return await _hydrate(fresh, db, tenant_id=tenant_id)


@router.delete(
    "/{group_id}/members/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
async def remove_member(
    group_id: uuid.UUID,
    user_id: int,
    actor: db_models.User = Depends(current_active_user),
    permissions: frozenset[str] = Depends(get_current_permissions),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    repo: UserGroupRepository = Depends(_repo),
) -> Response:
    await _require_manageable_group(
        group_id=group_id,
        user=actor,
        permissions=permissions,
        tenant_id=tenant_id,
        repo=repo,
    )
    ok = await repo.remove_member(
        group_id,
        user_id,
        tenant_id=tenant_id,
    )
    if not ok:
        raise HTTPException(status_code=404, detail="Membership not found.")
    logger.info(
        "admin.group.member_removed",
        extra={"actor_id": actor.id, "group_id": str(group_id), "user_id": user_id},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
