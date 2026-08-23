import logging
import secrets
import string
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, EmailStr
import sqlalchemy as sa
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import get_current_user_tenant_id, require_permission
from app.infrastructure.auth.core import current_active_user
from app.infrastructure.auth.manager import UserManager, get_user_manager
from app.infrastructure.database.models import RoleAssignment, User
from app.infrastructure.auth.sso import audit
from app.infrastructure.database.repositories.auth_session_repo import (
    AuthSessionRepository,
)
from app.shared.lib.permissions import ANALYST, IDENTITY_MANAGE, IDENTITY_READ

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["Admin: Users"])


class AdminUserRead(BaseModel):
    """UserRead variant that exposes is_verified — for admin-only endpoints."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    is_active: bool
    is_superuser: bool
    is_verified: bool
    role_keys: List[str]


class AdminUserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    is_active: bool = True
    is_superuser: bool = False
    is_verified: bool = False


class AdminUserUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_active: Optional[bool] = None
    is_superuser: Optional[bool] = None
    is_verified: Optional[bool] = None


async def _get_master_admin_id(session: AsyncSession) -> int:
    """Return the id of the master admin (force-SSO escape hatch).

    Reads the cached constant persisted at first-user bootstrap (M6 — see
    `setup.py` and `core.config_cache.SystemConfigCache.master_admin_user_id`).
    Falls back to a one-shot DB read against `system_config` if the cache
    isn't populated (e.g. a worker process that hasn't loaded it yet) — but
    NEVER falls back to `MIN(users.id)`, which would silently transfer
    delete/demote protection to the next-oldest user if the master admin
    were ever deleted out-of-band (the threat-model M6 abuse case).
    """
    from app.core.config_cache import SystemConfigCache

    cached = SystemConfigCache.get_master_admin_user_id()
    if cached is not None:
        return int(cached)
    # Cache miss — try the persisted system_config row directly.
    result = await session.execute(
        sa.text(
            "SELECT (value->>'user_id')::int FROM system_configurations "
            "WHERE key = 'security.master_admin_user_id'"
        )
    )
    row_value = result.scalar_one_or_none()
    if row_value is not None:
        SystemConfigCache.set_master_admin_user_id(int(row_value))
        return int(row_value)
    # No cached value, no persisted row: reject the operation rather than
    # quietly fall back. This is a deployment misconfiguration.
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=(
            "master_admin_user_id is not initialised; "
            "run /setup or backfill security.master_admin_user_id"
        ),
    )


async def _role_keys_for_users(
    session: AsyncSession,
    *,
    user_ids: list[int],
    tenant_id: uuid.UUID,
) -> dict[int, list[str]]:
    if not user_ids:
        return {}
    rows = (
        await session.execute(
            select(RoleAssignment.user_id, RoleAssignment.role_key)
            .where(
                RoleAssignment.user_id.in_(user_ids),
                sa.or_(
                    RoleAssignment.tenant_id == tenant_id,
                    RoleAssignment.tenant_id.is_(None),
                ),
            )
            .order_by(RoleAssignment.role_key)
        )
    ).all()
    result: dict[int, list[str]] = {user_id: [] for user_id in user_ids}
    for user_id, role_key in rows:
        result[int(user_id)].append(str(role_key))
    return result


def _to_admin_read(user: User, role_keys: list[str]) -> AdminUserRead:
    return AdminUserRead(
        id=user.id,
        email=user.email,
        is_active=user.is_active,
        is_superuser=user.is_superuser,
        is_verified=user.is_verified,
        role_keys=role_keys,
    )


@router.post(
    "/users",
    response_model=AdminUserRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(IDENTITY_MANAGE))],
)
async def admin_create_user(
    user_in: AdminUserCreate,
    acting_user: User = Depends(current_active_user),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user_manager: UserManager = Depends(get_user_manager),
):
    """
    Creates a new user and sends them a password setup email.
    Creates a least-privilege analyst in the caller's active tenant.
    """
    if user_in.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Platform ownership cannot be granted through tenant user creation.",
        )
    logger.info("admin.users.create_attempt")

    # Generate a strong, random placeholder password
    alphabet = string.ascii_letters + string.digits + string.punctuation
    placeholder_password = "".join(secrets.choice(alphabet) for i in range(32))

    try:
        session = user_manager.user_db.session
        try:
            created_user = await user_manager.user_db.create(
                {
                    "email": str(user_in.email).lower(),
                    "hashed_password": user_manager.password_helper.hash(
                        placeholder_password
                    ),
                    "is_active": user_in.is_active,
                    "is_superuser": False,
                    "is_verified": user_in.is_verified,
                    "tenant_id": tenant_id,
                }
            )
            session.add(
                RoleAssignment(
                    user_id=created_user.id,
                    tenant_id=tenant_id,
                    role_key=ANALYST,
                    created_by_user_id=acting_user.id,
                )
            )
            await session.commit()
        except IntegrityError:
            await session.rollback()
            # TOCTOU backstop: concurrent request with same email hit the DB unique constraint
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email already exists.",
            )

        # Trigger the forgot password flow to send the setup email
        await user_manager.forgot_password(created_user)

        logger.info(
            "admin.users.created",
            extra={
                "user_id": str(created_user.id),
                "is_superuser": False,
                "is_active": user_in.is_active,
            },
        )
        return _to_admin_read(created_user, [ANALYST])

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(
            "admin.users.create_failed",
            extra={"error_type": type(e).__name__},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while creating the user.",
        )


@router.get(
    "/users",
    response_model=List[AdminUserRead],
    dependencies=[Depends(require_permission(IDENTITY_READ))],
)
async def admin_list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user_manager: UserManager = Depends(get_user_manager),
):
    """
    List users in the caller's active tenant with pagination.
    Requires tenant identity-read permission.
    Results are paginated via skip/limit parameters (default: skip=0, limit=100, max limit=1000).
    """
    users = []
    # NOTE: fastapi-users' generic user_db has no list helper, so we bypass to raw SQLAlchemy
    # here. This is the ONLY place in this module where that bypass is intentional and allowed.
    # The session is obtained from user_manager.user_db.session as provided by the dependency.
    try:
        result = await user_manager.user_db.session.execute(
            select(User)
            .where(User.tenant_id == tenant_id)
            .order_by(User.id)
            .offset(skip)
            .limit(limit)
        )
        users = list(result.scalars().all())
        role_keys = await _role_keys_for_users(
            user_manager.user_db.session,
            user_ids=[user.id for user in users],
            tenant_id=tenant_id,
        )
        logger.info("admin.users.listed", extra={"result_count": len(users)})
    except Exception:
        logger.exception("admin.users.list_failed")
        raise HTTPException(status_code=500, detail="Could not retrieve users")
    return [_to_admin_read(user, role_keys[user.id]) for user in users]


@router.patch(
    "/users/{user_id}",
    response_model=AdminUserRead,
    dependencies=[Depends(require_permission(IDENTITY_MANAGE))],
)
async def admin_update_user(
    request: Request,
    user_id: int,
    update: AdminUserUpdate,
    acting_user: User = Depends(current_active_user),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user_manager: UserManager = Depends(get_user_manager),
):
    """
    Update a tenant user's active and verified flags.
    Legacy superuser state is visible for compatibility but cannot be changed here.
    """
    session = user_manager.user_db.session
    result = await session.execute(
        select(User).where(User.id == user_id, User.tenant_id == tenant_id)
    )
    target = result.scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="User not found.")

    if (
        update.is_superuser is not None
        and update.is_superuser != target.is_superuser
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Legacy superuser state cannot be changed through tenant administration.",
        )

    was_active = target.is_active
    if update.is_active is not None:
        target.is_active = update.is_active
    if update.is_verified is not None:
        target.is_verified = update.is_verified

    if was_active and update.is_active is False:
        revoked = await AuthSessionRepository(session).revoke_all_for_user(
            target.id,
            reason="admin_deactivated_user",
        )
        await audit.record(
            session,
            event="session.revoked_all",
            user_id=target.id,
            actor_user_id=acting_user.id,
            tenant_id=target.tenant_id,
            outcome="success",
            request=request,
            details={
                "reason": "admin_deactivated_user",
                "revoked_count": revoked,
            },
        )

    await session.commit()
    await session.refresh(target)
    role_keys = await _role_keys_for_users(
        session,
        user_ids=[target.id],
        tenant_id=tenant_id,
    )

    logger.info(
        "admin.users.updated",
        extra={
            "target_user_id": user_id,
            "acting_user_id": acting_user.id,
            "changes": update.model_dump(exclude_none=True),
        },
    )
    return _to_admin_read(target, role_keys[target.id])


@router.delete(
    "/users/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission(IDENTITY_MANAGE))],
)
async def admin_delete_user(
    request: Request,
    user_id: int,
    acting_user: User = Depends(current_active_user),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user_manager: UserManager = Depends(get_user_manager),
):
    """
    Delete a user account in the caller's active tenant.
    Requires tenant identity-manage permission.
    The master admin (first-created user) and the acting user themselves cannot be deleted.
    """
    session = user_manager.user_db.session
    result = await session.execute(
        select(User).where(User.id == user_id, User.tenant_id == tenant_id)
    )
    target = result.scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="User not found.")

    # Block self-deletion
    if target.id == acting_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot delete your own account.",
        )

    # Block deletion of the master admin (first-created user)
    master_id = await _get_master_admin_id(session)
    if target.id == master_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The master admin account cannot be deleted.",
        )

    revoked = await AuthSessionRepository(session).revoke_all_for_user(
        target.id,
        reason="admin_deleted_user",
    )
    await audit.record(
        session,
        event="session.revoked_all",
        user_id=target.id,
        actor_user_id=acting_user.id,
        tenant_id=target.tenant_id,
        outcome="success",
        request=request,
        details={"reason": "admin_deleted_user", "revoked_count": revoked},
    )
    await session.delete(target)
    await session.commit()

    logger.info(
        "admin.users.deleted",
        extra={"target_user_id": user_id, "acting_user_id": acting_user.id},
    )
