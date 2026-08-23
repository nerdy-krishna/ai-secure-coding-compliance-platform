import logging
import secrets
import string
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
import sqlalchemy as sa
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import (
    get_current_permissions,
    get_current_user_tenant_id,
    require_permission,
)
from app.api.v1.routers.authorization import ActionRequestRead, action_request_to_read
from app.infrastructure.auth.core import current_active_user
from app.infrastructure.auth.manager import UserManager, get_user_manager
from app.infrastructure.database.models import RoleAssignment, User
from app.infrastructure.auth.sso import audit
from app.infrastructure.database.repositories.auth_session_repo import (
    AuthSessionRepository,
)
from app.infrastructure.database.repositories.authorization_repo import (
    AuthorizationConflictError,
    AuthorizationDeniedError,
    AuthorizationRepository,
    payload_digest,
    target_fingerprint,
)
from app.shared.lib.permissions import (
    ANALYST,
    AUDITOR,
    DEVELOPER,
    IDENTITY_MANAGE,
    IDENTITY_READ,
    SECURITY_APPROVER,
    TENANT_ADMIN,
    permissions_for_roles,
)

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


TENANT_ROLE_KEYS = frozenset(
    {TENANT_ADMIN, SECURITY_APPROVER, ANALYST, DEVELOPER, AUDITOR}
)


class AdminUserRoleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role_keys: list[str] = Field(..., min_length=1, max_length=len(TENANT_ROLE_KEYS))
    action_request_id: uuid.UUID | None = None

    @field_validator("role_keys")
    @classmethod
    def validate_role_keys(cls, value: list[str]) -> list[str]:
        normalized = sorted(set(value))
        if len(normalized) != len(value):
            raise ValueError("role_keys must be unique")
        if not set(normalized).issubset(TENANT_ROLE_KEYS):
            raise ValueError("role_keys contains a non-tenant role")
        return normalized


class AdminUserRoleChangeRequestCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role_keys: list[str] = Field(..., min_length=1, max_length=len(TENANT_ROLE_KEYS))

    @field_validator("role_keys")
    @classmethod
    def validate_role_keys(cls, value: list[str]) -> list[str]:
        return AdminUserRoleUpdate.validate_role_keys(value)


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


async def _tenant_role_keys_for_user(
    session: AsyncSession, *, user_id: int, tenant_id: uuid.UUID
) -> list[str]:
    rows = await session.scalars(
        select(RoleAssignment.role_key)
        .where(
            RoleAssignment.user_id == user_id,
            RoleAssignment.tenant_id == tenant_id,
        )
        .order_by(RoleAssignment.role_key)
    )
    return [str(role_key) for role_key in rows.all()]


def _role_change_payload(role_keys: list[str]) -> dict[str, list[str]]:
    return {"role_keys": sorted(role_keys)}


def _role_change_fingerprint(*, tenant_id: uuid.UUID, user_id: int) -> str:
    return target_fingerprint(
        resource_type="user_role_assignment",
        target_id=f"{tenant_id}:{user_id}",
    )


def _is_privilege_elevation(*, current: list[str], desired: list[str]) -> bool:
    return not permissions_for_roles(desired).issubset(permissions_for_roles(current))


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


@router.post(
    "/users/{user_id}/role-change-requests",
    response_model=ActionRequestRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(IDENTITY_MANAGE))],
)
async def request_admin_user_role_change(
    user_id: int,
    payload: AdminUserRoleChangeRequestCreate,
    idempotency_key: str = Header(..., alias="X-Idempotency-Key", max_length=128),
    acting_user: User = Depends(current_active_user),
    permissions: frozenset[str] = Depends(get_current_permissions),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user_manager: UserManager = Depends(get_user_manager),
) -> ActionRequestRead:
    """Request distinct approval for an exact critical-mode privilege increase."""

    session = user_manager.user_db.session
    target = await session.scalar(
        select(User).where(User.id == user_id, User.tenant_id == tenant_id)
    )
    if target is None:
        raise HTTPException(status_code=404, detail="User not found.")

    repo = AuthorizationRepository(session)
    if await repo.separation_of_duties_mode(tenant_id=tenant_id) != "critical":
        raise HTTPException(
            status_code=409,
            detail="A distinct-actor request is only used in critical mode.",
        )
    current = await _tenant_role_keys_for_user(
        session, user_id=target.id, tenant_id=tenant_id
    )
    if not _is_privilege_elevation(current=current, desired=payload.role_keys):
        raise HTTPException(
            status_code=409,
            detail="The requested role change is not a privilege elevation.",
        )

    fingerprint = _role_change_fingerprint(tenant_id=tenant_id, user_id=target.id)
    try:
        action = await repo.create_action_request(
            tenant_id=tenant_id,
            requester_user_id=acting_user.id,
            requester_permission=IDENTITY_MANAGE,
            approver_permission=IDENTITY_MANAGE,
            target_type="user_role_change",
            target_fingerprint_value=fingerprint,
            payload_digest_value=payload_digest(_role_change_payload(payload.role_keys)),
            idempotency_key=idempotency_key,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
    except AuthorizationConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    repo.record_audit(
        tenant_id=tenant_id,
        principal_kind="human",
        principal_id=str(acting_user.id),
        permission=IDENTITY_MANAGE,
        resource_type="user_role_assignment",
        target_fingerprint_value=fingerprint,
        outcome="requested",
        reason_code="privilege_elevation_requested",
        action_request_id=action.id,
    )
    await session.commit()
    return action_request_to_read(
        action, actor_user_id=acting_user.id, permissions=permissions
    )


@router.patch(
    "/users/{user_id}/roles",
    response_model=AdminUserRead,
    dependencies=[Depends(require_permission(IDENTITY_MANAGE))],
)
async def admin_update_user_roles(
    user_id: int,
    payload: AdminUserRoleUpdate,
    acting_user: User = Depends(current_active_user),
    permissions: frozenset[str] = Depends(get_current_permissions),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user_manager: UserManager = Depends(get_user_manager),
) -> AdminUserRead:
    """Replace one tenant user's roles, enforcing critical-mode elevation SoD."""

    session = user_manager.user_db.session
    target = await session.scalar(
        select(User)
        .where(User.id == user_id, User.tenant_id == tenant_id)
        .with_for_update()
    )
    if target is None:
        raise HTTPException(status_code=404, detail="User not found.")

    current = await _tenant_role_keys_for_user(
        session, user_id=target.id, tenant_id=tenant_id
    )
    if current == payload.role_keys:
        effective = await _role_keys_for_users(
            session, user_ids=[target.id], tenant_id=tenant_id
        )
        return _to_admin_read(target, effective[target.id])

    repo = AuthorizationRepository(session)
    fingerprint = _role_change_fingerprint(tenant_id=tenant_id, user_id=target.id)
    requires_approval = (
        await repo.separation_of_duties_mode(tenant_id=tenant_id) == "critical"
        and _is_privilege_elevation(current=current, desired=payload.role_keys)
    )
    approver_id: int | None = None
    outcome = "allowed"
    reason_code = "tenant_roles_replaced"
    if requires_approval:
        if payload.action_request_id is None:
            raise HTTPException(
                status_code=409,
                detail="An approved distinct-actor action request is required.",
            )
        action = await repo.get_action_request(
            request_id=payload.action_request_id, tenant_id=tenant_id
        )
        if (
            action is None
            or action.requester_user_id != acting_user.id
            or action.target_type != "user_role_change"
            or action.target_fingerprint != fingerprint
        ):
            raise HTTPException(status_code=404, detail="Action request not found.")
        approver_permissions = await repo.permissions_for_user_id(
            user_id=action.approver_user_id or -1,
            tenant_id=tenant_id,
        )
        try:
            await repo.mark_executed(
                request_id=action.id,
                tenant_id=tenant_id,
                payload_digest_value=payload_digest(
                    _role_change_payload(payload.role_keys)
                ),
                requester_permissions=permissions,
                approver_permissions=approver_permissions,
            )
        except (AuthorizationConflictError, AuthorizationDeniedError) as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        approver_id = action.approver_user_id
        outcome = "executed"
        reason_code = "approved_privilege_elevation_executed"
    elif payload.action_request_id is not None:
        raise HTTPException(
            status_code=400,
            detail="An action request is not applicable to this role change.",
        )

    await session.execute(
        delete(RoleAssignment).where(
            RoleAssignment.user_id == target.id,
            RoleAssignment.tenant_id == tenant_id,
        )
    )
    session.add_all(
        RoleAssignment(
            user_id=target.id,
            tenant_id=tenant_id,
            role_key=role_key,
            created_by_user_id=acting_user.id,
        )
        for role_key in payload.role_keys
    )
    repo.record_audit(
        tenant_id=tenant_id,
        principal_kind="human",
        principal_id=str(acting_user.id),
        permission=IDENTITY_MANAGE,
        resource_type="user_role_assignment",
        target_fingerprint_value=fingerprint,
        outcome=outcome,
        reason_code=reason_code,
        action_request_id=payload.action_request_id,
        approver_principal_id=str(approver_id) if approver_id is not None else None,
    )
    await session.commit()
    logger.warning(
        "authorization.tenant_roles_replaced",
        extra={
            "actor_id": acting_user.id,
            "target_fingerprint": fingerprint,
            "approval_required": requires_approval,
        },
    )
    effective = await _role_keys_for_users(
        session, user_ids=[target.id], tenant_id=tenant_id
    )
    return _to_admin_read(target, effective[target.id])


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
