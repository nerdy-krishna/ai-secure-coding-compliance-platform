import logging
import secrets
import string
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, EmailStr
import sqlalchemy as sa
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.infrastructure.auth.core import current_superuser
from app.infrastructure.auth.manager import UserManager, get_user_manager
from app.infrastructure.database.models import User
from app.infrastructure.auth.schemas import UserRead

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


async def _get_master_admin_id(session) -> int:
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


@router.post(
    "/users",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(current_superuser)],
)
async def admin_create_user(
    user_in: AdminUserCreate,
    user_manager: UserManager = Depends(get_user_manager),
):
    """
    Creates a new user and sends them a password setup email.
    Accessible only to superusers.
    """
    logger.info("admin.users.create_attempt")
    # Check if user already exists
    try:
        existing_user = await user_manager.get_by_email(user_in.email)
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email already exists.",
            )
    except Exception:
        pass  # get_by_email might raise if not found

    # Generate a strong, random placeholder password
    alphabet = string.ascii_letters + string.digits + string.punctuation
    placeholder_password = "".join(secrets.choice(alphabet) for i in range(32))

    try:
        # We need a proper user dict for fastapi_users user_manager.create
        from app.infrastructure.auth.schemas import UserCreate

        create_schema = UserCreate(
            email=user_in.email,
            password=placeholder_password,
            is_active=user_in.is_active,
            is_superuser=user_in.is_superuser,
            is_verified=user_in.is_verified,
        )
        try:
            created_user = await user_manager.create(create_schema, safe=True)
        except IntegrityError:
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
                "is_superuser": user_in.is_superuser,
                "is_active": user_in.is_active,
            },
        )
        return created_user

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
    dependencies=[Depends(current_superuser)],
)
async def admin_list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    user_manager: UserManager = Depends(get_user_manager),
):
    """
    Lists all users with pagination.
    Accessible only to superusers.
    Results are paginated via skip/limit parameters (default: skip=0, limit=100, max limit=1000).
    """
    users = []
    # NOTE: fastapi-users' generic user_db has no list helper, so we bypass to raw SQLAlchemy
    # here. This is the ONLY place in this module where that bypass is intentional and allowed.
    # The session is obtained from user_manager.user_db.session as provided by the dependency.
    try:
        result = await user_manager.user_db.session.execute(
            select(User).order_by(User.id).offset(skip).limit(limit)
        )
        users = result.scalars().all()
        logger.info("admin.users.listed", extra={"result_count": len(users)})
    except Exception:
        logger.exception("admin.users.list_failed")
        raise HTTPException(status_code=500, detail="Could not retrieve users")
    return users


@router.patch(
    "/users/{user_id}",
    response_model=AdminUserRead,
    dependencies=[Depends(current_superuser)],
)
async def admin_update_user(
    user_id: int,
    update: AdminUserUpdate,
    acting_user: User = Depends(current_superuser),
    user_manager: UserManager = Depends(get_user_manager),
):
    """
    Update a user's active/verified/superuser flags.
    Accessible only to superusers.
    An admin cannot demote their own superuser status.
    """
    session = user_manager.user_db.session
    result = await session.execute(select(User).where(User.id == user_id))
    target = result.scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="User not found.")

    # Prevent self-demotion of superuser flag
    if update.is_superuser is False and target.id == acting_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot remove your own superuser status.",
        )

    if update.is_active is not None:
        target.is_active = update.is_active
    if update.is_superuser is not None:
        target.is_superuser = update.is_superuser
    if update.is_verified is not None:
        target.is_verified = update.is_verified

    await session.commit()
    await session.refresh(target)

    logger.info(
        "admin.users.updated",
        extra={
            "target_user_id": user_id,
            "acting_user_id": acting_user.id,
            "changes": update.model_dump(exclude_none=True),
        },
    )
    return target


@router.delete(
    "/users/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(current_superuser)],
)
async def admin_delete_user(
    user_id: int,
    acting_user: User = Depends(current_superuser),
    user_manager: UserManager = Depends(get_user_manager),
):
    """
    Delete a user account.
    Accessible only to superusers.
    The master admin (first-created user) and the acting user themselves cannot be deleted.
    """
    session = user_manager.user_db.session
    result = await session.execute(select(User).where(User.id == user_id))
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

    await session.delete(target)
    await session.commit()

    logger.info(
        "admin.users.deleted",
        extra={"target_user_id": user_id, "acting_user_id": acting_user.id},
    )
