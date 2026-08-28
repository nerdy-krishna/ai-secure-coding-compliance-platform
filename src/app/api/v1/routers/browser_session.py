"""Browser-session BFF endpoints.

These endpoints deliberately coexist with the bearer-token FastAPI Users
surface during the migration away from browser-managed access tokens.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.auth.backend import (
    get_custom_cookie_jwt_strategy,
    mark_auth_response_no_store,
)
from app.infrastructure.auth.core import current_active_user
from app.infrastructure.auth.schemas import UserRead
from app.infrastructure.auth.session import (
    BrowserSessionService,
    SessionError,
    issue_csrf_token,
)
from app.infrastructure.auth.sso import audit
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db
from app.infrastructure.database.models import User
from app.infrastructure.database.repositories.authorization_repo import (
    AuthorizationRepository,
)
from app.infrastructure.database.tenant_context import (
    DEFAULT_TENANT_ID,
    effective_tenant_id,
)
from app.shared.lib.permissions import PLATFORM_OWNER


router = APIRouter(prefix="/auth/session")


async def _current_session(
    request: Request,
    user: User,
    db: AsyncSession,
):
    strategy = get_custom_cookie_jwt_strategy()
    credential = request.cookies.get(strategy.browser_session_cookie_name)
    if not credential:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No browser session is active.",
        )
    try:
        session_row = await BrowserSessionService(db).authenticate(credential)
    except SessionError as exc:
        await db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED) from exc
    if session_row.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    return strategy, session_row


@router.get("/me", response_model=UserRead)
async def browser_session_me(
    request: Request,
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db),
) -> UserRead:
    repo = AuthorizationRepository(db)
    tenant_id = effective_tenant_id(user.tenant_id)
    role_keys = await repo.role_keys_for_user(user=user, tenant_id=tenant_id)
    permissions = await repo.permissions_for_user(user=user, tenant_id=tenant_id)
    active_tenant_id = tenant_id
    if PLATFORM_OWNER in role_keys:
        active_tenant_id = (
            getattr(request.state, "active_tenant_id", None) or DEFAULT_TENANT_ID
        )
    active_tenant = await db.get(db_models.Tenant, active_tenant_id)
    return UserRead.model_validate(user).model_copy(
        update={
            "role_keys": sorted(role_keys),
            "permissions": sorted(permissions),
            "active_tenant_id": active_tenant_id,
            "active_tenant_slug": active_tenant.slug if active_tenant else None,
            "active_tenant_display_name": (
                active_tenant.display_name if active_tenant else None
            ),
        }
    )


@router.get("/csrf")
async def browser_session_csrf(
    request: Request,
    response: Response,
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    _strategy, session_row = await _current_session(request, user, db)
    token = issue_csrf_token(session_row.id)
    response.headers["X-CSRF-Token"] = token
    response.headers["Access-Control-Expose-Headers"] = "X-CSRF-Token"
    mark_auth_response_no_store(response)
    await db.commit()
    return {"csrf_token": token}


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def browser_session_logout(
    request: Request,
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    strategy, session_row = await _current_session(request, user, db)
    await BrowserSessionService(db).repo.revoke(
        session_row,
        reason="user_logout",
    )
    await audit.record(
        db,
        event="session.revoked",
        user_id=user.id,
        actor_user_id=user.id,
        session_id=session_row.id,
        provider_id=session_row.provider_id,
        tenant_id=session_row.tenant_id,
        outcome="success",
        request=request,
        details={"reason": "user_logout"},
    )
    await db.commit()

    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    await strategy.destroy_refresh_token(response)
    await strategy.destroy_browser_session(response)
    response.headers["Clear-Site-Data"] = '"cache", "cookies", "storage"'
    mark_auth_response_no_store(response)
    return response
