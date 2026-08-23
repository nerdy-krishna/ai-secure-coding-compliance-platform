"""Tenant-scoped browser-session inventory and revocation APIs."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.auth.backend import (
    get_custom_cookie_jwt_strategy,
    mark_auth_response_no_store,
)
from app.infrastructure.auth.core import current_active_user, current_superuser
from app.infrastructure.auth.session import SessionError, decode_session_credential
from app.infrastructure.auth.sso import audit
from app.infrastructure.database.database import get_db
from app.infrastructure.database.models import AuthSession, User
from app.infrastructure.database.repositories.auth_session_repo import (
    AuthSessionRepository,
)


router = APIRouter()


class AuthSessionRead(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID
    current: bool
    auth_method: str
    assurance_level: str
    device_label: str | None
    network_observed: bool
    authenticated_at: datetime
    last_seen_at: datetime
    idle_expires_at: datetime
    absolute_expires_at: datetime


class RevocationResult(BaseModel):
    revoked: int


def _request_session_id(request: Request) -> uuid.UUID | None:
    strategy = get_custom_cookie_jwt_strategy()
    credential = request.cookies.get(strategy.browser_session_cookie_name)
    if not credential:
        return None
    try:
        return decode_session_credential(credential).session_id
    except SessionError:
        return None


def _to_read(row: AuthSession, current_session_id: uuid.UUID | None) -> AuthSessionRead:
    return AuthSessionRead(
        id=row.id,
        current=row.id == current_session_id,
        auth_method=row.auth_method,
        assurance_level=row.assurance_level,
        device_label=row.device_label,
        network_observed=row.ip_hash is not None,
        authenticated_at=row.authenticated_at,
        last_seen_at=row.last_seen_at,
        idle_expires_at=row.idle_expires_at,
        absolute_expires_at=row.absolute_expires_at,
    )


async def _clear_current_session(response: Response) -> None:
    strategy = get_custom_cookie_jwt_strategy()
    await strategy.destroy_refresh_token(response)
    await strategy.destroy_browser_session(response)
    response.headers["Clear-Site-Data"] = '"cache", "cookies", "storage"'
    mark_auth_response_no_store(response)


async def _tenant_scoped_target(
    db: AsyncSession,
    actor: User,
    user_id: int,
) -> User:
    target = await db.get(User, user_id)
    # Issue 17 introduces a distinct cross-tenant system-admin permission. Until
    # then, even a superuser session-admin action is confined to its tenant.
    if target is None or target.tenant_id != actor.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return target


@router.get("/auth/sessions", response_model=list[AuthSessionRead])
async def list_own_sessions(
    request: Request,
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db),
) -> list[AuthSessionRead]:
    rows = await AuthSessionRepository(db).list_for_user(user.id)
    current_session_id = _request_session_id(request)
    await audit.record(
        db,
        event="session.inventory.viewed",
        user_id=user.id,
        actor_user_id=user.id,
        tenant_id=user.tenant_id,
        outcome="success",
        request=request,
        details={"result_count": len(rows)},
    )
    await db.commit()
    return [_to_read(row, current_session_id) for row in rows]


@router.delete("/auth/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_own_session(
    request: Request,
    session_id: uuid.UUID = Path(...),
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    repo = AuthSessionRepository(db)
    row = await repo.get_for_update(session_id)
    if row is None or row.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    changed = await repo.revoke(row, reason="user_revoked")
    await audit.record(
        db,
        event="session.revoked",
        user_id=user.id,
        actor_user_id=user.id,
        session_id=row.id,
        provider_id=row.provider_id,
        tenant_id=row.tenant_id,
        outcome="success" if changed else "no_op",
        request=request,
        details={"reason": "user_revoked"},
    )
    await db.commit()

    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    if session_id == _request_session_id(request):
        await _clear_current_session(response)
    return response


@router.post("/auth/sessions/revoke-others", response_model=RevocationResult)
async def revoke_other_sessions(
    request: Request,
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db),
) -> RevocationResult:
    current_session_id = _request_session_id(request)
    revoked = await AuthSessionRepository(db).revoke_all_for_user(
        user.id,
        reason="user_revoked_others",
        except_session_id=current_session_id,
    )
    await audit.record(
        db,
        event="session.revoked_others",
        user_id=user.id,
        actor_user_id=user.id,
        session_id=current_session_id,
        tenant_id=user.tenant_id,
        outcome="success",
        request=request,
        details={"revoked_count": revoked},
    )
    await db.commit()
    return RevocationResult(revoked=revoked)


@router.get(
    "/admin/users/{user_id}/sessions",
    response_model=list[AuthSessionRead],
)
async def admin_list_user_sessions(
    request: Request,
    user_id: int = Path(..., ge=1),
    actor: User = Depends(current_superuser),
    db: AsyncSession = Depends(get_db),
) -> list[AuthSessionRead]:
    target = await _tenant_scoped_target(db, actor, user_id)
    rows = await AuthSessionRepository(db).list_for_user(target.id)
    current_session_id = _request_session_id(request) if target.id == actor.id else None
    await audit.record(
        db,
        event="session.inventory.admin_viewed",
        user_id=target.id,
        actor_user_id=actor.id,
        tenant_id=target.tenant_id,
        outcome="success",
        request=request,
        details={"result_count": len(rows)},
    )
    await db.commit()
    return [_to_read(row, current_session_id) for row in rows]


@router.delete(
    "/admin/users/{user_id}/sessions/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def admin_revoke_user_session(
    request: Request,
    user_id: int = Path(..., ge=1),
    session_id: uuid.UUID = Path(...),
    actor: User = Depends(current_superuser),
    db: AsyncSession = Depends(get_db),
) -> Response:
    target = await _tenant_scoped_target(db, actor, user_id)
    repo = AuthSessionRepository(db)
    row = await repo.get_for_update(session_id)
    if row is None or row.user_id != target.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    changed = await repo.revoke(row, reason="admin_revoked")
    await audit.record(
        db,
        event="session.admin_revoked",
        user_id=target.id,
        actor_user_id=actor.id,
        session_id=row.id,
        provider_id=row.provider_id,
        tenant_id=target.tenant_id,
        outcome="success" if changed else "no_op",
        request=request,
        details={"reason": "admin_revoked"},
    )
    await db.commit()

    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    if actor.id == target.id and session_id == _request_session_id(request):
        await _clear_current_session(response)
    return response


@router.post(
    "/admin/users/{user_id}/sessions/revoke-all",
    response_model=RevocationResult,
)
async def admin_revoke_all_user_sessions(
    request: Request,
    user_id: int = Path(..., ge=1),
    actor: User = Depends(current_superuser),
    db: AsyncSession = Depends(get_db),
) -> Response | RevocationResult:
    target = await _tenant_scoped_target(db, actor, user_id)
    revoked = await AuthSessionRepository(db).revoke_all_for_user(
        target.id,
        reason="admin_revoked_all",
    )
    await audit.record(
        db,
        event="session.admin_revoked_all",
        user_id=target.id,
        actor_user_id=actor.id,
        tenant_id=target.tenant_id,
        outcome="success",
        request=request,
        details={"revoked_count": revoked},
    )
    await db.commit()
    if target.id == actor.id and _request_session_id(request) is not None:
        response = Response(
            content=RevocationResult(revoked=revoked).model_dump_json(),
            media_type="application/json",
        )
        await _clear_current_session(response)
        return response
    return RevocationResult(revoked=revoked)
