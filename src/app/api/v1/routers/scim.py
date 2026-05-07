"""SCIM 2.0 server endpoints (Users only — Groups deferred).

Mounted at ``/scim/v2`` (NOT under ``/api/v1`` — SCIM clients expect a
spec-conformant URL hierarchy).

  GET    /scim/v2/Users                    — list (with optional ?filter=)
  GET    /scim/v2/Users/{id}
  POST   /scim/v2/Users                    — create
  PUT    /scim/v2/Users/{id}               — full replacement
  PATCH  /scim/v2/Users/{id}               — partial (active toggle minimum)
  DELETE /scim/v2/Users/{id}               — soft delete (is_active=False)
  GET    /scim/v2/ServiceProviderConfig
  GET    /scim/v2/ResourceTypes
  GET    /scim/v2/Schemas

Auth: bearer token issued via ``/api/v1/admin/scim/tokens`` (see
``admin_scim.py``). Scopes:
  - ``users:read``  — required for GET endpoints
  - ``users:write`` — required for POST / PUT / PATCH / DELETE

All write endpoints emit ``scim.user.{created,updated,deleted}`` audit
events.
"""

from __future__ import annotations

import logging
import secrets
import uuid as _uuid
from datetime import datetime, timezone
from typing import Optional, Tuple

from fastapi import (
    APIRouter,
    Body,
    Depends,
    Path,
    Query,
    Request,
    status,
)
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.auth.scim.auth import require_scope
from app.infrastructure.auth.scim.filter import (
    ScimFilterClause,
    UnsupportedScimFilter,
    parse_filter,
)
from app.infrastructure.auth.scim.schema import (
    SCHEMA_ERROR,
    SCHEMA_USER,
    ScimEmail,
    ScimError,
    ScimListResponse,
    ScimMeta,
    ScimPatchRequest,
    ScimUser,
)
from app.infrastructure.auth.sso import audit
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db


logger = logging.getLogger(__name__)


router = APIRouter(prefix="/scim/v2", tags=["SCIM 2.0"])


EVENT_SCIM_USER_CREATED = "scim.user.created"
EVENT_SCIM_USER_UPDATED = "scim.user.updated"
EVENT_SCIM_USER_DEACTIVATED = "scim.user.deactivated"
EVENT_SCIM_USER_DELETED = "scim.user.deleted"


# ----- Helpers ---------------------------------------------------------------


def _scim_error(status_code: int, detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=ScimError(detail=detail, status=str(status_code)).model_dump(
            exclude_none=True
        ),
        media_type="application/scim+json",
    )


def _user_to_scim(user: db_models.User) -> ScimUser:
    return ScimUser(
        id=str(user.id),
        userName=user.email,
        active=user.is_active,
        emails=[ScimEmail(value=user.email, primary=True, type="work")],
        meta=ScimMeta(resourceType="User"),
    )


def _apply_clause_to_query(query, clause: Optional[ScimFilterClause]):
    if clause is None:
        return query
    if clause.attribute in ("userName", "emails.value"):
        if not isinstance(clause.value, str):
            raise UnsupportedScimFilter("expected string for userName / emails.value")
        return query.where(db_models.User.email == clause.value.strip().lower())
    if clause.attribute == "active":
        return query.where(db_models.User.is_active == bool(clause.value))
    raise UnsupportedScimFilter(f"unsupported attribute: {clause.attribute}")


# ----- Discovery endpoints (RFC 7644 §4) -------------------------------------


@router.get("/ServiceProviderConfig")
async def service_provider_config() -> dict:
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "https://docs.sccap.dev/api-reference/",
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 200},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "Admin-issued bearer token (scim_…)",
                "primary": True,
            }
        ],
        "meta": {"resourceType": "ServiceProviderConfig"},
    }


@router.get("/ResourceTypes")
async def resource_types() -> dict:
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 1,
        "Resources": [
            {
                "id": "User",
                "name": "User",
                "endpoint": "/Users",
                "description": "User Account",
                "schema": SCHEMA_USER,
            }
        ],
    }


@router.get("/Schemas")
async def schemas() -> dict:
    """Minimal schema discovery — full SCIM Schemas are huge and rarely
    consumed by IdPs that already know the spec. Return the canonical
    User schema id."""
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 1,
        "Resources": [
            {
                "id": SCHEMA_USER,
                "name": "User",
                "description": "SCIM User schema",
                "attributes": [
                    {"name": "userName", "type": "string", "required": True},
                    {"name": "active", "type": "boolean"},
                    {"name": "emails", "type": "complex", "multiValued": True},
                ],
            }
        ],
    }


# ----- /Users endpoints ------------------------------------------------------


@router.get("/Users")
async def list_users(
    request: Request,
    filter: Optional[str] = Query(default=None, max_length=512, alias="filter"),
    startIndex: int = Query(default=1, ge=1, le=10_000_000),
    count: int = Query(default=100, ge=0, le=200),
    db: AsyncSession = Depends(get_db),
    _token: Tuple[db_models.ScimToken, list] = Depends(require_scope("users:read")),
):
    try:
        clause = parse_filter(filter)
    except UnsupportedScimFilter as exc:
        return _scim_error(400, str(exc))

    base_q = select(db_models.User)
    try:
        base_q = _apply_clause_to_query(base_q, clause)
    except UnsupportedScimFilter as exc:
        return _scim_error(400, str(exc))

    # Total count for ListResponse.totalResults.
    count_q = select(func.count()).select_from(base_q.subquery())
    total = (await db.execute(count_q)).scalar_one()

    users_q = base_q.order_by(db_models.User.id).offset(startIndex - 1).limit(count)
    users = list((await db.execute(users_q)).scalars().all())

    body = ScimListResponse(
        totalResults=int(total),
        startIndex=startIndex,
        itemsPerPage=len(users),
        Resources=[_user_to_scim(u) for u in users],
    )
    return JSONResponse(
        content=body.model_dump(exclude_none=True),
        media_type="application/scim+json",
    )


@router.get("/Users/{user_id}")
async def get_user(
    user_id: str = Path(...),
    db: AsyncSession = Depends(get_db),
    _token: Tuple[db_models.ScimToken, list] = Depends(require_scope("users:read")),
):
    try:
        uid = int(user_id)
    except ValueError:
        return _scim_error(400, "invalid user id")
    result = await db.execute(select(db_models.User).where(db_models.User.id == uid))
    user = result.scalar_one_or_none()
    if user is None:
        return _scim_error(404, "user not found")
    return JSONResponse(
        content=_user_to_scim(user).model_dump(exclude_none=True),
        media_type="application/scim+json",
    )


@router.post("/Users")
async def create_user(
    request: Request,
    payload: ScimUser = Body(...),
    db: AsyncSession = Depends(get_db),
    _token: Tuple[db_models.ScimToken, list] = Depends(require_scope("users:write")),
):
    """Create a SCIM-managed user. Maps userName → email. JIT-creates with
    a random sentinel password; the user must use the password-reset flow
    or SSO to log in (SCIM doesn't carry credentials)."""
    norm_email = payload.userName.strip().lower()
    if "@" not in norm_email:
        return _scim_error(400, "userName must look like an email address")

    existing = (
        await db.execute(
            select(db_models.User).where(db_models.User.email == norm_email)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return _scim_error(409, "user already exists")

    # JIT-create via the user-db layer (mirrors the SSO provisioning path)
    # so the password is hashed via fastapi-users' password helper.
    from app.infrastructure.auth.db import get_user_db
    from app.infrastructure.auth.manager import UserManager

    user_db_gen = get_user_db(db)
    user_db = await user_db_gen.__anext__()
    try:
        manager = UserManager(user_db)
        sentinel_password = secrets.token_urlsafe(64)
        user = await user_db.create(
            {
                "email": norm_email,
                "hashed_password": manager.password_helper.hash(sentinel_password),
                "is_active": payload.active,
                # NEVER set is_superuser via SCIM — admin elevation is a
                # separate flow.
                "is_superuser": False,
                "is_verified": True,
            }
        )
    finally:
        try:
            await user_db_gen.aclose()
        except Exception:
            pass

    await audit.record(
        db,
        event=EVENT_SCIM_USER_CREATED,
        user_id=user.id,
        request=request,
        details={"userName": norm_email, "active": payload.active},
    )
    await db.commit()

    body = _user_to_scim(user).model_dump(exclude_none=True)
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content=body,
        media_type="application/scim+json",
        headers={"Location": f"/scim/v2/Users/{user.id}"},
    )


@router.put("/Users/{user_id}")
async def replace_user(
    request: Request,
    user_id: str = Path(...),
    payload: ScimUser = Body(...),
    db: AsyncSession = Depends(get_db),
    _token: Tuple[db_models.ScimToken, list] = Depends(require_scope("users:write")),
):
    try:
        uid = int(user_id)
    except ValueError:
        return _scim_error(400, "invalid user id")
    result = await db.execute(select(db_models.User).where(db_models.User.id == uid))
    user = result.scalar_one_or_none()
    if user is None:
        return _scim_error(404, "user not found")

    # Email change: only if it doesn't collide.
    new_email = payload.userName.strip().lower()
    if new_email != user.email:
        clash = (
            await db.execute(
                select(db_models.User).where(db_models.User.email == new_email)
            )
        ).scalar_one_or_none()
        if clash is not None:
            return _scim_error(409, "another user already has that userName")
        user.email = new_email

    # is_superuser is NEVER touched by SCIM.
    user.is_active = payload.active

    await audit.record(
        db,
        event=EVENT_SCIM_USER_UPDATED,
        user_id=user.id,
        request=request,
        details={"userName": user.email, "active": user.is_active},
    )
    await db.commit()
    return JSONResponse(
        content=_user_to_scim(user).model_dump(exclude_none=True),
        media_type="application/scim+json",
    )


@router.patch("/Users/{user_id}")
async def patch_user(
    request: Request,
    user_id: str = Path(...),
    payload: ScimPatchRequest = Body(...),
    db: AsyncSession = Depends(get_db),
    _token: Tuple[db_models.ScimToken, list] = Depends(require_scope("users:write")),
):
    """Minimal PATCH support — only ``replace`` on ``active``. Everything
    else returns 400; the IdP can fall back to PUT for full replacement."""
    try:
        uid = int(user_id)
    except ValueError:
        return _scim_error(400, "invalid user id")
    result = await db.execute(select(db_models.User).where(db_models.User.id == uid))
    user = result.scalar_one_or_none()
    if user is None:
        return _scim_error(404, "user not found")

    handled = False
    for op_obj in payload.Operations:
        op = (op_obj.op or "").lower()
        path = (op_obj.path or "").strip()
        if op == "replace" and path.lower() == "active":
            new_active = bool(op_obj.value)
            user.is_active = new_active
            handled = True
        else:
            return _scim_error(
                400, f"PATCH op={op!r} path={path!r} not supported (use PUT)"
            )

    if not handled:
        return _scim_error(400, "no supported PATCH operation in request")

    await audit.record(
        db,
        event=EVENT_SCIM_USER_UPDATED,
        user_id=user.id,
        request=request,
        details={"path": "active", "active": user.is_active},
    )
    await db.commit()
    return JSONResponse(
        content=_user_to_scim(user).model_dump(exclude_none=True),
        media_type="application/scim+json",
    )


@router.delete("/Users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    request: Request,
    user_id: str = Path(...),
    db: AsyncSession = Depends(get_db),
    _token: Tuple[db_models.ScimToken, list] = Depends(require_scope("users:write")),
):
    """SOFT delete: set is_active=False. SCIM expects 204 on success.

    Hard-delete is intentionally not supported via SCIM — too easy for a
    misconfigured IdP to nuke the SCCAP user table. Admins use the
    user-management UI for irreversible deletion."""
    try:
        uid = int(user_id)
    except ValueError:
        return _scim_error(400, "invalid user id")
    result = await db.execute(select(db_models.User).where(db_models.User.id == uid))
    user = result.scalar_one_or_none()
    if user is None:
        return _scim_error(404, "user not found")

    # M6 protection: SCIM cannot deactivate the master admin.
    from app.core.config_cache import SystemConfigCache

    if SystemConfigCache.get_master_admin_user_id() == user.id:
        return _scim_error(
            403,
            "the master admin cannot be deactivated via SCIM "
            "(use the admin user-management UI instead)",
        )

    user.is_active = False
    await audit.record(
        db,
        event=EVENT_SCIM_USER_DEACTIVATED,
        user_id=user.id,
        request=request,
        details={"userName": user.email},
    )
    await db.commit()
    # SCIM spec: 204 No Content (no body).
    return JSONResponse(status_code=status.HTTP_204_NO_CONTENT, content=None)


# Avoid unused-import warnings.
_ = (datetime, timezone, _uuid, SCHEMA_ERROR)
