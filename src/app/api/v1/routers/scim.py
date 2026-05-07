"""SCIM 2.0 server endpoints (Users + Groups).

Mounted at ``/scim/v2`` (NOT under ``/api/v1`` — SCIM clients expect a
spec-conformant URL hierarchy).

  GET    /scim/v2/Users                    — list (with optional ?filter=)
  GET    /scim/v2/Users/{id}
  POST   /scim/v2/Users                    — create
  PUT    /scim/v2/Users/{id}               — full replacement
  PATCH  /scim/v2/Users/{id}               — partial (active toggle minimum)
  DELETE /scim/v2/Users/{id}               — soft delete (is_active=False)

  GET    /scim/v2/Groups                   — list (with optional ?filter=)
  GET    /scim/v2/Groups/{id}
  POST   /scim/v2/Groups                   — create (with optional members)
  PUT    /scim/v2/Groups/{id}              — full replacement
  PATCH  /scim/v2/Groups/{id}              — add/remove members; rename
  DELETE /scim/v2/Groups/{id}              — hard delete (memberships cascade)

  GET    /scim/v2/ServiceProviderConfig
  GET    /scim/v2/ResourceTypes
  GET    /scim/v2/Schemas

Auth: bearer token issued via ``/api/v1/admin/scim/tokens`` (see
``admin_scim.py``). Scopes:
  - ``users:read``  — required for GET on /Users
  - ``users:write`` — required for write ops on /Users
  - ``groups:read`` — required for GET on /Groups
  - ``groups:write`` — required for write ops on /Groups

All write endpoints emit ``scim.{user,group}.{created,updated,deleted}``
audit events.
"""

from __future__ import annotations

import logging
import re as _re
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
    ScimFilterGroup,
    ScimFilterNode,
    UnsupportedScimFilter,
    parse_filter,
)
from app.infrastructure.auth.scim.schema import (
    SCHEMA_ERROR,
    SCHEMA_GROUP,
    SCHEMA_USER,
    ScimEmail,
    ScimError,
    ScimGroup,
    ScimGroupMember,
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
EVENT_SCIM_GROUP_CREATED = "scim.group.created"
EVENT_SCIM_GROUP_UPDATED = "scim.group.updated"
EVENT_SCIM_GROUP_DELETED = "scim.group.deleted"


# Okta-style PATCH path for member removal: members[value eq "<id>"]
_MEMBERS_VALUE_REMOVE = _re.compile(
    r'^members\[\s*value\s+eq\s+"([^"]+)"\s*\]\s*$',
    _re.IGNORECASE,
)


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


def _user_clause_to_sql(clause: ScimFilterClause):
    """Convert a single SCIM comparison on the User resource to a
    SQLAlchemy predicate. Each attribute defines its own column-binding
    plus the ops it actually supports; anything outside that vocabulary
    raises ``UnsupportedScimFilter`` (mapped to HTTP 400)."""
    attr = clause.attribute
    op = clause.op
    val = clause.value

    if attr in ("userName", "emails.value"):
        # Email comparisons are case-folded at both sides.
        col = func.lower(db_models.User.email)
        if op == "pr":
            return col.is_not(None)
        if not isinstance(val, str):
            raise UnsupportedScimFilter(
                f"expected string for {attr!r}, got {type(val).__name__}"
            )
        v = val.strip().lower()
        if op == "eq":
            return col == v
        if op == "ne":
            return col != v
        if op == "co":
            return col.contains(v)
        if op == "sw":
            return col.startswith(v)
        if op == "ew":
            return col.endswith(v)
        raise UnsupportedScimFilter(f"op {op!r} not supported on {attr!r}")

    if attr == "active":
        col = db_models.User.is_active
        if op == "pr":
            return col.is_not(None)
        if not isinstance(val, bool):
            raise UnsupportedScimFilter("expected bool for active")
        if op == "eq":
            return col == val
        if op == "ne":
            return col != val
        raise UnsupportedScimFilter(f"op {op!r} not supported on active")

    raise UnsupportedScimFilter(f"unsupported User attribute: {attr}")


def _node_to_sql(node: Optional[ScimFilterNode], clause_to_sql):
    """Translate a parsed SCIM filter tree into a SQLAlchemy boolean
    expression. ``clause_to_sql`` is the per-resource binding (so
    Users + Groups can share this walker)."""
    from sqlalchemy import and_, not_, or_

    if node is None:
        return None
    if isinstance(node, ScimFilterClause):
        return clause_to_sql(node)
    if isinstance(node, ScimFilterGroup):
        children = [_node_to_sql(c, clause_to_sql) for c in node.children]
        if any(c is None for c in children):
            raise UnsupportedScimFilter("logical group contained empty branch")
        if node.op == "and":
            return and_(*children)
        if node.op == "or":
            return or_(*children)
        if node.op == "not":
            if len(children) != 1:
                raise UnsupportedScimFilter("`not` takes exactly one operand")
            return not_(children[0])
        raise UnsupportedScimFilter(f"unsupported logical op: {node.op}")
    raise UnsupportedScimFilter(f"unrecognised filter node: {type(node).__name__}")


def _apply_clause_to_query(query, node: Optional[ScimFilterNode]):
    """Compose a SCIM User-resource filter onto a query's WHERE clause."""
    if node is None:
        return query
    return query.where(_node_to_sql(node, _user_clause_to_sql))


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
        "totalResults": 2,
        "Resources": [
            {
                "id": "User",
                "name": "User",
                "endpoint": "/Users",
                "description": "User Account",
                "schema": SCHEMA_USER,
            },
            {
                "id": "Group",
                "name": "Group",
                "endpoint": "/Groups",
                "description": "Collection of users for shared visibility",
                "schema": SCHEMA_GROUP,
            },
        ],
    }


@router.get("/Schemas")
async def schemas() -> dict:
    """Minimal schema discovery — full SCIM Schemas are huge and rarely
    consumed by IdPs that already know the spec. Return canonical
    User + Group schema ids with the attributes we actually persist."""
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 2,
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
            },
            {
                "id": SCHEMA_GROUP,
                "name": "Group",
                "description": "SCIM Group schema",
                "attributes": [
                    {"name": "displayName", "type": "string", "required": True},
                    {"name": "members", "type": "complex", "multiValued": True},
                ],
            },
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


# ----- /Groups endpoints (RFC 7643 §4.2 + RFC 7644) --------------------------


def _group_clause_to_sql(clause: ScimFilterClause):
    """Filter binding for the Group resource.

    Currently only ``displayName`` is filterable — we intentionally do
    NOT expose member-id filters to keep the surface narrow."""
    attr = clause.attribute
    op = clause.op
    val = clause.value

    if attr == "displayName":
        col = db_models.UserGroup.name
        if op == "pr":
            return col.is_not(None)
        if not isinstance(val, str):
            raise UnsupportedScimFilter(f"expected string for {attr!r}")
        if op == "eq":
            return col == val
        if op == "ne":
            return col != val
        if op == "co":
            return col.contains(val)
        if op == "sw":
            return col.startswith(val)
        if op == "ew":
            return col.endswith(val)
        raise UnsupportedScimFilter(f"op {op!r} not supported on {attr!r}")

    raise UnsupportedScimFilter(f"unsupported Group attribute: {attr}")


def _apply_group_clause_to_query(query, node: Optional[ScimFilterNode]):
    if node is None:
        return query
    return query.where(_node_to_sql(node, _group_clause_to_sql))


def _parse_group_id(raw: str) -> Optional[_uuid.UUID]:
    try:
        return _uuid.UUID(raw)
    except (ValueError, AttributeError, TypeError):
        return None


async def _load_member_ids(db: AsyncSession, group_id: _uuid.UUID) -> list[int]:
    rows = (
        await db.execute(
            select(db_models.UserGroupMembership.user_id).where(
                db_models.UserGroupMembership.group_id == group_id
            )
        )
    ).all()
    return sorted({int(r[0]) for r in rows})


def _group_to_dict(group: db_models.UserGroup, member_ids: list[int]) -> dict:
    return {
        "schemas": [SCHEMA_GROUP],
        "id": str(group.id),
        "displayName": group.name,
        "members": [
            {
                "value": str(uid),
                "$ref": f"/scim/v2/Users/{uid}",
                "type": "User",
            }
            for uid in member_ids
        ],
        "meta": {"resourceType": "Group"},
    }


async def _link_members(
    db: AsyncSession,
    group_id: _uuid.UUID,
    members: list[ScimGroupMember],
) -> list[int]:
    """Insert UserGroupMembership rows for the supplied members.

    Skips entries that don't resolve to an existing user; idempotent
    against duplicate (group_id, user_id) pairs. Returns the ids that
    were either added or already present."""
    linked: list[int] = []
    for m in members:
        try:
            uid = int(m.value)
        except (ValueError, TypeError):
            continue
        u = (
            await db.execute(select(db_models.User.id).where(db_models.User.id == uid))
        ).scalar_one_or_none()
        if u is None:
            continue
        existing = (
            await db.execute(
                select(db_models.UserGroupMembership).where(
                    db_models.UserGroupMembership.group_id == group_id,
                    db_models.UserGroupMembership.user_id == uid,
                )
            )
        ).scalar_one_or_none()
        if existing is None:
            db.add(db_models.UserGroupMembership(group_id=group_id, user_id=uid))
        linked.append(uid)
    return sorted(set(linked))


async def _resolve_creator_id(db: AsyncSession) -> Optional[int]:
    """user_groups.created_by is NOT NULL; SCIM tokens carry no specific
    user, so attribute the row to the configured master admin (or the
    lowest-id active superuser as a fallback)."""
    from app.core.config_cache import SystemConfigCache

    creator_id = SystemConfigCache.get_master_admin_user_id()
    if creator_id is not None:
        return int(creator_id)
    return (
        await db.execute(
            select(db_models.User.id)
            .where(db_models.User.is_superuser.is_(True))
            .order_by(db_models.User.id)
            .limit(1)
        )
    ).scalar_one_or_none()


@router.get("/Groups")
async def list_groups(
    request: Request,
    filter: Optional[str] = Query(default=None, max_length=512, alias="filter"),
    startIndex: int = Query(default=1, ge=1, le=10_000_000),
    count: int = Query(default=100, ge=0, le=200),
    db: AsyncSession = Depends(get_db),
    _token: Tuple[db_models.ScimToken, list] = Depends(require_scope("groups:read")),
):
    try:
        node = parse_filter(filter)
    except UnsupportedScimFilter as exc:
        return _scim_error(400, str(exc))

    base_q = select(db_models.UserGroup)
    try:
        base_q = _apply_group_clause_to_query(base_q, node)
    except UnsupportedScimFilter as exc:
        return _scim_error(400, str(exc))

    total = (
        await db.execute(select(func.count()).select_from(base_q.subquery()))
    ).scalar_one()
    page_q = (
        base_q.order_by(db_models.UserGroup.name).offset(startIndex - 1).limit(count)
    )
    groups = list((await db.execute(page_q)).scalars().all())
    resources = []
    for g in groups:
        member_ids = await _load_member_ids(db, g.id)
        resources.append(_group_to_dict(g, member_ids))
    return JSONResponse(
        content={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": int(total),
            "startIndex": startIndex,
            "itemsPerPage": len(resources),
            "Resources": resources,
        },
        media_type="application/scim+json",
    )


@router.get("/Groups/{group_id}")
async def get_group(
    group_id: str = Path(...),
    db: AsyncSession = Depends(get_db),
    _token: Tuple[db_models.ScimToken, list] = Depends(require_scope("groups:read")),
):
    gid = _parse_group_id(group_id)
    if gid is None:
        return _scim_error(400, "invalid group id")
    g = (
        await db.execute(
            select(db_models.UserGroup).where(db_models.UserGroup.id == gid)
        )
    ).scalar_one_or_none()
    if g is None:
        return _scim_error(404, "group not found")
    member_ids = await _load_member_ids(db, g.id)
    return JSONResponse(
        content=_group_to_dict(g, member_ids),
        media_type="application/scim+json",
    )


@router.post("/Groups")
async def create_group(
    request: Request,
    payload: ScimGroup = Body(...),
    db: AsyncSession = Depends(get_db),
    _token: Tuple[db_models.ScimToken, list] = Depends(require_scope("groups:write")),
):
    name = payload.displayName.strip()
    if not name:
        return _scim_error(400, "displayName is required")
    clash = (
        await db.execute(
            select(db_models.UserGroup).where(db_models.UserGroup.name == name)
        )
    ).scalar_one_or_none()
    if clash is not None:
        return _scim_error(409, "group with that displayName already exists")

    creator_id = await _resolve_creator_id(db)
    if creator_id is None:
        return _scim_error(
            500,
            "cannot create group via SCIM: no superuser exists to attribute "
            "the row to (complete first-run setup first)",
        )

    g = db_models.UserGroup(name=name, created_by=int(creator_id))
    db.add(g)
    await db.flush()

    member_ids: list[int] = []
    if payload.members:
        member_ids = await _link_members(db, g.id, payload.members)

    await audit.record(
        db,
        event=EVENT_SCIM_GROUP_CREATED,
        user_id=None,
        request=request,
        details={
            "group_id": str(g.id),
            "displayName": name,
            "member_count": len(member_ids),
        },
    )
    await db.commit()

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content=_group_to_dict(g, member_ids),
        media_type="application/scim+json",
        headers={"Location": f"/scim/v2/Groups/{g.id}"},
    )


@router.put("/Groups/{group_id}")
async def replace_group(
    request: Request,
    group_id: str = Path(...),
    payload: ScimGroup = Body(...),
    db: AsyncSession = Depends(get_db),
    _token: Tuple[db_models.ScimToken, list] = Depends(require_scope("groups:write")),
):
    """Full replacement: displayName updated, member set wiped + reseeded."""
    from sqlalchemy import delete as sa_delete

    gid = _parse_group_id(group_id)
    if gid is None:
        return _scim_error(400, "invalid group id")
    g = (
        await db.execute(
            select(db_models.UserGroup).where(db_models.UserGroup.id == gid)
        )
    ).scalar_one_or_none()
    if g is None:
        return _scim_error(404, "group not found")

    new_name = payload.displayName.strip()
    if not new_name:
        return _scim_error(400, "displayName cannot be empty")
    if new_name != g.name:
        clash = (
            await db.execute(
                select(db_models.UserGroup).where(
                    db_models.UserGroup.name == new_name,
                    db_models.UserGroup.id != gid,
                )
            )
        ).scalar_one_or_none()
        if clash is not None:
            return _scim_error(409, "another group already has that displayName")
        g.name = new_name

    await db.execute(
        sa_delete(db_models.UserGroupMembership).where(
            db_models.UserGroupMembership.group_id == gid
        )
    )
    member_ids: list[int] = []
    if payload.members:
        member_ids = await _link_members(db, gid, payload.members)

    await audit.record(
        db,
        event=EVENT_SCIM_GROUP_UPDATED,
        user_id=None,
        request=request,
        details={
            "group_id": str(g.id),
            "displayName": g.name,
            "member_count": len(member_ids),
        },
    )
    await db.commit()
    return JSONResponse(
        content=_group_to_dict(g, member_ids),
        media_type="application/scim+json",
    )


@router.patch("/Groups/{group_id}")
async def patch_group(
    request: Request,
    group_id: str = Path(...),
    payload: ScimPatchRequest = Body(...),
    db: AsyncSession = Depends(get_db),
    _token: Tuple[db_models.ScimToken, list] = Depends(require_scope("groups:write")),
):
    """Group PATCH — supports the operations IdPs actually emit:

    - replace displayName
    - add members      (path="members", value=[{"value": "<id>"}, ...])
    - remove members   (path='members[value eq "<id>"]')
    - remove members   (path="members", value=[{"value": "<id>"}, ...])  — Okta variant
    """
    from sqlalchemy import delete as sa_delete

    gid = _parse_group_id(group_id)
    if gid is None:
        return _scim_error(400, "invalid group id")
    g = (
        await db.execute(
            select(db_models.UserGroup).where(db_models.UserGroup.id == gid)
        )
    ).scalar_one_or_none()
    if g is None:
        return _scim_error(404, "group not found")

    added: list[int] = []
    removed: list[int] = []
    renamed = False

    for op_obj in payload.Operations:
        op = (op_obj.op or "").lower()
        path = (op_obj.path or "").strip()
        plower = path.lower()

        if op == "replace" and plower == "displayname":
            new_name = str(op_obj.value or "").strip()
            if not new_name:
                return _scim_error(400, "displayName cannot be empty")
            clash = (
                await db.execute(
                    select(db_models.UserGroup).where(
                        db_models.UserGroup.name == new_name,
                        db_models.UserGroup.id != gid,
                    )
                )
            ).scalar_one_or_none()
            if clash is not None:
                return _scim_error(409, "another group already has that displayName")
            g.name = new_name
            renamed = True
            continue

        if op == "add" and plower == "members":
            members_in: list[ScimGroupMember] = []
            for raw in op_obj.value or []:
                if isinstance(raw, dict) and "value" in raw:
                    members_in.append(
                        ScimGroupMember(
                            value=str(raw["value"]),
                            type=str(raw.get("type", "User")),
                        )
                    )
            new_ids = await _link_members(db, gid, members_in)
            added.extend(new_ids)
            continue

        match = _MEMBERS_VALUE_REMOVE.match(path)
        if op == "remove" and match:
            try:
                uid = int(match.group(1))
            except ValueError:
                return _scim_error(400, f"invalid member id in path: {path}")
            await db.execute(
                sa_delete(db_models.UserGroupMembership).where(
                    db_models.UserGroupMembership.group_id == gid,
                    db_models.UserGroupMembership.user_id == uid,
                )
            )
            removed.append(uid)
            continue

        if op == "remove" and plower == "members":
            ids: list[int] = []
            for raw in op_obj.value or []:
                if isinstance(raw, dict) and "value" in raw:
                    try:
                        ids.append(int(raw["value"]))
                    except (ValueError, TypeError):
                        pass
            if ids:
                await db.execute(
                    sa_delete(db_models.UserGroupMembership).where(
                        db_models.UserGroupMembership.group_id == gid,
                        db_models.UserGroupMembership.user_id.in_(ids),
                    )
                )
            removed.extend(ids)
            continue

        return _scim_error(400, f"PATCH op={op!r} path={path!r} not supported on Group")

    await audit.record(
        db,
        event=EVENT_SCIM_GROUP_UPDATED,
        user_id=None,
        request=request,
        details={
            "group_id": str(g.id),
            "displayName": g.name,
            "renamed": renamed,
            "members_added": sorted(set(added)),
            "members_removed": sorted(set(removed)),
        },
    )
    await db.commit()
    member_ids = await _load_member_ids(db, g.id)
    return JSONResponse(
        content=_group_to_dict(g, member_ids),
        media_type="application/scim+json",
    )


@router.delete("/Groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_group(
    request: Request,
    group_id: str = Path(...),
    db: AsyncSession = Depends(get_db),
    _token: Tuple[db_models.ScimToken, list] = Depends(require_scope("groups:write")),
):
    """Hard-delete the group; memberships cascade. Unlike Users, dropping
    a Group only loses shared visibility (re-creatable), so we don't
    soft-delete here."""
    gid = _parse_group_id(group_id)
    if gid is None:
        return _scim_error(400, "invalid group id")
    g = (
        await db.execute(
            select(db_models.UserGroup).where(db_models.UserGroup.id == gid)
        )
    ).scalar_one_or_none()
    if g is None:
        return _scim_error(404, "group not found")

    name = g.name
    await db.delete(g)
    await audit.record(
        db,
        event=EVENT_SCIM_GROUP_DELETED,
        user_id=None,
        request=request,
        details={"group_id": str(gid), "displayName": name},
    )
    await db.commit()
    return JSONResponse(status_code=status.HTTP_204_NO_CONTENT, content=None)


# Avoid unused-import warnings.
_ = (datetime, timezone, _uuid, SCHEMA_ERROR)
