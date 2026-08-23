"""Tenant-scoped endpoints for SCIM service-principal lifecycle.

Surface (all require ``service_principal.manage``):

  GET    /api/v1/admin/scim/tokens        — list (token plaintext NEVER returned)
  POST   /api/v1/admin/scim/tokens        — issue (plaintext returned ONCE)
  DELETE /api/v1/admin/scim/tokens/{id}   — revoke

The plaintext is returned only in the POST response body; it is not
re-derivable from anything stored. The frontend should display it once
+ encourage the operator to copy it immediately.
"""

from __future__ import annotations

import logging
import uuid as _uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import (
    APIRouter,
    Body,
    Depends,
    Header,
    HTTPException,
    Path,
    Query,
    Request,
    status,
)
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.auth.core import current_active_user
from app.api.v1.dependencies import (
    get_current_permissions,
    get_current_user_tenant_id,
    require_permission,
)
from app.api.v1.routers.authorization import ActionRequestRead, action_request_to_read
from app.infrastructure.auth.scim.auth import hash_token, issue_plaintext_token
from app.infrastructure.auth.sso import audit
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db
from app.infrastructure.database.repositories.authorization_repo import (
    AuthorizationConflictError,
    AuthorizationDeniedError,
    AuthorizationRepository,
    payload_digest,
    target_fingerprint,
)
from app.shared.lib.permissions import SERVICE_PRINCIPAL_MANAGE


logger = logging.getLogger(__name__)


router = APIRouter(prefix="/admin/scim", tags=["Admin: SCIM"])


_VALID_SCOPES = {
    "users:read",
    "users:write",
    "groups:read",
    "groups:write",
}
_REVOKE_TOKEN_PAYLOAD = {"operation": "revoke_scim_token"}


class ScimTokenCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(..., min_length=1, max_length=128)
    scopes: List[str] = Field(..., min_length=1, max_length=10)
    expires_at: Optional[datetime] = None


class ScimTokenRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: _uuid.UUID
    name: str
    scopes: List[str]
    created_at: datetime
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]


class ScimTokenIssued(ScimTokenRead):
    """Returned ONLY from POST. Carries the plaintext token; the caller is
    expected to copy it immediately because it can't be retrieved later."""

    plaintext_token: str


def _token_fingerprint(*, tenant_id: _uuid.UUID, token_id: _uuid.UUID) -> str:
    return target_fingerprint(
        resource_type="scim_service_principal",
        target_id=f"{tenant_id}:{token_id}",
    )


@router.get(
    "/tokens",
    response_model=List[ScimTokenRead],
    dependencies=[Depends(require_permission(SERVICE_PRINCIPAL_MANAGE))],
)
async def list_tokens(
    tenant_id: _uuid.UUID = Depends(get_current_user_tenant_id),
    db: AsyncSession = Depends(get_db),
):
    rows = (
        (
            await db.execute(
                select(db_models.ScimToken)
                .where(db_models.ScimToken.tenant_id == tenant_id)
                .order_by(db_models.ScimToken.created_at)
            )
        )
        .scalars()
        .all()
    )
    return [ScimTokenRead.model_validate(r) for r in rows]


@router.post(
    "/tokens",
    response_model=ScimTokenIssued,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(SERVICE_PRINCIPAL_MANAGE))],
)
async def create_token(
    request: Request,
    payload: ScimTokenCreate = Body(...),
    tenant_id: _uuid.UUID = Depends(get_current_user_tenant_id),
    db: AsyncSession = Depends(get_db),
    user: db_models.User = Depends(current_active_user),
):
    bad = [s for s in payload.scopes if s not in _VALID_SCOPES]
    if bad:
        raise HTTPException(
            status_code=400,
            detail=f"unknown scope(s): {bad}; allowed: {sorted(_VALID_SCOPES)}",
        )
    plaintext = issue_plaintext_token()
    row = db_models.ScimToken(
        name=payload.name,
        token_hash=hash_token(plaintext),
        scopes=list(payload.scopes),
        expires_at=payload.expires_at,
        created_by_user_id=user.id,
        tenant_id=tenant_id,
    )
    db.add(row)
    await db.flush()
    await audit.record(
        db,
        event="scim.token.created",
        actor_user_id=user.id,
        tenant_id=tenant_id,
        outcome="success",
        request=request,
        details={"name": payload.name, "scopes": list(payload.scopes)},
    )
    await db.commit()
    return ScimTokenIssued(
        id=row.id,
        name=row.name,
        scopes=list(row.scopes),
        created_at=row.created_at,
        expires_at=row.expires_at,
        last_used_at=row.last_used_at,
        plaintext_token=plaintext,
    )


@router.post(
    "/tokens/{token_id}/revocation-requests",
    response_model=ActionRequestRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(SERVICE_PRINCIPAL_MANAGE))],
)
async def request_token_revocation(
    token_id: _uuid.UUID = Path(...),
    idempotency_key: str = Header(..., alias="X-Idempotency-Key", max_length=128),
    tenant_id: _uuid.UUID = Depends(get_current_user_tenant_id),
    permissions: frozenset[str] = Depends(get_current_permissions),
    db: AsyncSession = Depends(get_db),
    user: db_models.User = Depends(current_active_user),
) -> ActionRequestRead:
    token = await db.scalar(
        select(db_models.ScimToken).where(
            db_models.ScimToken.id == token_id,
            db_models.ScimToken.tenant_id == tenant_id,
        )
    )
    if token is None:
        raise HTTPException(status_code=404, detail="token not found")
    authz = AuthorizationRepository(db)
    if await authz.separation_of_duties_mode(tenant_id=tenant_id) != "critical":
        raise HTTPException(
            status_code=409,
            detail="A distinct-actor request is only used in critical mode.",
        )
    fingerprint = _token_fingerprint(tenant_id=tenant_id, token_id=token_id)
    try:
        action = await authz.create_action_request(
            tenant_id=tenant_id,
            requester_user_id=user.id,
            requester_permission=SERVICE_PRINCIPAL_MANAGE,
            approver_permission=SERVICE_PRINCIPAL_MANAGE,
            target_type="scim_token_revoke",
            target_fingerprint_value=fingerprint,
            payload_digest_value=payload_digest(_REVOKE_TOKEN_PAYLOAD),
            idempotency_key=idempotency_key,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
    except AuthorizationConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    authz.record_audit(
        tenant_id=tenant_id,
        principal_kind="human",
        principal_id=str(user.id),
        permission=SERVICE_PRINCIPAL_MANAGE,
        resource_type="scim_service_principal",
        target_fingerprint_value=fingerprint,
        outcome="requested",
        reason_code="service_principal_revocation_requested",
        action_request_id=action.id,
    )
    await db.commit()
    return action_request_to_read(
        action, actor_user_id=user.id, permissions=permissions
    )


@router.delete(
    "/tokens/{token_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission(SERVICE_PRINCIPAL_MANAGE))],
)
async def revoke_token(
    request: Request,
    token_id: _uuid.UUID = Path(...),
    action_request_id: _uuid.UUID | None = Query(default=None),
    tenant_id: _uuid.UUID = Depends(get_current_user_tenant_id),
    permissions: frozenset[str] = Depends(get_current_permissions),
    db: AsyncSession = Depends(get_db),
    user: db_models.User = Depends(current_active_user),
):
    row = (
        await db.execute(
            select(db_models.ScimToken)
            .where(
                db_models.ScimToken.id == token_id,
                db_models.ScimToken.tenant_id == tenant_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="token not found")
    authz = AuthorizationRepository(db)
    fingerprint = _token_fingerprint(tenant_id=tenant_id, token_id=token_id)
    requires_approval = (
        await authz.separation_of_duties_mode(tenant_id=tenant_id) == "critical"
    )
    approver_id: int | None = None
    if requires_approval:
        if action_request_id is None:
            raise HTTPException(
                status_code=409,
                detail="An approved distinct-actor action request is required.",
            )
        action = await authz.get_action_request(
            request_id=action_request_id, tenant_id=tenant_id
        )
        if (
            action is None
            or action.requester_user_id != user.id
            or action.target_type != "scim_token_revoke"
            or action.target_fingerprint != fingerprint
        ):
            raise HTTPException(status_code=404, detail="Action request not found.")
        approver_permissions = await authz.permissions_for_user_id(
            user_id=action.approver_user_id or -1,
            tenant_id=tenant_id,
        )
        try:
            await authz.mark_executed(
                request_id=action.id,
                tenant_id=tenant_id,
                payload_digest_value=payload_digest(_REVOKE_TOKEN_PAYLOAD),
                requester_permissions=permissions,
                approver_permissions=approver_permissions,
            )
        except (AuthorizationConflictError, AuthorizationDeniedError) as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        approver_id = action.approver_user_id
    elif action_request_id is not None:
        raise HTTPException(
            status_code=400,
            detail="An action request is not applicable to this token revocation.",
        )

    await db.delete(row)
    await audit.record(
        db,
        event="scim.token.revoked",
        actor_user_id=user.id,
        tenant_id=tenant_id,
        outcome="success",
        request=request,
        details={"approval_required": requires_approval},
    )
    authz.record_audit(
        tenant_id=tenant_id,
        principal_kind="human",
        principal_id=str(user.id),
        permission=SERVICE_PRINCIPAL_MANAGE,
        resource_type="scim_service_principal",
        target_fingerprint_value=fingerprint,
        outcome="executed" if requires_approval else "allowed",
        reason_code=(
            "approved_service_principal_revocation_executed"
            if requires_approval
            else "service_principal_revoked"
        ),
        action_request_id=action_request_id,
        approver_principal_id=str(approver_id) if approver_id is not None else None,
    )
    await db.commit()


__all__ = ["router"]
