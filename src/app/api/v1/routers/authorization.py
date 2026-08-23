"""Tenant authorization policy and durable high-risk action inbox."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import (
    get_current_permissions,
    get_current_user_tenant_id,
    require_permission,
)
from app.infrastructure.auth.core import current_active_user
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db
from app.infrastructure.database.repositories.authorization_repo import (
    AuthorizationConflictError,
    AuthorizationDeniedError,
    AuthorizationRepository,
    payload_digest,
    target_fingerprint,
)
from app.shared.lib.permissions import (
    AUDIT_READ,
    TENANT_POLICY_MANAGE,
)


router = APIRouter(prefix="/admin/authorization", tags=["Admin: Authorization"])
ActionStatus = Literal[
    "pending", "approved", "rejected", "expired", "executed", "cancelled"
]


class AuthorizationPolicyRead(BaseModel):
    separation_of_duties_mode: Literal["off", "critical"]


class AuthorizationPolicyUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    separation_of_duties_mode: Literal["off", "critical"]
    action_request_id: uuid.UUID | None = None


class PolicyChangeRequestCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    separation_of_duties_mode: Literal["off"]


class ActionDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approved: bool
    reason: str = Field(..., min_length=1, max_length=500)


class ActionRequestRead(BaseModel):
    id: uuid.UUID
    requester_permission: str
    approver_permission: str
    target_type: str
    status: ActionStatus
    expires_at: datetime
    created_at: datetime
    decided_at: datetime | None
    executed_at: datetime | None
    is_requester: bool
    can_decide: bool


def _to_action_read(
    row: db_models.AuthorizationActionRequest,
    *,
    actor_user_id: int,
    permissions: frozenset[str],
) -> ActionRequestRead:
    return ActionRequestRead(
        id=row.id,
        requester_permission=row.requester_permission,
        approver_permission=row.approver_permission,
        target_type=row.target_type,
        status=row.status,
        expires_at=row.expires_at,
        created_at=row.created_at,
        decided_at=row.decided_at,
        executed_at=row.executed_at,
        is_requester=row.requester_user_id == actor_user_id,
        can_decide=(
            row.status == "pending"
            and row.requester_user_id != actor_user_id
            and row.approver_permission in permissions
        ),
    )


@router.get(
    "/policy",
    response_model=AuthorizationPolicyRead,
    dependencies=[Depends(require_permission(AUDIT_READ))],
)
async def get_authorization_policy(
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    db: AsyncSession = Depends(get_db),
) -> AuthorizationPolicyRead:
    mode = await AuthorizationRepository(db).separation_of_duties_mode(
        tenant_id=tenant_id
    )
    return AuthorizationPolicyRead(separation_of_duties_mode=mode)


@router.post(
    "/policy-change-requests",
    response_model=ActionRequestRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(TENANT_POLICY_MANAGE))],
)
async def request_policy_relaxation(
    payload: PolicyChangeRequestCreate,
    idempotency_key: str = Header(..., alias="X-Idempotency-Key", max_length=128),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    permissions: frozenset[str] = Depends(get_current_permissions),
    user: db_models.User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db),
) -> ActionRequestRead:
    repo = AuthorizationRepository(db)
    current = await repo.separation_of_duties_mode(tenant_id=tenant_id)
    if current != "critical" or payload.separation_of_duties_mode != "off":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Only relaxation of a critical policy requires this workflow.",
        )
    canonical = {"separation_of_duties_mode": "off"}
    fingerprint = target_fingerprint(
        resource_type="tenant_authorization_policy", target_id=str(tenant_id)
    )
    try:
        row = await repo.create_action_request(
            tenant_id=tenant_id,
            requester_user_id=user.id,
            requester_permission=TENANT_POLICY_MANAGE,
            approver_permission=TENANT_POLICY_MANAGE,
            target_type="tenant_policy_change",
            target_fingerprint_value=fingerprint,
            payload_digest_value=payload_digest(canonical),
            idempotency_key=idempotency_key,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
    except AuthorizationConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    repo.record_audit(
        tenant_id=tenant_id,
        principal_kind="human",
        principal_id=str(user.id),
        permission=TENANT_POLICY_MANAGE,
        resource_type="tenant_authorization_policy",
        target_fingerprint_value=fingerprint,
        outcome="requested",
        reason_code="critical_policy_relaxation_requested",
        action_request_id=row.id,
    )
    await db.commit()
    return _to_action_read(row, actor_user_id=user.id, permissions=permissions)


@router.patch(
    "/policy",
    response_model=AuthorizationPolicyRead,
    dependencies=[Depends(require_permission(TENANT_POLICY_MANAGE))],
)
async def update_authorization_policy(
    payload: AuthorizationPolicyUpdate,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    permissions: frozenset[str] = Depends(get_current_permissions),
    user: db_models.User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db),
) -> AuthorizationPolicyRead:
    tenant = await db.scalar(
        select(db_models.Tenant)
        .where(db_models.Tenant.id == tenant_id)
        .with_for_update()
    )
    if tenant is None:
        raise HTTPException(status_code=404)
    desired = payload.separation_of_duties_mode
    if tenant.separation_of_duties_mode == desired:
        return AuthorizationPolicyRead(separation_of_duties_mode=desired)

    repo = AuthorizationRepository(db)
    fingerprint = target_fingerprint(
        resource_type="tenant_authorization_policy", target_id=str(tenant_id)
    )
    if tenant.separation_of_duties_mode == "critical" and desired == "off":
        if payload.action_request_id is None:
            raise HTTPException(
                status_code=409,
                detail="An approved distinct-actor action request is required.",
            )
        action = await repo.get_action_request(
            request_id=payload.action_request_id, tenant_id=tenant_id
        )
        canonical = {"separation_of_duties_mode": "off"}
        if (
            action is None
            or action.requester_user_id != user.id
            or action.target_type != "tenant_policy_change"
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
                payload_digest_value=payload_digest(canonical),
                requester_permissions=permissions,
                approver_permissions=approver_permissions,
            )
        except (AuthorizationConflictError, AuthorizationDeniedError) as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        outcome = "executed"
        reason_code = "approved_policy_relaxation_executed"
    else:
        outcome = "allowed"
        reason_code = "policy_tightened"

    tenant.separation_of_duties_mode = desired
    repo.record_audit(
        tenant_id=tenant_id,
        principal_kind="human",
        principal_id=str(user.id),
        permission=TENANT_POLICY_MANAGE,
        resource_type="tenant_authorization_policy",
        target_fingerprint_value=fingerprint,
        outcome=outcome,
        reason_code=reason_code,
        action_request_id=payload.action_request_id,
    )
    await db.commit()
    return AuthorizationPolicyRead(separation_of_duties_mode=desired)


@router.get(
    "/actions",
    response_model=list[ActionRequestRead],
)
async def list_action_requests(
    action_status: ActionStatus | None = Query(default=None, alias="status"),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    permissions: frozenset[str] = Depends(get_current_permissions),
    user: db_models.User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db),
) -> list[ActionRequestRead]:
    stmt = select(db_models.AuthorizationActionRequest).where(
        db_models.AuthorizationActionRequest.tenant_id == tenant_id,
        or_(
            db_models.AuthorizationActionRequest.requester_user_id == user.id,
            db_models.AuthorizationActionRequest.approver_permission.in_(permissions),
        ),
    )
    if action_status is not None:
        stmt = stmt.where(db_models.AuthorizationActionRequest.status == action_status)
    rows = list(
        (
            await db.scalars(
                stmt.order_by(db_models.AuthorizationActionRequest.created_at.desc())
            )
        ).all()
    )
    return [
        _to_action_read(row, actor_user_id=user.id, permissions=permissions)
        for row in rows
    ]


@router.post(
    "/actions/{request_id}/decision",
    response_model=ActionRequestRead,
)
async def decide_action_request(
    request_id: uuid.UUID,
    payload: ActionDecision,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    permissions: frozenset[str] = Depends(get_current_permissions),
    user: db_models.User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db),
) -> ActionRequestRead:
    repo = AuthorizationRepository(db)
    action = await repo.get_action_request(request_id=request_id, tenant_id=tenant_id)
    if action is None:
        raise HTTPException(status_code=404, detail="Action request not found.")
    requester_permissions = await repo.permissions_for_user_id(
        user_id=action.requester_user_id,
        tenant_id=tenant_id,
    )
    try:
        decided = await repo.decide_action_request(
            request_id=request_id,
            tenant_id=tenant_id,
            approver_user_id=user.id,
            approver_permissions=permissions,
            requester_permissions=requester_permissions,
            approved=payload.approved,
            reason=payload.reason,
        )
    except AuthorizationDeniedError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except AuthorizationConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    repo.record_audit(
        tenant_id=tenant_id,
        principal_kind="human",
        principal_id=str(user.id),
        permission=action.approver_permission,
        resource_type=action.target_type,
        target_fingerprint_value=action.target_fingerprint,
        outcome="approved" if payload.approved else "rejected",
        reason_code="distinct_actor_decision",
        action_request_id=action.id,
        approver_principal_id=str(user.id),
    )
    await db.commit()
    return _to_action_read(decided, actor_user_id=user.id, permissions=permissions)


__all__ = ["router"]
