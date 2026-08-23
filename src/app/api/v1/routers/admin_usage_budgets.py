"""Tenant-scoped administration and inspection of durable usage budgets."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import (
    get_current_permissions,
    get_current_user_tenant_id,
    require_permission,
)
from app.api.v1.schemas.usage_budgets import (
    BudgetAmountsRead,
    BudgetCaps,
    UsageBudgetCounterRead,
    UsageBudgetOverrideCreate,
    UsageBudgetOverrideRead,
    UsageBudgetPolicyCreate,
    UsageBudgetPolicyDisable,
    UsageBudgetPolicyRead,
    UsageBudgetPolicyReplace,
    UsageBudgetReservationRead,
    UsageBudgetThresholdEventRead,
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
from app.infrastructure.database.repositories.usage_budget_repo import (
    BudgetAmounts,
    UsageBudgetRepository,
)
from app.shared.lib.permissions import AUDIT_READ, TENANT_POLICY_MANAGE


router = APIRouter(prefix="/admin/usage-budgets", tags=["Admin: Usage Budgets"])


def _budget_repo(db: AsyncSession = Depends(get_db)) -> UsageBudgetRepository:
    return UsageBudgetRepository(db)


def _amounts(row: Any, prefix: str) -> BudgetAmountsRead:
    def value(name: str, default: Any = 0) -> Any:
        return getattr(row, f"{prefix}_{name}", default)

    return BudgetAmountsRead(
        input_tokens=value("input_tokens"),
        output_tokens=value("output_tokens"),
        total_tokens=value("total_tokens"),
        uncached_input_tokens=value("uncached_input_tokens"),
        billable_tokens=value("billable_tokens"),
        usd=value("usd", Decimal("0")),
        upstream_requests=value("provider_requests"),
    )


def _caps_kwargs(caps: BudgetCaps, *, prefix: str = "cap") -> dict[str, Any]:
    return {
        f"{prefix}_input_tokens": caps.input_tokens,
        f"{prefix}_output_tokens": caps.output_tokens,
        f"{prefix}_total_tokens": caps.total_tokens,
        f"{prefix}_uncached_input_tokens": caps.uncached_input_tokens,
        f"{prefix}_billable_tokens": caps.billable_tokens,
        f"{prefix}_usd": caps.usd,
        f"{prefix}_provider_requests": caps.upstream_requests,
    }


def _policy_kwargs(
    payload: UsageBudgetPolicyCreate | UsageBudgetPolicyReplace,
) -> dict[str, Any]:
    return {
        "scope_kind": payload.scope,
        "target_group_id": payload.group_id,
        "target_user_id": payload.user_id,
        "window_kind": payload.window,
        "llm_config_id": payload.llm_config_id,
        "stage": payload.stage,
        **_caps_kwargs(payload.caps),
        "soft_threshold_low": payload.soft_thresholds[0],
        "soft_threshold_high": payload.soft_thresholds[-1],
        "unknown_price_action": payload.unknown_price_action,
        "effective_from": payload.effective_from or datetime.now(timezone.utc),
        "effective_to": payload.effective_to,
        "reason": payload.reason,
        "enabled": getattr(payload, "enabled", True),
    }


def _policy_read(row: db_models.UsageBudgetPolicy) -> UsageBudgetPolicyRead:
    return UsageBudgetPolicyRead(
        id=row.id,
        logical_policy_id=row.logical_policy_id,
        tenant_id=row.tenant_id,
        version=row.version,
        scope=row.scope_kind,
        group_id=row.target_group_id,
        user_id=row.target_user_id,
        window=row.window_kind,
        llm_config_id=row.llm_config_id,
        stage=row.stage,
        caps=BudgetCaps(
            input_tokens=row.cap_input_tokens,
            output_tokens=row.cap_output_tokens,
            total_tokens=row.cap_total_tokens,
            uncached_input_tokens=row.cap_uncached_input_tokens,
            billable_tokens=row.cap_billable_tokens,
            usd=row.cap_usd,
            upstream_requests=row.cap_provider_requests,
        ),
        soft_thresholds=(row.soft_threshold_low, row.soft_threshold_high),
        unknown_price_action=row.unknown_price_action,
        effective_from=row.effective_from,
        effective_to=row.effective_to,
        reason=row.reason,
        enabled=row.enabled,
        created_by_user_id=row.created_by_user_id,
        created_at=row.created_at,
    )


def _counter_read(row: db_models.UsageBudgetCounter) -> UsageBudgetCounterRead:
    return UsageBudgetCounterRead(
        id=row.id,
        tenant_id=row.tenant_id,
        policy_id=row.policy_id,
        window_key=row.window_key,
        window_start=row.window_start,
        window_end=row.window_end,
        spent=_amounts(row, "spent"),
        held=_amounts(row, "held"),
        updated_at=row.updated_at,
    )


def _reservation_read(
    row: db_models.UsageBudgetReservation,
) -> UsageBudgetReservationRead:
    return UsageBudgetReservationRead(
        id=row.id,
        tenant_id=row.tenant_id,
        actor_user_id=row.actor_user_id,
        state=row.state,
        idempotency_key=row.idempotency_key,
        request_key=row.request_key,
        scan_attempt_id=row.scan_attempt_id,
        llm_config_id=row.llm_config_id,
        stage=row.stage,
        estimate=_amounts(row, "estimated"),
        expires_at=row.expires_at,
        created_at=row.created_at,
    )


def _override_read(row: db_models.UsageBudgetOverride) -> UsageBudgetOverrideRead:
    return UsageBudgetOverrideRead(
        id=row.id,
        tenant_id=row.tenant_id,
        policy_id=row.policy_id,
        window_key=row.window_key,
        allowance=_amounts(row, "allowance"),
        reason=row.reason,
        created_by_user_id=row.created_by_user_id,
        expires_at=row.expires_at,
        created_at=row.created_at,
    )


async def _validate_target(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    payload: UsageBudgetPolicyCreate | UsageBudgetPolicyReplace,
) -> None:
    if payload.group_id is not None:
        found = await db.scalar(
            select(db_models.UserGroup.id).where(
                db_models.UserGroup.id == payload.group_id,
                db_models.UserGroup.tenant_id == tenant_id,
            )
        )
        if found is None:
            raise HTTPException(status_code=404, detail="Budget group target not found.")
    if payload.user_id is not None:
        found = await db.scalar(
            select(db_models.User.id).where(
                db_models.User.id == payload.user_id,
                db_models.User.tenant_id == tenant_id,
            )
        )
        if found is None:
            raise HTTPException(status_code=404, detail="Budget user target not found.")


async def _validate_override_target(
    db: AsyncSession,
    repo: UsageBudgetRepository,
    *,
    tenant_id: uuid.UUID,
    payload: UsageBudgetOverrideCreate,
) -> None:
    policy = await repo.get_policy(payload.policy_id, tenant_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Budget policy not found.")
    counter = await db.scalar(
        select(db_models.UsageBudgetCounter).where(
            db_models.UsageBudgetCounter.tenant_id == tenant_id,
            db_models.UsageBudgetCounter.policy_id == payload.policy_id,
            db_models.UsageBudgetCounter.window_key == payload.window_key,
        )
    )
    if counter is None:
        raise HTTPException(status_code=404, detail="Budget window not found.")
    maximum_expiry = min(
        datetime.now(timezone.utc) + timedelta(hours=24), counter.window_end
    )
    if payload.expires_at > maximum_expiry:
        raise HTTPException(
            status_code=422,
            detail="Override expiry exceeds the policy window or 24-hour maximum.",
        )


def _record_audit(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    user_id: int,
    resource_id: uuid.UUID,
    outcome: str,
    reason_code: str,
    action_request_id: uuid.UUID | None = None,
    resource_type: str = "usage_budget_policy",
) -> None:
    AuthorizationRepository(db).record_audit(
        tenant_id=tenant_id,
        principal_kind="human",
        principal_id=str(user_id),
        permission=TENANT_POLICY_MANAGE,
        resource_type=resource_type,
        target_fingerprint_value=target_fingerprint(
            resource_type=resource_type, target_id=str(resource_id)
        ),
        outcome=outcome,
        reason_code=reason_code,
        action_request_id=action_request_id,
    )


@router.get(
    "/policies",
    response_model=list[UsageBudgetPolicyRead],
    dependencies=[Depends(require_permission(AUDIT_READ))],
)
async def list_policies(
    include_disabled: bool = Query(default=False),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    repo: UsageBudgetRepository = Depends(_budget_repo),
) -> list[UsageBudgetPolicyRead]:
    rows = await repo.list_policies(
        tenant_id=tenant_id, include_disabled=include_disabled
    )
    return [_policy_read(row) for row in rows]


@router.post(
    "/policies",
    response_model=UsageBudgetPolicyRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(TENANT_POLICY_MANAGE))],
)
async def create_policy(
    payload: UsageBudgetPolicyCreate,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user: db_models.User = Depends(current_active_user),
    repo: UsageBudgetRepository = Depends(_budget_repo),
    db: AsyncSession = Depends(get_db),
) -> UsageBudgetPolicyRead:
    await _validate_target(db, tenant_id=tenant_id, payload=payload)
    try:
        row = await repo.create_policy(
            tenant_id=tenant_id,
            created_by_user_id=user.id,
            **_policy_kwargs(payload),
            commit=False,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    _record_audit(
        db,
        tenant_id=tenant_id,
        user_id=user.id,
        resource_id=row.id,
        outcome="allowed",
        reason_code="usage_budget_policy_created",
    )
    await db.commit()
    return _policy_read(row)


@router.put(
    "/policies/{policy_id}",
    response_model=UsageBudgetPolicyRead,
    dependencies=[Depends(require_permission(TENANT_POLICY_MANAGE))],
)
async def replace_policy(
    policy_id: uuid.UUID,
    payload: UsageBudgetPolicyReplace,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user: db_models.User = Depends(current_active_user),
    repo: UsageBudgetRepository = Depends(_budget_repo),
    db: AsyncSession = Depends(get_db),
) -> UsageBudgetPolicyRead:
    await _validate_target(db, tenant_id=tenant_id, payload=payload)
    try:
        row = await repo.replace_policy(
            policy_id=policy_id,
            tenant_id=tenant_id,
            created_by_user_id=user.id,
            **_policy_kwargs(payload),
            commit=False,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    if row is None:
        raise HTTPException(status_code=404, detail="Budget policy not found.")
    _record_audit(
        db,
        tenant_id=tenant_id,
        user_id=user.id,
        resource_id=row.id,
        outcome="allowed",
        reason_code="usage_budget_policy_replaced",
    )
    await db.commit()
    return _policy_read(row)


@router.post(
    "/policies/{policy_id}/disable",
    response_model=UsageBudgetPolicyRead,
    dependencies=[Depends(require_permission(TENANT_POLICY_MANAGE))],
)
async def disable_policy(
    policy_id: uuid.UUID,
    payload: UsageBudgetPolicyDisable,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user: db_models.User = Depends(current_active_user),
    repo: UsageBudgetRepository = Depends(_budget_repo),
    db: AsyncSession = Depends(get_db),
) -> UsageBudgetPolicyRead:
    row = await repo.disable_policy(
        policy_id=policy_id,
        tenant_id=tenant_id,
        created_by_user_id=user.id,
        reason=payload.reason,
        commit=False,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Budget policy not found.")
    _record_audit(
        db,
        tenant_id=tenant_id,
        user_id=user.id,
        resource_id=row.id,
        outcome="allowed",
        reason_code="usage_budget_policy_disabled",
    )
    await db.commit()
    return _policy_read(row)


@router.get(
    "/counters",
    response_model=list[UsageBudgetCounterRead],
    dependencies=[Depends(require_permission(AUDIT_READ))],
)
async def list_counters(
    policy_id: uuid.UUID | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    repo: UsageBudgetRepository = Depends(_budget_repo),
) -> list[UsageBudgetCounterRead]:
    rows = await repo.list_counters(
        tenant_id=tenant_id, policy_id=policy_id, limit=limit
    )
    return [_counter_read(row) for row in rows]


@router.get(
    "/reservations",
    response_model=list[UsageBudgetReservationRead],
    dependencies=[Depends(require_permission(AUDIT_READ))],
)
async def list_reservations(
    reservation_state: Literal[
        "held", "settled", "released", "expired", "accounting_unknown"
    ]
    | None = Query(default=None, alias="state"),
    limit: int = Query(default=200, ge=1, le=1000),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    repo: UsageBudgetRepository = Depends(_budget_repo),
) -> list[UsageBudgetReservationRead]:
    rows = await repo.list_reservations(
        tenant_id=tenant_id, state=reservation_state, limit=limit
    )
    return [_reservation_read(row) for row in rows]


@router.get(
    "/threshold-events",
    response_model=list[UsageBudgetThresholdEventRead],
    dependencies=[Depends(require_permission(AUDIT_READ))],
)
async def list_threshold_events(
    policy_id: uuid.UUID | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    repo: UsageBudgetRepository = Depends(_budget_repo),
) -> list[UsageBudgetThresholdEventRead]:
    rows = await repo.list_threshold_events(
        tenant_id=tenant_id, policy_id=policy_id, limit=limit
    )
    return [UsageBudgetThresholdEventRead.model_validate(row) for row in rows]


@router.get(
    "/overrides",
    response_model=list[UsageBudgetOverrideRead],
    dependencies=[Depends(require_permission(AUDIT_READ))],
)
async def list_overrides(
    policy_id: uuid.UUID | None = Query(default=None),
    active_only: bool = Query(default=True),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    repo: UsageBudgetRepository = Depends(_budget_repo),
) -> list[UsageBudgetOverrideRead]:
    rows = await repo.list_overrides(
        tenant_id=tenant_id,
        policy_id=policy_id,
        active_only=active_only,
    )
    return [_override_read(row) for row in rows]


def _override_canonical(payload: UsageBudgetOverrideCreate) -> dict[str, Any]:
    return payload.model_dump(mode="json", exclude={"action_request_id"})


@router.post(
    "/override-requests",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(TENANT_POLICY_MANAGE))],
)
async def request_override(
    payload: UsageBudgetOverrideCreate,
    idempotency_key: str = Header(..., alias="X-Idempotency-Key", max_length=128),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user: db_models.User = Depends(current_active_user),
    repo: UsageBudgetRepository = Depends(_budget_repo),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    await _validate_override_target(
        db, repo, tenant_id=tenant_id, payload=payload
    )
    authz = AuthorizationRepository(db)
    if await authz.separation_of_duties_mode(tenant_id=tenant_id) != "critical":
        raise HTTPException(
            status_code=409,
            detail="An override request is only required in critical mode.",
        )
    if payload.expires_at > datetime.now(timezone.utc) + timedelta(hours=24):
        raise HTTPException(status_code=422, detail="Override expiry exceeds 24 hours.")
    canonical = _override_canonical(payload)
    fingerprint = target_fingerprint(
        resource_type="usage_budget_override", target_id=str(payload.policy_id)
    )
    try:
        row = await authz.create_action_request(
            tenant_id=tenant_id,
            requester_user_id=user.id,
            requester_permission=TENANT_POLICY_MANAGE,
            approver_permission=TENANT_POLICY_MANAGE,
            target_type="usage_budget_override",
            target_fingerprint_value=fingerprint,
            payload_digest_value=payload_digest(canonical),
            idempotency_key=idempotency_key,
            expires_at=min(
                payload.expires_at, datetime.now(timezone.utc) + timedelta(hours=24)
            ),
        )
    except AuthorizationConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    _record_audit(
        db,
        tenant_id=tenant_id,
        user_id=user.id,
        resource_id=payload.policy_id,
        outcome="requested",
        reason_code="usage_budget_override_requested",
        action_request_id=row.id,
        resource_type="usage_budget_override",
    )
    await db.commit()
    return {"action_request_id": row.id, "status": row.status}


@router.post(
    "/overrides",
    response_model=UsageBudgetOverrideRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(TENANT_POLICY_MANAGE))],
)
async def create_override(
    payload: UsageBudgetOverrideCreate,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    permissions: frozenset[str] = Depends(get_current_permissions),
    user: db_models.User = Depends(current_active_user),
    repo: UsageBudgetRepository = Depends(_budget_repo),
    db: AsyncSession = Depends(get_db),
) -> UsageBudgetOverrideRead:
    await _validate_override_target(
        db, repo, tenant_id=tenant_id, payload=payload
    )
    now = datetime.now(timezone.utc)
    if payload.expires_at <= now or payload.expires_at > now + timedelta(hours=24):
        raise HTTPException(
            status_code=422,
            detail="Override expiry must be in the next 24 hours.",
        )
    authz = AuthorizationRepository(db)
    mode = await authz.separation_of_duties_mode(tenant_id=tenant_id)
    canonical = _override_canonical(payload)
    fingerprint = target_fingerprint(
        resource_type="usage_budget_override", target_id=str(payload.policy_id)
    )
    if mode == "critical":
        if payload.action_request_id is None:
            _record_audit(
                db,
                tenant_id=tenant_id,
                user_id=user.id,
                resource_id=payload.policy_id,
                outcome="denied",
                reason_code="usage_budget_override_approval_required",
                resource_type="usage_budget_override",
            )
            await db.commit()
            raise HTTPException(
                status_code=409,
                detail="An approved distinct-actor action request is required.",
            )
        action = await authz.get_action_request(
            request_id=payload.action_request_id, tenant_id=tenant_id
        )
        if (
            action is None
            or action.requester_user_id != user.id
            or action.target_type != "usage_budget_override"
            or action.target_fingerprint != fingerprint
        ):
            _record_audit(
                db,
                tenant_id=tenant_id,
                user_id=user.id,
                resource_id=payload.policy_id,
                outcome="denied",
                reason_code="usage_budget_override_approval_not_found",
                action_request_id=payload.action_request_id,
                resource_type="usage_budget_override",
            )
            await db.commit()
            raise HTTPException(status_code=404, detail="Action request not found.")
        approver_permissions = await authz.permissions_for_user_id(
            user_id=action.approver_user_id or -1, tenant_id=tenant_id
        )
        try:
            await authz.mark_executed(
                request_id=action.id,
                tenant_id=tenant_id,
                payload_digest_value=payload_digest(canonical),
                requester_permissions=permissions,
                approver_permissions=approver_permissions,
            )
        except (AuthorizationConflictError, AuthorizationDeniedError) as exc:
            _record_audit(
                db,
                tenant_id=tenant_id,
                user_id=user.id,
                resource_id=payload.policy_id,
                outcome="denied",
                reason_code="usage_budget_override_approval_invalid",
                action_request_id=payload.action_request_id,
                resource_type="usage_budget_override",
            )
            await db.commit()
            raise HTTPException(status_code=409, detail=str(exc))
    try:
        row = await repo.create_override(
            tenant_id=tenant_id,
            policy_id=payload.policy_id,
            window_key=payload.window_key,
            allowance=BudgetAmounts(
                input_tokens=payload.allowance.input_tokens or 0,
                output_tokens=payload.allowance.output_tokens or 0,
                total_tokens=payload.allowance.total_tokens or 0,
                uncached_input_tokens=payload.allowance.uncached_input_tokens or 0,
                billable_tokens=payload.allowance.billable_tokens or 0,
                usd=payload.allowance.usd or Decimal("0"),
                provider_requests=payload.allowance.upstream_requests or 0,
            ),
            reason=payload.reason,
            created_by_user_id=user.id,
            effective_from=now,
            expires_at=payload.expires_at,
            commit=False,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    _record_audit(
        db,
        tenant_id=tenant_id,
        user_id=user.id,
        resource_id=payload.policy_id,
        outcome="executed" if mode == "critical" else "allowed",
        reason_code="usage_budget_override_created",
        action_request_id=payload.action_request_id,
        resource_type="usage_budget_override",
    )
    await db.commit()
    return _override_read(row)
