"""Authenticated, tenant-scoped canonical usage and budget center."""

from __future__ import annotations

import csv
import io
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import (
    get_current_permissions,
    get_current_user_tenant_id,
    get_visible_user_ids,
    require_permission,
)
from app.api.v1.schemas.usage_center import (
    UsageBreakdownResponse,
    UsageBudgetStatusResponse,
    UsageEventsResponse,
    UsagePolicyPreviewRequest,
    UsagePolicyPreviewResponse,
    UsageSummaryResponse,
    UsageTrendsResponse,
)
from app.core.services.usage_center_service import (
    UsageCenterService,
    UsageScopeError,
    decode_cursor,
    encode_cursor,
)
from app.infrastructure.auth.core import current_active_user
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db
from app.infrastructure.database.repositories.usage_center_repo import (
    UsageCenterRepository,
    UsageQuery,
)
from app.shared.lib.permissions import TENANT_POLICY_MANAGE


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/usage", tags=["Usage and Budgets"])

CostStatus = Literal["exact", "estimated", "unknown", "reconciled"]
OperationKind = Literal["scan", "chat", "rag", "pentest"]
BreakdownDimension = Literal[
    "operation",
    "project",
    "scan",
    "stage",
    "agent",
    "provider",
    "model",
    "account",
    "group",
]
TrendInterval = Literal["hour", "day", "week", "month"]


def _service(db: AsyncSession = Depends(get_db)) -> UsageCenterService:
    return UsageCenterService(UsageCenterRepository(db))


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise HTTPException(status_code=422, detail="Usage timestamps need a timezone.")
    return value.astimezone(timezone.utc)


def _range(
    from_at: datetime | None, to_at: datetime | None
) -> tuple[datetime, datetime]:
    end = _utc(to_at) if to_at is not None else datetime.now(timezone.utc)
    start = _utc(from_at) if from_at is not None else end - timedelta(days=30)
    if start >= end:
        raise HTTPException(status_code=422, detail="from_at must be before to_at.")
    if end - start > timedelta(days=366):
        raise HTTPException(
            status_code=422, detail="Usage queries are limited to 366 days."
        )
    return start, end


async def _scoped_query(
    *,
    service: UsageCenterService,
    tenant_id: uuid.UUID,
    user: db_models.User,
    permissions: frozenset[str],
    dependency_visible_user_ids: list[int] | None,
    from_at: datetime | None,
    to_at: datetime | None,
    user_id: int | None,
    group_id: uuid.UUID | None,
    project_id: uuid.UUID | None,
    scan_id: uuid.UUID | None,
    operation_kind: OperationKind | None,
    operation_id: str | None,
    stage: str | None,
    agent_name: str | None,
    provider: str | None,
    model: str | None,
    llm_config_id: uuid.UUID | None,
    cost_status: CostStatus | None,
) -> tuple[UsageQuery, Literal["self", "group", "tenant"]]:
    start, end = _range(from_at, to_at)
    visibility = await service.resolve_visibility(
        tenant_id=tenant_id,
        user_id=user.id,
        permissions=permissions,
        dependency_visible_user_ids=dependency_visible_user_ids,
    )
    query = UsageQuery(
        tenant_id=tenant_id,
        from_at=start,
        to_at=end,
        visible_user_ids=visibility.visible_user_ids,
        user_id=user_id,
        group_id=group_id,
        project_id=project_id,
        scan_id=scan_id,
        operation_kind=operation_kind,
        operation_id=operation_id,
        stage=stage,
        agent_name=agent_name,
        provider=provider,
        model=model,
        llm_config_id=llm_config_id,
        cost_status=cost_status,
    )
    try:
        return service.authorize_query(query, visibility), visibility.scope
    except UsageScopeError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


FromAt = Annotated[datetime | None, Query()]
ToAt = Annotated[datetime | None, Query()]


@router.get("/summary", response_model=UsageSummaryResponse)
async def usage_summary(
    from_at: FromAt = None,
    to_at: ToAt = None,
    user_id: int | None = Query(default=None, ge=1),
    group_id: uuid.UUID | None = None,
    project_id: uuid.UUID | None = None,
    scan_id: uuid.UUID | None = None,
    operation_kind: OperationKind | None = None,
    operation_id: str | None = Query(default=None, max_length=128),
    stage: str | None = Query(default=None, max_length=100),
    agent_name: str | None = Query(default=None, max_length=100),
    provider: str | None = Query(default=None, max_length=64),
    model: str | None = Query(default=None, max_length=255),
    llm_config_id: uuid.UUID | None = None,
    cost_status: CostStatus | None = None,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user: db_models.User = Depends(current_active_user),
    permissions: frozenset[str] = Depends(get_current_permissions),
    dependency_visible_user_ids: list[int] | None = Depends(get_visible_user_ids),
    service: UsageCenterService = Depends(_service),
) -> UsageSummaryResponse:
    query, scope = await _scoped_query(**locals())
    totals = await service.summary(query)
    return UsageSummaryResponse(
        from_at=query.from_at, to_at=query.to_at, scope=scope, totals=totals
    )


@router.get("/trends", response_model=UsageTrendsResponse)
async def usage_trends(
    interval: TrendInterval = "day",
    from_at: FromAt = None,
    to_at: ToAt = None,
    user_id: int | None = Query(default=None, ge=1),
    group_id: uuid.UUID | None = None,
    project_id: uuid.UUID | None = None,
    scan_id: uuid.UUID | None = None,
    operation_kind: OperationKind | None = None,
    operation_id: str | None = Query(default=None, max_length=128),
    stage: str | None = Query(default=None, max_length=100),
    agent_name: str | None = Query(default=None, max_length=100),
    provider: str | None = Query(default=None, max_length=64),
    model: str | None = Query(default=None, max_length=255),
    llm_config_id: uuid.UUID | None = None,
    cost_status: CostStatus | None = None,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user: db_models.User = Depends(current_active_user),
    permissions: frozenset[str] = Depends(get_current_permissions),
    dependency_visible_user_ids: list[int] | None = Depends(get_visible_user_ids),
    service: UsageCenterService = Depends(_service),
) -> UsageTrendsResponse:
    values = locals().copy()
    values.pop("interval")
    query, _ = await _scoped_query(**values)
    return UsageTrendsResponse(
        from_at=query.from_at,
        to_at=query.to_at,
        interval=interval,
        points=await service.trends(query, interval),
    )


@router.get("/breakdowns", response_model=UsageBreakdownResponse)
async def usage_breakdown(
    dimension: BreakdownDimension = "operation",
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    from_at: FromAt = None,
    to_at: ToAt = None,
    user_id: int | None = Query(default=None, ge=1),
    group_id: uuid.UUID | None = None,
    project_id: uuid.UUID | None = None,
    scan_id: uuid.UUID | None = None,
    operation_kind: OperationKind | None = None,
    operation_id: str | None = Query(default=None, max_length=128),
    stage: str | None = Query(default=None, max_length=100),
    agent_name: str | None = Query(default=None, max_length=100),
    provider: str | None = Query(default=None, max_length=64),
    model: str | None = Query(default=None, max_length=255),
    llm_config_id: uuid.UUID | None = None,
    cost_status: CostStatus | None = None,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user: db_models.User = Depends(current_active_user),
    permissions: frozenset[str] = Depends(get_current_permissions),
    dependency_visible_user_ids: list[int] | None = Depends(get_visible_user_ids),
    service: UsageCenterService = Depends(_service),
) -> UsageBreakdownResponse:
    values = locals().copy()
    for key in ("dimension", "page", "page_size"):
        values.pop(key)
    query, _ = await _scoped_query(**values)
    items, total = await service.breakdown(
        query, dimension=dimension, page=page, page_size=page_size
    )
    return UsageBreakdownResponse(
        dimension=dimension,
        items=items,
        page=page,
        page_size=page_size,
        total=total,
    )


@router.get("/events", response_model=UsageEventsResponse)
async def usage_events(
    cursor: str | None = Query(default=None, max_length=512),
    limit: int = Query(default=50, ge=1, le=200),
    from_at: FromAt = None,
    to_at: ToAt = None,
    user_id: int | None = Query(default=None, ge=1),
    group_id: uuid.UUID | None = None,
    project_id: uuid.UUID | None = None,
    scan_id: uuid.UUID | None = None,
    operation_kind: OperationKind | None = None,
    operation_id: str | None = Query(default=None, max_length=128),
    stage: str | None = Query(default=None, max_length=100),
    agent_name: str | None = Query(default=None, max_length=100),
    provider: str | None = Query(default=None, max_length=64),
    model: str | None = Query(default=None, max_length=255),
    llm_config_id: uuid.UUID | None = None,
    cost_status: CostStatus | None = None,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user: db_models.User = Depends(current_active_user),
    permissions: frozenset[str] = Depends(get_current_permissions),
    dependency_visible_user_ids: list[int] | None = Depends(get_visible_user_ids),
    service: UsageCenterService = Depends(_service),
) -> UsageEventsResponse:
    values = locals().copy()
    for key in ("cursor", "limit"):
        values.pop(key)
    query, _ = await _scoped_query(**values)
    try:
        before = decode_cursor(cursor) if cursor else None
    except UsageScopeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    rows = await service.repo.list_events(query, limit=limit + 1, before=before)
    has_more = len(rows) > limit
    items = rows[:limit]
    next_cursor = (
        encode_cursor(items[-1].created_at, items[-1].id)
        if has_more and items
        else None
    )
    logger.info(
        "usage.events.read",
        extra={
            "actor_id": user.id,
            "tenant_id": str(tenant_id),
            "returned": len(items),
            "has_more": has_more,
        },
    )
    return UsageEventsResponse(items=items, next_cursor=next_cursor)


@router.get("/export")
async def export_usage(
    format: Literal["csv", "json"] = "csv",
    from_at: FromAt = None,
    to_at: ToAt = None,
    user_id: int | None = Query(default=None, ge=1),
    group_id: uuid.UUID | None = None,
    project_id: uuid.UUID | None = None,
    scan_id: uuid.UUID | None = None,
    operation_kind: OperationKind | None = None,
    operation_id: str | None = Query(default=None, max_length=128),
    stage: str | None = Query(default=None, max_length=100),
    agent_name: str | None = Query(default=None, max_length=100),
    provider: str | None = Query(default=None, max_length=64),
    model: str | None = Query(default=None, max_length=255),
    llm_config_id: uuid.UUID | None = None,
    cost_status: CostStatus | None = None,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user: db_models.User = Depends(current_active_user),
    permissions: frozenset[str] = Depends(get_current_permissions),
    dependency_visible_user_ids: list[int] | None = Depends(get_visible_user_ids),
    service: UsageCenterService = Depends(_service),
) -> Response:
    values = locals().copy()
    values.pop("format")
    query, _ = await _scoped_query(**values)
    rows = await service.repo.list_events(query, limit=10_001)
    if len(rows) > 10_000:
        raise HTTPException(
            status_code=413,
            detail="Export exceeds 10,000 rows; narrow the filters and retry.",
        )
    fields = (
        "id",
        "created_at",
        "operation_kind",
        "operation_id",
        "scan_id",
        "stage",
        "agent_name",
        "user_id",
        "provider",
        "requested_model",
        "request_count",
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "cache_read_tokens",
        "cache_write_tokens",
        "reasoning_tokens",
        "usage_source",
        "quality_state",
        "cost_status",
        "currency",
        "total_cost",
    )
    records = [
        {
            field: (
                str(getattr(row, field)) if getattr(row, field) is not None else None
            )
            for field in fields
        }
        for row in rows
    ]
    headers = {"Content-Disposition": f'attachment; filename="usage.{format}"'}
    if format == "json":
        return Response(
            json.dumps(records, separators=(",", ":")),
            media_type="application/json",
            headers=headers,
        )
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerows(records)
    return Response(output.getvalue(), media_type="text/csv", headers=headers)


@router.get("/budgets", response_model=UsageBudgetStatusResponse)
async def usage_budgets(
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user: db_models.User = Depends(current_active_user),
    permissions: frozenset[str] = Depends(get_current_permissions),
    dependency_visible_user_ids: list[int] | None = Depends(get_visible_user_ids),
    service: UsageCenterService = Depends(_service),
) -> UsageBudgetStatusResponse:
    visibility = await service.resolve_visibility(
        tenant_id=tenant_id,
        user_id=user.id,
        permissions=permissions,
        dependency_visible_user_ids=dependency_visible_user_ids,
    )
    states, thresholds, denials = await service.budget_state(
        tenant_id=tenant_id, user_id=user.id, visibility=visibility
    )
    return UsageBudgetStatusResponse(
        states=states,
        recent_thresholds=[
            {
                "policy_id": str(row.policy_id),
                "dimension": row.dimension,
                "threshold_percent": row.threshold_percent,
                "observed": str(row.observed),
                "effective_cap": str(row.effective_cap),
                "created_at": row.created_at.isoformat(),
            }
            for row in thresholds
        ],
        recent_denials=[
            {
                "operation_kind": row.resource_type.removeprefix("usage_budget_"),
                "occurred_at": row.occurred_at.isoformat(),
                "code": row.reason_code,
            }
            for row in denials
        ],
    )


@router.post(
    "/policy-preview",
    response_model=UsagePolicyPreviewResponse,
    dependencies=[Depends(require_permission(TENANT_POLICY_MANAGE))],
)
async def preview_usage_policy(
    payload: UsagePolicyPreviewRequest,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    service: UsageCenterService = Depends(_service),
) -> UsagePolicyPreviewResponse:
    try:
        preview = await service.preview_policy(
            tenant_id=tenant_id, candidate=payload.policy
        )
    except UsageScopeError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return UsagePolicyPreviewResponse(**preview)
