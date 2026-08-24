"""Tenant administration and usage-center reads for provider reconciliation."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import (
    get_current_user_tenant_id,
    require_permission,
)
from app.api.v1.schemas.provider_reconciliation import (
    ConnectorCreate,
    ConnectorRead,
    ConnectorUpdate,
    ReconciliationEvidenceRead,
    ReconciliationRunRead,
    ReconciliationRunRequest,
    ReconciliationSummaryRead,
)
from app.core.services.provider_reconciliation_service import (
    ConnectorDisabledError,
    ProviderReconciliationService,
)
from app.infrastructure.auth.core import current_active_user
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db
from app.infrastructure.database.repositories.provider_reconciliation_repo import (
    ProviderReconciliationRepository,
)
from app.shared.lib.permissions import AUDIT_READ, TENANT_POLICY_MANAGE


router = APIRouter(
    prefix="/admin/usage-reconciliation", tags=["Admin: Usage Reconciliation"]
)


def _repo(db: AsyncSession = Depends(get_db)) -> ProviderReconciliationRepository:
    return ProviderReconciliationRepository(db)


def _connector_read(row: db_models.ProviderBillingConnector) -> ConnectorRead:
    return ConnectorRead(
        id=row.id,
        tenant_id=row.tenant_id,
        provider=row.provider,
        display_name=row.display_name,
        project_ids=row.provider_project_ids,
        verified_scopes=row.verified_scopes,
        enabled=row.enabled,
        credentials_configured=bool(row.credentials_encrypted),
        absolute_tolerance_micro_usd=row.absolute_tolerance_micro_usd,
        percentage_tolerance=row.percentage_tolerance,
        lookback_minutes=row.lookback_minutes,
        poll_interval_minutes=row.poll_interval_minutes,
        next_run_at=row.next_run_at,
        last_run_at=row.last_run_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


@router.get(
    "/connectors",
    response_model=list[ConnectorRead],
    dependencies=[Depends(require_permission(AUDIT_READ))],
)
async def list_connectors(
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    repo: ProviderReconciliationRepository = Depends(_repo),
) -> list[ConnectorRead]:
    return [_connector_read(row) for row in await repo.list_connectors(tenant_id=tenant_id)]


@router.post(
    "/connectors",
    response_model=ConnectorRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(TENANT_POLICY_MANAGE))],
)
async def create_connector(
    payload: ConnectorCreate,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user: db_models.User = Depends(current_active_user),
    repo: ProviderReconciliationRepository = Depends(_repo),
) -> ConnectorRead:
    now = datetime.now(timezone.utc)
    try:
        row = await repo.create_connector(
            tenant_id=tenant_id,
            provider=payload.provider,
            display_name=payload.display_name.strip(),
            credentials={"api_key": payload.credentials.api_key.get_secret_value()},
            provider_project_ids=payload.project_ids,
            enabled=payload.enabled,
            absolute_tolerance_micro_usd=payload.absolute_tolerance_micro_usd,
            percentage_tolerance=payload.percentage_tolerance,
            lookback_minutes=payload.lookback_minutes,
            poll_interval_minutes=payload.poll_interval_minutes,
            created_by_user_id=user.id,
            now=now,
        )
        await repo.db.commit()
    except IntegrityError:
        await repo.db.rollback()
        raise HTTPException(status_code=409, detail="Connector name already exists.") from None
    return _connector_read(row)


@router.put(
    "/connectors/{connector_id}",
    response_model=ConnectorRead,
    dependencies=[Depends(require_permission(TENANT_POLICY_MANAGE))],
)
async def update_connector(
    connector_id: uuid.UUID,
    payload: ConnectorUpdate,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    repo: ProviderReconciliationRepository = Depends(_repo),
) -> ConnectorRead:
    credentials = (
        {"api_key": payload.credentials.api_key.get_secret_value()}
        if payload.credentials
        else None
    )
    row = await repo.update_connector(
        connector_id=connector_id,
        tenant_id=tenant_id,
        credentials=credentials,
        enabled=payload.enabled,
        absolute_tolerance_micro_usd=payload.absolute_tolerance_micro_usd,
        percentage_tolerance=payload.percentage_tolerance,
        lookback_minutes=payload.lookback_minutes,
        poll_interval_minutes=payload.poll_interval_minutes,
        provider_project_ids=payload.project_ids,
        now=datetime.now(timezone.utc),
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Connector not found.")
    await repo.db.commit()
    return _connector_read(row)


@router.post(
    "/connectors/{connector_id}/runs",
    response_model=ReconciliationRunRead,
    dependencies=[Depends(require_permission(TENANT_POLICY_MANAGE))],
)
async def run_connector(
    connector_id: uuid.UUID,
    payload: ReconciliationRunRequest,
    idempotency_key: str = Header(..., alias="X-Idempotency-Key", min_length=8, max_length=128),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user: db_models.User = Depends(current_active_user),
    repo: ProviderReconciliationRepository = Depends(_repo),
) -> ReconciliationRunRead:
    try:
        row = await ProviderReconciliationService(repo).run(
            connector_id=connector_id,
            tenant_id=tenant_id,
            window_start=payload.window_start,
            window_end=payload.window_end,
            trigger_kind="manual",
            created_by_user_id=user.id,
            idempotency_key=f"tenant:{tenant_id}:connector:{connector_id}:{idempotency_key}",
        )
    except LookupError:
        raise HTTPException(status_code=404, detail="Connector not found.") from None
    except ConnectorDisabledError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    return ReconciliationRunRead.model_validate(row)


@router.get(
    "/summary",
    response_model=ReconciliationSummaryRead,
    dependencies=[Depends(require_permission(AUDIT_READ))],
)
async def get_summary(
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    repo: ProviderReconciliationRepository = Depends(_repo),
) -> ReconciliationSummaryRead:
    row = await repo.summary(tenant_id=tenant_id)
    if row is None:
        connectors = await repo.list_connectors(tenant_id=tenant_id)
        return ReconciliationSummaryRead(status="never_run" if connectors else "not_configured")
    return ReconciliationSummaryRead(
        last_reconciliation_at=row.completed_at,
        status=row.status,
        coverage_percent=row.coverage_percent,
        variance_micro_usd=row.variance_micro_usd,
        unresolved_micro_usd=row.unresolved_micro_usd,
        unresolved_dimensions=row.unresolved_dimensions,
        run_id=row.id,
    )


@router.get(
    "/runs",
    response_model=list[ReconciliationRunRead],
    dependencies=[Depends(require_permission(AUDIT_READ))],
)
async def list_runs(
    cursor: uuid.UUID | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    repo: ProviderReconciliationRepository = Depends(_repo),
) -> list[ReconciliationRunRead]:
    return [
        ReconciliationRunRead.model_validate(row)
        for row in await repo.list_runs(tenant_id=tenant_id, cursor=cursor, limit=limit)
    ]


@router.get(
    "/runs/{run_id}",
    response_model=ReconciliationRunRead,
    dependencies=[Depends(require_permission(AUDIT_READ))],
)
async def get_run(
    run_id: uuid.UUID,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    repo: ProviderReconciliationRepository = Depends(_repo),
) -> ReconciliationRunRead:
    row = await repo.get_run(run_id=run_id, tenant_id=tenant_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Reconciliation run not found.")
    return ReconciliationRunRead.model_validate(row)


@router.get(
    "/runs/{run_id}/evidence",
    response_model=list[ReconciliationEvidenceRead],
    dependencies=[Depends(require_permission(AUDIT_READ))],
)
async def list_evidence(
    run_id: uuid.UUID,
    cursor: uuid.UUID | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    repo: ProviderReconciliationRepository = Depends(_repo),
) -> list[ReconciliationEvidenceRead]:
    if await repo.get_run(run_id=run_id, tenant_id=tenant_id) is None:
        raise HTTPException(status_code=404, detail="Reconciliation run not found.")
    return [
        ReconciliationEvidenceRead.model_validate(row)
        for row in await repo.list_evidence(
            run_id=run_id, tenant_id=tenant_id, cursor=cursor, limit=limit
        )
    ]
