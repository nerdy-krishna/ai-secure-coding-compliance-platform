"""Evidence-first finding detail, baselines, policy gates, and waivers."""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import (
    get_current_user_tenant_id,
    get_visible_user_ids,
    require_permission,
)
from app.api.v1.schemas.finding_governance import (
    FindingLineageListResponse,
    FindingPolicyEvaluationResponse,
    FindingPolicyRequest,
    FindingPolicyResponse,
    FindingPortfolioTrendsResponse,
    FindingWaiverRequest,
    FindingWaiverResponse,
    RevokeFindingWaiverRequest,
)
from app.core.services.finding_governance_service import FindingGovernanceService
from app.infrastructure.auth.core import current_active_user
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db
from app.infrastructure.database.repositories.finding_governance_repo import (
    FindingGovernanceRepository,
)
from app.shared.lib.permissions import (
    FINDING_TRIAGE,
    TENANT_POLICY_MANAGE,
    WAIVER_APPROVE,
)


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/finding-governance", tags=["Finding governance"])


def service(db: AsyncSession = Depends(get_db)) -> FindingGovernanceService:
    return FindingGovernanceService(FindingGovernanceRepository(db))


@router.get(
    "/scans/{scan_id}/findings",
    response_model=FindingLineageListResponse,
)
async def list_finding_evidence(
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    visible_user_ids: list[int] | None = Depends(get_visible_user_ids),
    svc: FindingGovernanceService = Depends(service),
) -> FindingLineageListResponse:
    return await svc.lineage(
        scan_id, tenant_id=tenant_id, visible_user_ids=visible_user_ids
    )


@router.get(
    "/scans/{scan_id}/findings/{finding_id}",
    response_model=FindingLineageListResponse,
)
async def get_finding_evidence(
    scan_id: uuid.UUID,
    finding_id: int,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    visible_user_ids: list[int] | None = Depends(get_visible_user_ids),
    svc: FindingGovernanceService = Depends(service),
) -> FindingLineageListResponse:
    return await svc.lineage(
        scan_id,
        tenant_id=tenant_id,
        visible_user_ids=visible_user_ids,
        finding_id=finding_id,
    )


@router.get("/policy", response_model=FindingPolicyResponse)
async def get_finding_policy(
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    svc: FindingGovernanceService = Depends(service),
) -> FindingPolicyResponse:
    return await svc.latest_policy(tenant_id)


@router.post(
    "/policy",
    response_model=FindingPolicyResponse,
    dependencies=[Depends(require_permission(TENANT_POLICY_MANAGE))],
)
async def create_finding_policy(
    request: FindingPolicyRequest,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user: db_models.User = Depends(current_active_user),
    svc: FindingGovernanceService = Depends(service),
) -> FindingPolicyResponse:
    return await svc.create_policy(
        tenant_id=tenant_id, actor_user_id=user.id, request=request
    )


@router.post(
    "/scans/{scan_id}/evaluate",
    response_model=FindingPolicyEvaluationResponse,
    dependencies=[Depends(require_permission(FINDING_TRIAGE))],
)
async def evaluate_finding_policy(
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    visible_user_ids: list[int] | None = Depends(get_visible_user_ids),
    svc: FindingGovernanceService = Depends(service),
) -> FindingPolicyEvaluationResponse:
    return await svc.evaluate(
        scan_id, tenant_id=tenant_id, visible_user_ids=visible_user_ids
    )


@router.post(
    "/scans/{scan_id}/findings/{finding_id}/waivers",
    response_model=FindingWaiverResponse,
    dependencies=[Depends(require_permission(WAIVER_APPROVE))],
)
async def grant_finding_waiver(
    scan_id: uuid.UUID,
    finding_id: int,
    request: FindingWaiverRequest,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    visible_user_ids: list[int] | None = Depends(get_visible_user_ids),
    user: db_models.User = Depends(current_active_user),
    svc: FindingGovernanceService = Depends(service),
) -> FindingWaiverResponse:
    response = await svc.grant_waiver(
        scan_id,
        finding_id,
        request,
        tenant_id=tenant_id,
        visible_user_ids=visible_user_ids,
        actor_user_id=user.id,
    )
    logger.info(
        "finding.waiver.granted",
        extra={
            "tenant_id": str(tenant_id),
            "scan_id": str(scan_id),
            "finding_id": finding_id,
            "waiver_id": str(response.id),
            "actor_user_id": user.id,
            "scope": request.scope,
            "expires_at": request.expires_at.isoformat(),
        },
    )
    return response


@router.post(
    "/waivers/{waiver_id}/revoke",
    response_model=FindingWaiverResponse,
    dependencies=[Depends(require_permission(WAIVER_APPROVE))],
)
async def revoke_finding_waiver(
    waiver_id: uuid.UUID,
    request: RevokeFindingWaiverRequest,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    visible_user_ids: list[int] | None = Depends(get_visible_user_ids),
    user: db_models.User = Depends(current_active_user),
    svc: FindingGovernanceService = Depends(service),
) -> FindingWaiverResponse:
    response = await svc.revoke_waiver(
        waiver_id,
        reason=request.reason,
        tenant_id=tenant_id,
        visible_user_ids=visible_user_ids,
        actor_user_id=user.id,
    )
    logger.info(
        "finding.waiver.revoked",
        extra={
            "tenant_id": str(tenant_id),
            "waiver_id": str(waiver_id),
            "actor_user_id": user.id,
        },
    )
    return response


@router.get("/waivers/{waiver_id}", response_model=FindingWaiverResponse)
async def get_finding_waiver_history(
    waiver_id: uuid.UUID,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    visible_user_ids: list[int] | None = Depends(get_visible_user_ids),
    svc: FindingGovernanceService = Depends(service),
) -> FindingWaiverResponse:
    return await svc.waiver_history(
        waiver_id,
        tenant_id=tenant_id,
        visible_user_ids=visible_user_ids,
    )


@router.get("/portfolio/trends", response_model=FindingPortfolioTrendsResponse)
async def get_finding_portfolio_trends(
    days: int = Query(default=90, ge=1, le=730),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    visible_user_ids: list[int] | None = Depends(get_visible_user_ids),
    svc: FindingGovernanceService = Depends(service),
) -> FindingPortfolioTrendsResponse:
    return await svc.trends(
        tenant_id=tenant_id,
        visible_user_ids=visible_user_ids,
        days=days,
    )
