"""Authenticated tenant API for governed rule candidates and deployments."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import (
    get_current_permissions,
    get_current_user_tenant_id,
    require_permission,
)
from app.api.v1.schemas.rule_foundry import (
    CandidateCreate,
    CandidatePage,
    CandidateRead,
    DeploymentRead,
    ReviewDecision,
    ReviewRequiredRequest,
    SignedVersionRead,
    TransitionRequest,
)
from app.config.config import settings
from app.core.services.rule_foundry_service import (
    RuleFoundryDeniedError,
    RuleFoundryNotFoundError,
    RuleFoundryService,
    RuleFoundryStateError,
)
from app.infrastructure.auth.core import current_active_user
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db
from app.infrastructure.database.repositories.authorization_repo import (
    AuthorizationRepository,
)
from app.infrastructure.database.repositories.rule_foundry_repo import (
    RuleFoundryConflictError,
    RuleFoundryRepository,
)
from app.infrastructure.signing.digest_signer import AwsKmsDigestSigner
from app.shared.lib.permissions import (
    AUDIT_READ,
    RULE_CANDIDATE_CREATE,
    RULE_CANDIDATE_REVIEW,
    RULE_PROMOTE,
)


router = APIRouter(prefix="/foundry", tags=["rule-foundry"])


async def require_foundry_read(
    permissions: frozenset[str] = Depends(get_current_permissions),
) -> frozenset[str]:
    if not permissions.intersection(
        {AUDIT_READ, RULE_CANDIDATE_CREATE, RULE_CANDIDATE_REVIEW, RULE_PROMOTE}
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied."
        )
    return permissions


def _service(db: AsyncSession) -> RuleFoundryService:
    signer = None
    if settings.RULE_FOUNDRY_KMS_KEY_ID:
        signer = AwsKmsDigestSigner(
            key_id=settings.RULE_FOUNDRY_KMS_KEY_ID,
            region=settings.RULE_FOUNDRY_KMS_REGION,
        )
    return RuleFoundryService(
        repo=RuleFoundryRepository(db),
        authz_repo=AuthorizationRepository(db),
        signer=signer,
    )


async def _read_candidate(
    repo: RuleFoundryRepository, candidate: db_models.RuleFoundryCandidate
) -> CandidateRead:
    version = await repo.latest_version(
        tenant_id=candidate.tenant_id, candidate_id=candidate.id
    )
    deployment = await repo.active_deployment(
        tenant_id=candidate.tenant_id, candidate_id=candidate.id
    )
    deployment_read = None
    if deployment is not None:
        eligible, unexpected = await repo.shadow_totals(
            tenant_id=candidate.tenant_id, deployment_id=deployment.id
        )
        deployment_read = DeploymentRead.model_validate(
            {
                **{
                    field: getattr(deployment, field)
                    for field in (
                        "id",
                        "version_id",
                        "prior_version_id",
                        "state",
                        "shadow_started_at",
                        "review_due_at",
                        "promoted_at",
                        "ended_at",
                    )
                },
                "eligible_files": eligible,
                "unexpected_matches": unexpected,
            }
        )
    return CandidateRead.model_validate(
        {
            **{
                field: getattr(candidate, field)
                for field in (
                    "id",
                    "tenant_id",
                    "source_finding_id",
                    "registry_kind",
                    "predicate_kind",
                    "static_representable",
                    "non_representable_reason",
                    "stable_identity",
                    "status",
                    "severity",
                    "cwe",
                    "normalized_evidence",
                    "creator_user_id",
                    "reviewer_user_id",
                    "promoter_user_id",
                    "expires_at",
                    "reviewed_at",
                    "promoted_at",
                    "created_at",
                )
            },
            "latest_version": (
                SignedVersionRead.model_validate(version) if version else None
            ),
            "active_deployment": deployment_read,
        }
    )


async def _commit_or_http(db: AsyncSession, operation):
    try:
        result = await operation
        await db.commit()
        return result
    except RuleFoundryNotFoundError as exc:
        await db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuleFoundryDeniedError as exc:
        await db.rollback()
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except RuleFoundryConflictError as exc:
        await db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except RuleFoundryStateError as exc:
        # State transitions such as expiry/review-required and failed quality
        # attestations are themselves durable audit facts.
        await db.commit()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/candidates", response_model=CandidatePage)
async def list_candidates(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    candidate_status: str | None = Query(None, alias="status", max_length=24),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    db: AsyncSession = Depends(get_db),
    _permissions: frozenset[str] = Depends(require_foundry_read),
) -> CandidatePage:
    repo = RuleFoundryRepository(db)
    await repo.expire_due(tenant_id=tenant_id, now=datetime.now(timezone.utc))
    rows, total = await repo.list_candidates(
        tenant_id=tenant_id,
        page=page,
        page_size=page_size,
        status=candidate_status,
    )
    await db.commit()
    return CandidatePage(
        items=[await _read_candidate(repo, row) for row in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post(
    "/candidates",
    response_model=CandidateRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_candidate(
    payload: CandidateCreate,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    db: AsyncSession = Depends(get_db),
    user: db_models.User = Depends(current_active_user),
    _permission: frozenset[str] = Depends(require_permission(RULE_CANDIDATE_CREATE)),
) -> CandidateRead:
    service = _service(db)
    candidate = await _commit_or_http(
        db,
        service.create_candidate(
            tenant_id=tenant_id, actor_user_id=user.id, payload=payload
        ),
    )
    return await _read_candidate(service.repo, candidate)


@router.get("/candidates/{candidate_id}", response_model=CandidateRead)
async def get_candidate(
    candidate_id: uuid.UUID,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    db: AsyncSession = Depends(get_db),
    _permissions: frozenset[str] = Depends(require_foundry_read),
) -> CandidateRead:
    repo = RuleFoundryRepository(db)
    candidate = await repo.get_candidate(tenant_id=tenant_id, candidate_id=candidate_id)
    if candidate is None:
        raise HTTPException(status_code=404, detail="Candidate not found.")
    return await _read_candidate(repo, candidate)


@router.post("/candidates/{candidate_id}/review", response_model=CandidateRead)
async def review_candidate(
    candidate_id: uuid.UUID,
    payload: ReviewDecision,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    db: AsyncSession = Depends(get_db),
    user: db_models.User = Depends(current_active_user),
    _permission: frozenset[str] = Depends(require_permission(RULE_CANDIDATE_REVIEW)),
) -> CandidateRead:
    service = _service(db)
    candidate = await _commit_or_http(
        db,
        service.review_candidate(
            tenant_id=tenant_id,
            actor_user_id=user.id,
            candidate_id=candidate_id,
            decision=payload,
        ),
    )
    return await _read_candidate(service.repo, candidate)


@router.post("/candidates/{candidate_id}/shadow", response_model=CandidateRead)
async def start_shadow(
    candidate_id: uuid.UUID,
    payload: TransitionRequest,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    db: AsyncSession = Depends(get_db),
    user: db_models.User = Depends(current_active_user),
    _permission: frozenset[str] = Depends(require_permission(RULE_PROMOTE)),
) -> CandidateRead:
    service = _service(db)
    candidate = await _commit_or_http(
        db,
        service.start_shadow(
            tenant_id=tenant_id,
            actor_user_id=user.id,
            candidate_id=candidate_id,
            reason=payload.reason,
        ),
    )
    return await _read_candidate(service.repo, candidate)


@router.post("/candidates/{candidate_id}/promote", response_model=CandidateRead)
async def promote_candidate(
    candidate_id: uuid.UUID,
    payload: TransitionRequest,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    db: AsyncSession = Depends(get_db),
    user: db_models.User = Depends(current_active_user),
    _permission: frozenset[str] = Depends(require_permission(RULE_PROMOTE)),
) -> CandidateRead:
    service = _service(db)
    candidate = await _commit_or_http(
        db,
        service.promote(
            tenant_id=tenant_id,
            actor_user_id=user.id,
            candidate_id=candidate_id,
            reason=payload.reason,
        ),
    )
    return await _read_candidate(service.repo, candidate)


@router.post("/candidates/{candidate_id}/rollback", response_model=CandidateRead)
async def rollback_candidate(
    candidate_id: uuid.UUID,
    payload: TransitionRequest,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    db: AsyncSession = Depends(get_db),
    user: db_models.User = Depends(current_active_user),
    _permission: frozenset[str] = Depends(require_permission(RULE_PROMOTE)),
) -> CandidateRead:
    service = _service(db)
    candidate = await _commit_or_http(
        db,
        service.rollback(
            tenant_id=tenant_id,
            actor_user_id=user.id,
            candidate_id=candidate_id,
            reason=payload.reason,
        ),
    )
    return await _read_candidate(service.repo, candidate)


@router.post("/candidates/{candidate_id}/review-required", response_model=CandidateRead)
async def mark_review_required(
    candidate_id: uuid.UUID,
    payload: ReviewRequiredRequest,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    db: AsyncSession = Depends(get_db),
    user: db_models.User = Depends(current_active_user),
    _permission: frozenset[str] = Depends(require_permission(RULE_PROMOTE)),
) -> CandidateRead:
    service = _service(db)
    candidate = await _commit_or_http(
        db,
        service.mark_review_required(
            tenant_id=tenant_id,
            actor_user_id=user.id,
            candidate_id=candidate_id,
            trigger=payload.trigger,
            reason=payload.reason,
        ),
    )
    return await _read_candidate(service.repo, candidate)


@router.post("/expire", status_code=status.HTTP_200_OK)
async def expire_candidates(
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    db: AsyncSession = Depends(get_db),
    _permission: frozenset[str] = Depends(require_permission(RULE_PROMOTE)),
) -> dict[str, int]:
    count = await RuleFoundryRepository(db).expire_due(
        tenant_id=tenant_id, now=datetime.now(timezone.utc)
    )
    await db.commit()
    return {"expired": count}
