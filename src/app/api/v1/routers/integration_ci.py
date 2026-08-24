"""Authenticated CI submission and persisted policy polling contract."""

from __future__ import annotations

import re
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy import select

from app.api.v1.dependencies import (
    get_current_user_tenant_id,
    get_llm_config_repository,
    get_scan_query_service,
    get_scan_submission_service,
    get_visible_user_ids,
    require_permission,
)
from app.api.v1.schemas.integrations import CiPolicyRead, CiSubmissionRead
from app.config.logging_config import correlation_id_var
from app.core.services.scan import ScanQueryService, ScanSubmissionService
from app.infrastructure.auth.core import current_active_user
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.llm_config_repo import LLMConfigRepository
from app.shared.lib.integration_contract import (
    IntegrationContractError,
    IntegrationSourceProvenance,
)
from app.shared.lib.permissions import SCAN_READ, SCAN_SUBMIT
from app.shared.lib.scan_status import TERMINAL_SCAN_STATUSES


router = APIRouter(prefix="/integrations/ci", tags=["Enterprise integrations: CI"])
_FULL_OBJECT_ID = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_REF = re.compile(r"^refs/(?:heads|tags|pull)/[-A-Za-z0-9_./]+$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


@router.post(
    "/submissions",
    response_model=CiSubmissionRead,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_permission(SCAN_SUBMIT))],
)
async def submit_ci_archive(
    provider: Literal["github", "gitlab", "azure_devops", "bitbucket"] = Form(...),
    commit_sha: str = Form(..., min_length=40, max_length=64),
    ref: str = Form(..., min_length=6, max_length=255),
    repository_slug: str = Form(..., min_length=3, max_length=255),
    trusted_context: bool = Form(...),
    project_name: str = Form(
        ..., min_length=1, max_length=200, pattern=r"^[A-Za-z0-9_. -]+$"
    ),
    frameworks: str = Form(..., min_length=1, max_length=2048),
    archive_file: UploadFile = File(...),
    scan_type: Literal["AUDIT", "SUGGEST", "REMEDIATE"] = Form("AUDIT"),
    reasoning_llm_config_id: uuid.UUID | None = Form(None),
    utility_llm_config_id: uuid.UUID | None = Form(None),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user: db_models.User = Depends(current_active_user),
    service: ScanSubmissionService = Depends(get_scan_submission_service),
    llm_repo: LLMConfigRepository = Depends(get_llm_config_repository),
) -> CiSubmissionRead:
    if not trusted_context:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Untrusted CI contexts cannot submit tenant-authenticated scans.",
        )
    if user.tenant_id != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CI submission credentials are not owned by the selected tenant.",
        )
    if not _FULL_OBJECT_ID.fullmatch(commit_sha):
        raise HTTPException(
            status_code=400, detail="A full immutable commit SHA is required."
        )
    if (
        not _REF.fullmatch(ref)
        or ".." in ref
        or not _REPOSITORY.fullmatch(repository_slug)
    ):
        raise HTTPException(
            status_code=400, detail="Invalid immutable source provenance."
        )
    filename = archive_file.filename or ""
    if not filename or any(value in filename for value in ("/", "\\", "\x00")):
        raise HTTPException(status_code=400, detail="Invalid archive filename.")
    selected_frameworks = [
        value.strip() for value in frameworks.split(",") if value.strip()
    ]
    if not selected_frameworks or len(selected_frameworks) > 50:
        raise HTTPException(status_code=400, detail="Invalid framework selection.")

    if reasoning_llm_config_id is None:
        available = await llm_repo.get_all(skip=0, limit=1)
        if not available:
            raise HTTPException(
                status_code=400,
                detail="No LLM configuration is available for CI scans.",
            )
        reasoning_llm_config_id = available[0].id
    if utility_llm_config_id is None:
        utility_llm_config_id = reasoning_llm_config_id

    try:
        source_provenance = IntegrationSourceProvenance(
            tenant_id=tenant_id,
            provider=provider,
            commit_sha=commit_sha,
            ref=ref,
            repository_slug=repository_slug,
            trusted_context=True,
            actor_user_id=user.id,
        )
    except IntegrationContractError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None

    scan = await service.create_scan_from_archive(
        archive_file=archive_file,
        project_name=project_name,
        user_id=user.id,
        correlation_id=correlation_id_var.get(),
        scan_type=scan_type,
        reasoning_llm_config_id=reasoning_llm_config_id,
        utility_llm_config_id=utility_llm_config_id,
        secondary_reasoning_llm_config_id=None,
        stage_temperatures={
            "profiler": 0.2,
            "analysis": 0.2,
            "consolidation": 0.2,
            "analysis_secondary": 0.2,
        },
        disable_temperature=False,
        cross_file_validation=False,
        deep_vendor_scan=False,
        frameworks=selected_frameworks,
        selected_files=None,
        source_provenance=source_provenance,
    )
    return CiSubmissionRead(
        scan_id=scan.id,
        project_id=scan.project_id,
        provider=provider,
        commit_sha=commit_sha.casefold(),
        ref=ref,
    )


@router.get(
    "/scans/{scan_id}/policy",
    response_model=CiPolicyRead,
    dependencies=[Depends(require_permission(SCAN_READ))],
)
async def persisted_ci_policy(
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user: db_models.User = Depends(current_active_user),
    visible_user_ids=Depends(get_visible_user_ids),
    service: ScanQueryService = Depends(get_scan_query_service),
) -> CiPolicyRead:
    scan = await service.get_scan_status(
        scan_id,
        user,
        visible_user_ids=visible_user_ids,
        tenant_id=tenant_id,
    )
    evaluation = None
    if scan.current_attempt_id is not None:
        evaluation = await service.repo.db.scalar(
            select(db_models.FindingPolicyEvaluation)
            .where(
                db_models.FindingPolicyEvaluation.tenant_id == tenant_id,
                db_models.FindingPolicyEvaluation.scan_id == scan_id,
                db_models.FindingPolicyEvaluation.attempt_id == scan.current_attempt_id,
            )
            .order_by(db_models.FindingPolicyEvaluation.created_at.desc())
            .limit(1)
        )
    terminal = scan.status in TERMINAL_SCAN_STATUSES
    return CiPolicyRead(
        scan_id=scan_id,
        status=scan.status,
        terminal=terminal,
        policy_evaluation_id=evaluation.id if evaluation else None,
        policy_version_id=evaluation.policy_version_id if evaluation else None,
        outcome=evaluation.outcome if evaluation else None,
        coverage_complete=evaluation.coverage_complete if evaluation else None,
        report_url=(
            f"/api/v1/scans/{scan_id}/report?format=sarif"
            if terminal and evaluation
            else None
        ),
    )
