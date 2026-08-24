"""Authenticated tenant administration for enterprise integrations."""

from __future__ import annotations

import uuid

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import (
    get_current_user_tenant_id,
    get_scan_query_service,
    get_visible_user_ids,
    require_permission,
)
from app.api.v1.schemas.integrations import (
    DeliveryAuditRead,
    FindingTicketRead,
    GithubSarifRequest,
    GithubSourceRequest,
    GrantCreate,
    GrantRead,
    OutboxRead,
    PolicyEventRequest,
    PrincipalCreate,
    PrincipalRead,
    TicketSyncRequest,
)
from app.core.services.integration_service import IntegrationService
from app.core.services.report import generate_report
from app.core.services.scan import ScanQueryService
from app.infrastructure.auth.core import current_active_user
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db
from app.infrastructure.database.repositories.authorization_repo import (
    AuthorizationRepository,
    target_fingerprint,
)
from app.infrastructure.database.repositories.integration_repo import (
    IntegrationRepository,
)
from app.infrastructure.integrations.clients import configured_pinned_http_client
from app.shared.lib.integration_contract import IntegrationContractError
from app.shared.lib.permissions import AUDIT_READ, SERVICE_PRINCIPAL_MANAGE


router = APIRouter(prefix="/admin/integrations", tags=["Admin: Integrations"])


def _repo(db: AsyncSession = Depends(get_db)) -> IntegrationRepository:
    return IntegrationRepository(db)


def _audit(
    *,
    repo: IntegrationRepository,
    tenant_id: uuid.UUID,
    actor_user_id: int,
    resource_type: str,
    target_id: str,
    reason_code: str,
) -> None:
    AuthorizationRepository(repo.db).record_audit(
        tenant_id=tenant_id,
        principal_kind="human",
        principal_id=str(actor_user_id),
        permission=SERVICE_PRINCIPAL_MANAGE,
        resource_type=resource_type,
        target_fingerprint_value=target_fingerprint(
            resource_type=resource_type, target_id=target_id
        ),
        outcome="allowed",
        reason_code=reason_code,
    )


@router.get(
    "/principals",
    response_model=list[PrincipalRead],
    dependencies=[Depends(require_permission(SERVICE_PRINCIPAL_MANAGE))],
)
async def list_principals(
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    repo: IntegrationRepository = Depends(_repo),
) -> list[PrincipalRead]:
    return [
        PrincipalRead.model_validate(row)
        for row in await repo.list_principals(tenant_id=tenant_id)
    ]


@router.post(
    "/principals",
    response_model=PrincipalRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(SERVICE_PRINCIPAL_MANAGE))],
)
async def create_principal(
    payload: PrincipalCreate,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user: db_models.User = Depends(current_active_user),
    repo: IntegrationRepository = Depends(_repo),
) -> PrincipalRead:
    try:
        row = await IntegrationService(repo).create_principal(
            tenant_id=tenant_id,
            kind=payload.kind,
            display_name=payload.display_name,
            config=payload.config,
            secret_values={
                key: value.get_secret_value()
                for key, value in payload.secret_values.items()
            },
            actor_user_id=user.id,
        )
        _audit(
            repo=repo,
            tenant_id=tenant_id,
            actor_user_id=user.id,
            resource_type="integration_service_principal",
            target_id=str(row.id),
            reason_code="integration_principal_created",
        )
        await repo.db.commit()
    except IntegrityError:
        await repo.db.rollback()
        raise HTTPException(
            status_code=409, detail="Integration name already exists."
        ) from None
    except IntegrationContractError as exc:
        await repo.db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from None
    return PrincipalRead.model_validate(row)


@router.post(
    "/principals/{principal_id}/revoke",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission(SERVICE_PRINCIPAL_MANAGE))],
)
async def revoke_principal(
    principal_id: uuid.UUID,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user: db_models.User = Depends(current_active_user),
    repo: IntegrationRepository = Depends(_repo),
) -> Response:
    if not await repo.revoke_principal(
        tenant_id=tenant_id, principal_id=principal_id, actor_user_id=user.id
    ):
        raise HTTPException(status_code=404, detail="Integration principal not found.")
    _audit(
        repo=repo,
        tenant_id=tenant_id,
        actor_user_id=user.id,
        resource_type="integration_service_principal",
        target_id=str(principal_id),
        reason_code="integration_principal_revoked",
    )
    await repo.db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/principals/{principal_id}/grants",
    response_model=list[GrantRead],
    dependencies=[Depends(require_permission(SERVICE_PRINCIPAL_MANAGE))],
)
async def list_grants(
    principal_id: uuid.UUID,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    repo: IntegrationRepository = Depends(_repo),
) -> list[GrantRead]:
    if await repo.get_principal(tenant_id=tenant_id, principal_id=principal_id) is None:
        raise HTTPException(status_code=404, detail="Integration principal not found.")
    return [
        GrantRead.model_validate(row)
        for row in await repo.list_grants(
            tenant_id=tenant_id, principal_id=principal_id
        )
    ]


@router.post(
    "/principals/{principal_id}/grants",
    response_model=GrantRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(SERVICE_PRINCIPAL_MANAGE))],
)
async def create_grant(
    principal_id: uuid.UUID,
    payload: GrantCreate,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user: db_models.User = Depends(current_active_user),
    repo: IntegrationRepository = Depends(_repo),
) -> GrantRead:
    try:
        row = await IntegrationService(repo).grant_feature(
            tenant_id=tenant_id,
            principal_id=principal_id,
            feature=payload.feature,
            scope=payload.scope,
            actor_user_id=user.id,
        )
        _audit(
            repo=repo,
            tenant_id=tenant_id,
            actor_user_id=user.id,
            resource_type="integration_grant",
            target_id=str(row.id),
            reason_code="integration_feature_granted",
        )
        await repo.db.commit()
    except LookupError:
        raise HTTPException(
            status_code=404, detail="Integration principal not found."
        ) from None
    except IntegrationContractError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    return GrantRead.model_validate(row)


@router.post(
    "/principals/{principal_id}/grants/{grant_id}/revoke",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission(SERVICE_PRINCIPAL_MANAGE))],
)
async def revoke_grant(
    principal_id: uuid.UUID,
    grant_id: uuid.UUID,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user: db_models.User = Depends(current_active_user),
    repo: IntegrationRepository = Depends(_repo),
) -> Response:
    row, changed = await repo.revoke_grant(
        tenant_id=tenant_id,
        principal_id=principal_id,
        grant_id=grant_id,
        actor_user_id=user.id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Integration grant not found.")
    _audit(
        repo=repo,
        tenant_id=tenant_id,
        actor_user_id=user.id,
        resource_type="integration_grant",
        target_id=str(grant_id),
        reason_code=(
            "integration_feature_revoked"
            if changed
            else "integration_feature_already_revoked"
        ),
    )
    await repo.db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/principals/{principal_id}/policy-events",
    response_model=OutboxRead,
    dependencies=[Depends(require_permission(SERVICE_PRINCIPAL_MANAGE))],
)
async def enqueue_policy_event(
    principal_id: uuid.UUID,
    payload: PolicyEventRequest,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user: db_models.User = Depends(current_active_user),
    repo: IntegrationRepository = Depends(_repo),
) -> OutboxRead:
    try:
        row, _ = await IntegrationService(repo).enqueue_persisted_policy_event(
            tenant_id=tenant_id, principal_id=principal_id, scan_id=payload.scan_id
        )
        _audit(
            repo=repo,
            tenant_id=tenant_id,
            actor_user_id=user.id,
            resource_type="integration_delivery",
            target_id=str(row.id),
            reason_code="integration_policy_event_enqueued",
        )
        await repo.db.commit()
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from None
    return OutboxRead.model_validate(row)


@router.post(
    "/principals/{principal_id}/ticket-events",
    response_model=OutboxRead,
    dependencies=[Depends(require_permission(SERVICE_PRINCIPAL_MANAGE))],
)
async def enqueue_ticket_event(
    principal_id: uuid.UUID,
    payload: TicketSyncRequest,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user: db_models.User = Depends(current_active_user),
    repo: IntegrationRepository = Depends(_repo),
) -> OutboxRead:
    try:
        row, _ = await IntegrationService(repo).enqueue_ticket_sync(
            tenant_id=tenant_id,
            principal_id=principal_id,
            canonical_root_id=payload.canonical_root_id,
            title=payload.title,
            severity=payload.severity,
            status=payload.status,
            waiver_expires_at=payload.waiver_expires_at,
            reason=payload.reason,
            authorized_view=payload.authorized_view,
        )
        _audit(
            repo=repo,
            tenant_id=tenant_id,
            actor_user_id=user.id,
            resource_type="integration_delivery",
            target_id=str(row.id),
            reason_code="integration_ticket_event_enqueued",
        )
        await repo.db.commit()
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from None
    return OutboxRead.model_validate(row)


@router.get(
    "/deliveries",
    response_model=list[OutboxRead],
    dependencies=[Depends(require_permission(AUDIT_READ))],
)
async def list_deliveries(
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    limit: int = Query(100, ge=1, le=500),
    repo: IntegrationRepository = Depends(_repo),
) -> list[OutboxRead]:
    return [
        OutboxRead.model_validate(row)
        for row in await repo.list_outbox(tenant_id=tenant_id, limit=limit)
    ]


@router.post(
    "/deliveries/{outbox_id}/retry",
    response_model=OutboxRead,
    dependencies=[Depends(require_permission(SERVICE_PRINCIPAL_MANAGE))],
)
async def retry_delivery(
    outbox_id: uuid.UUID,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user: db_models.User = Depends(current_active_user),
    repo: IntegrationRepository = Depends(_repo),
) -> OutboxRead:
    try:
        row = await repo.requeue_dead_letter(tenant_id=tenant_id, outbox_id=outbox_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    if row is None:
        raise HTTPException(status_code=404, detail="Delivery not found.")
    _audit(
        repo=repo,
        tenant_id=tenant_id,
        actor_user_id=user.id,
        resource_type="integration_delivery",
        target_id=str(row.id),
        reason_code="integration_dead_letter_requeued",
    )
    await repo.db.commit()
    return OutboxRead.model_validate(row)


@router.get(
    "/delivery-audit",
    response_model=list[DeliveryAuditRead],
    dependencies=[Depends(require_permission(AUDIT_READ))],
)
async def list_delivery_audit(
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    limit: int = Query(100, ge=1, le=500),
    repo: IntegrationRepository = Depends(_repo),
) -> list[DeliveryAuditRead]:
    return [
        DeliveryAuditRead.model_validate(row)
        for row in await repo.list_audit(tenant_id=tenant_id, limit=limit)
    ]


@router.get(
    "/tickets",
    response_model=list[FindingTicketRead],
    dependencies=[Depends(require_permission(AUDIT_READ))],
)
async def list_tickets(
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    limit: int = Query(100, ge=1, le=500),
    repo: IntegrationRepository = Depends(_repo),
) -> list[FindingTicketRead]:
    return [
        FindingTicketRead.model_validate(row)
        for row in await repo.list_tickets(tenant_id=tenant_id, limit=limit)
    ]


@router.post(
    "/principals/{principal_id}/github/source",
    dependencies=[Depends(require_permission(SERVICE_PRINCIPAL_MANAGE))],
)
async def download_github_source(
    principal_id: uuid.UUID,
    payload: GithubSourceRequest,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user: db_models.User = Depends(current_active_user),
    repo: IntegrationRepository = Depends(_repo),
) -> Response:
    try:
        async with configured_pinned_http_client() as http:
            archive = await IntegrationService(repo).download_github_source(
                tenant_id=tenant_id,
                principal_id=principal_id,
                commit_sha=payload.commit_sha,
                http=http,
            )
        _audit(
            repo=repo,
            tenant_id=tenant_id,
            actor_user_id=user.id,
            resource_type="integration_github_source",
            target_id=f"{principal_id}:{payload.commit_sha}",
            reason_code="integration_github_source_downloaded",
        )
        await repo.db.commit()
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from None
    except (httpx.HTTPError, IntegrationContractError) as exc:
        raise HTTPException(
            status_code=502, detail="GitHub source retrieval failed."
        ) from exc
    return Response(
        archive,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="github-{payload.commit_sha}.zip"'
        },
    )


@router.post(
    "/principals/{principal_id}/github/sarif",
    dependencies=[Depends(require_permission(SERVICE_PRINCIPAL_MANAGE))],
)
async def upload_github_sarif(
    principal_id: uuid.UUID,
    payload: GithubSarifRequest,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user: db_models.User = Depends(current_active_user),
    visible_user_ids=Depends(get_visible_user_ids),
    scan_service: ScanQueryService = Depends(get_scan_query_service),
    repo: IntegrationRepository = Depends(_repo),
) -> dict[str, object]:
    result = await scan_service.get_scan_result(
        payload.scan_id,
        user,
        include_source=False,
        visible_user_ids=visible_user_ids,
        tenant_id=tenant_id,
    )
    sarif = generate_report(result, "sarif").content
    try:
        async with configured_pinned_http_client() as http:
            delivered = await IntegrationService(repo).upload_github_sarif(
                tenant_id=tenant_id,
                principal_id=principal_id,
                commit_sha=payload.commit_sha,
                ref=payload.ref,
                sarif=sarif,
                http=http,
            )
        if delivered.delivered:
            _audit(
                repo=repo,
                tenant_id=tenant_id,
                actor_user_id=user.id,
                resource_type="integration_github_sarif",
                target_id=f"{principal_id}:{payload.scan_id}:{payload.commit_sha}",
                reason_code="integration_github_sarif_uploaded",
            )
            await repo.db.commit()
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from None
    except (httpx.HTTPError, IntegrationContractError) as exc:
        raise HTTPException(
            status_code=502, detail="GitHub SARIF upload failed."
        ) from exc
    if not delivered.delivered:
        raise HTTPException(status_code=502, detail="GitHub rejected the SARIF upload.")
    return {"delivered": True, "status": delivered.http_status}
