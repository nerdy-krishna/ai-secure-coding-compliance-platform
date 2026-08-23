"""Tenant-scoped SSO administration under `/api/v1/admin/sso/*`.

Surface:

* ``GET    /admin/sso/providers``                  — list (secrets redacted)
* ``GET    /admin/sso/providers/{id}``             — detail (secrets redacted)
* ``POST   /admin/sso/providers``                  — create (validates protocol-specific config)
* ``PATCH  /admin/sso/providers/{id}``             — update (accepts ``"<<unchanged>>"`` sentinel for secrets)
* ``DELETE /admin/sso/providers/{id}``             — delete (cascades to oauth_accounts + saml_subjects)
* ``POST   /admin/sso/providers/{id}/test``        — preflight (OIDC discovery / SAML metadata parse)
* ``GET    /admin/sso/audit``                      — paginated auth_audit_events

Mitigations:
  * **M13** — secrets (``client_secret``, ``sp_private_key``) NEVER round-trip
    out of the API; PATCH accepts a literal ``"<<unchanged>>"`` to keep the
    existing value without re-entry.
  * Every CRUD mutation writes ``auth.provider.{created,updated,deleted}`` audit rows.
  * **M14** — preflight uses bounded httpx timeouts (inherited from oidc.py).
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import (
    APIRouter,
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

from app.api.v1.dependencies import (
    get_current_permissions,
    get_current_user_tenant_id,
    require_permission,
)
from app.api.v1.routers.authorization import ActionRequestRead, action_request_to_read
from app.infrastructure.auth.core import current_active_user
from app.infrastructure.auth.sso import audit, oidc, saml
from app.infrastructure.auth.sso.domains import (
    DomainVerificationError,
    ensure_verified_provider_domains,
)
from app.infrastructure.auth.sso.models import (
    OidcConfig,
    SamlConfig,
    SsoProtocol,
    parse_provider_config,
)
from app.infrastructure.auth.sso.repository import SsoProviderRepository
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db
from app.infrastructure.database.repositories.auth_session_repo import (
    AuthSessionRepository,
)
from app.infrastructure.database.repositories.authorization_repo import (
    AuthorizationConflictError,
    AuthorizationDeniedError,
    AuthorizationRepository,
    payload_digest,
    target_fingerprint,
)
from app.shared.lib.permissions import AUDIT_READ, TENANT_POLICY_MANAGE

logger = logging.getLogger(__name__)


router = APIRouter(prefix="/admin/sso", tags=["Admin: SSO"])

# Sentinel used by PATCH to indicate "keep the existing secret without
# re-entering" — admins can update the issuer URL without typing the
# client_secret again.
_UNCHANGED = "<<unchanged>>"
_REDACTED = "***"
_DELETE_PROVIDER_PAYLOAD = {"operation": "delete_sso_provider"}


# ---------- request / response schemas ---------------------------------------


class ProviderRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    display_name: str
    # F11: Pydantic ``Literal`` on the read shape. Even if a future migration
    # loosens the DB CHECK constraint, this catches an unknown ``protocol``
    # value at the wire boundary instead of silently accepting it.
    protocol: SsoProtocol
    enabled: bool
    allowed_email_domains: Optional[List[str]] = None
    force_for_domains: Optional[List[str]] = None
    jit_policy: str
    created_at: datetime
    updated_at: datetime
    # Decrypted config WITH SECRETS REDACTED. The frontend admin form
    # uses this to populate non-secret fields and shows ``***`` for secrets.
    config: Dict[str, Any]


class ProviderCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$")
    display_name: str = Field(..., min_length=1, max_length=128)
    protocol: SsoProtocol
    config: Dict[str, Any]
    enabled: bool = True
    allowed_email_domains: Optional[List[str]] = None
    force_for_domains: Optional[List[str]] = None
    jit_policy: str = Field(default="auto", pattern=r"^(auto|approve|deny)$")


class ProviderUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: Optional[str] = Field(default=None, min_length=1, max_length=128)
    enabled: Optional[bool] = None
    config: Optional[Dict[str, Any]] = None
    allowed_email_domains: Optional[List[str]] = None
    force_for_domains: Optional[List[str]] = None
    jit_policy: Optional[str] = Field(default=None, pattern=r"^(auto|approve|deny)$")


class AuditRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ts: datetime
    event: str
    user_id: Optional[int]
    provider_id: Optional[uuid.UUID]
    email_hash: Optional[str]
    ip: Optional[str]
    user_agent: Optional[str]
    details: Optional[Dict[str, Any]]


# ---------- helpers ----------------------------------------------------------


def _redact_config(protocol: str, plaintext: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of the config with secret fields replaced by ``***``."""
    out = dict(plaintext)
    if protocol == "oidc":
        if "client_secret" in out:
            out["client_secret"] = _REDACTED
    elif protocol == "saml":
        if "sp_private_key" in out:
            out["sp_private_key"] = _REDACTED
    return out


async def _to_read(
    repo: SsoProviderRepository, row: db_models.SsoProvider
) -> ProviderRead:
    bundle = await repo.get_with_config(row.id, tenant_id=row.tenant_id)
    if bundle is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="provider config could not be loaded",
        )
    plain = bundle.config.model_dump(mode="json")
    return ProviderRead(
        id=row.id,
        name=row.name,
        display_name=row.display_name,
        protocol=row.protocol,
        enabled=row.enabled,
        allowed_email_domains=row.allowed_email_domains,
        force_for_domains=row.force_for_domains,
        jit_policy=row.jit_policy,
        created_at=row.created_at,
        updated_at=row.updated_at,
        config=_redact_config(row.protocol, plain),
    )


def _merge_secrets(
    *,
    incoming: Dict[str, Any],
    existing_plain: Dict[str, Any],
    protocol: str,
) -> Dict[str, Any]:
    """Replace ``"<<unchanged>>"`` placeholders with the existing secret values.

    Allows admins to update non-secret fields (e.g. issuer URL) without
    re-entering the secret.
    """
    secret_fields = {
        "oidc": ("client_secret",),
        "saml": ("sp_private_key",),
    }.get(protocol, tuple())
    out = dict(incoming)
    for field in secret_fields:
        if out.get(field) in (_UNCHANGED, _REDACTED):
            existing = existing_plain.get(field)
            if existing is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"{field}: cannot keep unchanged — no existing value",
                )
            out[field] = existing
    return out


def _provider_fingerprint(*, tenant_id: uuid.UUID, provider_id: uuid.UUID) -> str:
    return target_fingerprint(
        resource_type="sso_provider",
        target_id=f"{tenant_id}:{provider_id}",
    )


# ---------- endpoints --------------------------------------------------------


@router.get(
    "/providers",
    response_model=List[ProviderRead],
    dependencies=[Depends(require_permission(TENANT_POLICY_MANAGE))],
)
async def list_providers(
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    db: AsyncSession = Depends(get_db),
):
    repo = SsoProviderRepository(db)
    rows = await repo.list_all(tenant_id=tenant_id)
    return [await _to_read(repo, row) for row in rows]


@router.post(
    "/providers",
    response_model=ProviderRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(TENANT_POLICY_MANAGE))],
)
async def create_provider(
    payload: ProviderCreate,
    request: Request,
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    db: AsyncSession = Depends(get_db),
    user: db_models.User = Depends(current_active_user),
):
    repo = SsoProviderRepository(db)
    # Reject duplicate slug.
    if await repo.get_by_name(payload.name, tenant_id=tenant_id) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"provider name {payload.name!r} already exists",
        )
    # Validate config shape against the protocol model.
    try:
        parse_provider_config(payload.protocol, payload.config)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid config: {exc}")
    try:
        allowed_domains, forced_domains = await ensure_verified_provider_domains(
            db,
            tenant_id=tenant_id,
            allowed_domains=payload.allowed_email_domains,
            forced_domains=payload.force_for_domains,
            jit_policy=payload.jit_policy,
        )
    except DomainVerificationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    row = await repo.create(
        name=payload.name,
        display_name=payload.display_name,
        protocol=payload.protocol,
        config_plain=payload.config,
        enabled=payload.enabled,
        allowed_email_domains=allowed_domains,
        force_for_domains=forced_domains,
        jit_policy=payload.jit_policy,
        tenant_id=tenant_id,
    )
    await audit.record(
        db,
        event=audit.EVENT_PROVIDER_CREATED,
        actor_user_id=user.id,
        provider_id=row.id,
        tenant_id=row.tenant_id,
        outcome="success",
        request=request,
        details={"name": payload.name, "protocol": payload.protocol},
    )
    await db.commit()
    return await _to_read(repo, row)


@router.get(
    "/providers/{provider_id}",
    response_model=ProviderRead,
    dependencies=[Depends(require_permission(TENANT_POLICY_MANAGE))],
)
async def get_provider(
    provider_id: uuid.UUID = Path(...),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    db: AsyncSession = Depends(get_db),
):
    repo = SsoProviderRepository(db)
    row = await repo.get_by_id(provider_id, tenant_id=tenant_id)
    if row is None:
        raise HTTPException(status_code=404, detail="not found")
    return await _to_read(repo, row)


@router.patch(
    "/providers/{provider_id}",
    response_model=ProviderRead,
    dependencies=[Depends(require_permission(TENANT_POLICY_MANAGE))],
)
async def update_provider(
    payload: ProviderUpdate,
    request: Request,
    provider_id: uuid.UUID = Path(...),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    db: AsyncSession = Depends(get_db),
    user: db_models.User = Depends(current_active_user),
):
    repo = SsoProviderRepository(db)
    row = await repo.get_by_id(provider_id, tenant_id=tenant_id)
    if row is None:
        raise HTTPException(status_code=404, detail="not found")

    config_plain: Optional[Dict[str, Any]] = None
    if payload.config is not None:
        # Pull the current decrypted config so we can re-merge secrets.
        bundle = await repo.get_with_config(provider_id, tenant_id=tenant_id)
        if bundle is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="config unavailable",
            )
        existing_plain = bundle.config.model_dump(mode="json")
        config_plain = _merge_secrets(
            incoming=payload.config,
            existing_plain=existing_plain,
            protocol=row.protocol,
        )
        try:
            parse_provider_config(row.protocol, config_plain)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"invalid config: {exc}")

    effective_allowed = (
        payload.allowed_email_domains
        if payload.allowed_email_domains is not None
        else row.allowed_email_domains
    )
    effective_forced = (
        payload.force_for_domains
        if payload.force_for_domains is not None
        else row.force_for_domains
    )
    effective_jit = payload.jit_policy or row.jit_policy
    try:
        normalized_allowed, normalized_forced = await ensure_verified_provider_domains(
            db,
            tenant_id=row.tenant_id,
            allowed_domains=effective_allowed,
            forced_domains=effective_forced,
            jit_policy=effective_jit,
        )
    except DomainVerificationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    updated = await repo.update_fields(
        provider_id,
        tenant_id=tenant_id,
        display_name=payload.display_name,
        enabled=payload.enabled,
        config_plain=config_plain,
        allowed_email_domains=(
            normalized_allowed if payload.allowed_email_domains is not None else None
        ),
        force_for_domains=(
            normalized_forced if payload.force_for_domains is not None else None
        ),
        jit_policy=payload.jit_policy,
    )
    if updated is None:
        raise HTTPException(status_code=404, detail="not found")
    await audit.record(
        db,
        event=audit.EVENT_PROVIDER_UPDATED,
        actor_user_id=user.id,
        provider_id=provider_id,
        tenant_id=row.tenant_id,
        outcome="success",
        request=request,
        details={
            "fields": [
                k
                for k in (
                    "display_name",
                    "enabled",
                    "config",
                    "allowed_email_domains",
                    "force_for_domains",
                    "jit_policy",
                )
                if getattr(payload, k) is not None
            ],
        },
    )
    await db.commit()
    return await _to_read(repo, updated)


@router.post(
    "/providers/{provider_id}/deletion-requests",
    response_model=ActionRequestRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(TENANT_POLICY_MANAGE))],
)
async def request_provider_deletion(
    provider_id: uuid.UUID = Path(...),
    idempotency_key: str = Header(..., alias="X-Idempotency-Key", max_length=128),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    permissions: frozenset[str] = Depends(get_current_permissions),
    db: AsyncSession = Depends(get_db),
    user: db_models.User = Depends(current_active_user),
) -> ActionRequestRead:
    provider = await SsoProviderRepository(db).get_by_id(
        provider_id, tenant_id=tenant_id
    )
    if provider is None:
        raise HTTPException(status_code=404, detail="not found")
    authz = AuthorizationRepository(db)
    if await authz.separation_of_duties_mode(tenant_id=tenant_id) != "critical":
        raise HTTPException(
            status_code=409,
            detail="A distinct-actor request is only used in critical mode.",
        )
    fingerprint = _provider_fingerprint(
        tenant_id=tenant_id, provider_id=provider_id
    )
    try:
        action = await authz.create_action_request(
            tenant_id=tenant_id,
            requester_user_id=user.id,
            requester_permission=TENANT_POLICY_MANAGE,
            approver_permission=TENANT_POLICY_MANAGE,
            target_type="sso_provider_delete",
            target_fingerprint_value=fingerprint,
            payload_digest_value=payload_digest(_DELETE_PROVIDER_PAYLOAD),
            idempotency_key=idempotency_key,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
    except AuthorizationConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    authz.record_audit(
        tenant_id=tenant_id,
        principal_kind="human",
        principal_id=str(user.id),
        permission=TENANT_POLICY_MANAGE,
        resource_type="sso_provider",
        target_fingerprint_value=fingerprint,
        outcome="requested",
        reason_code="provider_deletion_requested",
        action_request_id=action.id,
    )
    await db.commit()
    return action_request_to_read(
        action, actor_user_id=user.id, permissions=permissions
    )


@router.delete(
    "/providers/{provider_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission(TENANT_POLICY_MANAGE))],
)
async def delete_provider(
    request: Request,
    provider_id: uuid.UUID = Path(...),
    action_request_id: uuid.UUID | None = Query(default=None),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    permissions: frozenset[str] = Depends(get_current_permissions),
    db: AsyncSession = Depends(get_db),
    user: db_models.User = Depends(current_active_user),
):
    repo = SsoProviderRepository(db)
    row = await db.scalar(
        select(db_models.SsoProvider)
        .where(
            db_models.SsoProvider.id == provider_id,
            db_models.SsoProvider.tenant_id == tenant_id,
        )
        .with_for_update()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="not found")
    authz = AuthorizationRepository(db)
    fingerprint = _provider_fingerprint(
        tenant_id=tenant_id, provider_id=provider_id
    )
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
            or action.target_type != "sso_provider_delete"
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
                payload_digest_value=payload_digest(_DELETE_PROVIDER_PAYLOAD),
                requester_permissions=permissions,
                approver_permissions=approver_permissions,
            )
        except (AuthorizationConflictError, AuthorizationDeniedError) as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        approver_id = action.approver_user_id
    elif action_request_id is not None:
        raise HTTPException(
            status_code=400,
            detail="An action request is not applicable to this provider deletion.",
        )

    revoked = await AuthSessionRepository(db).revoke_all_for_provider(
        provider_id,
        reason="provider_deleted",
    )
    await audit.record(
        db,
        event="session.provider_revoked_all",
        actor_user_id=user.id,
        provider_id=provider_id,
        tenant_id=row.tenant_id,
        outcome="success",
        request=request,
        details={"reason": "provider_deleted", "revoked_count": revoked},
    )
    await audit.record(
        db,
        event=audit.EVENT_PROVIDER_DELETED,
        actor_user_id=user.id,
        provider_id=provider_id,
        tenant_id=tenant_id,
        outcome="success",
        request=request,
        details={"approval_required": requires_approval},
    )
    deleted = await repo.delete(provider_id, tenant_id=tenant_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="not found")
    authz.record_audit(
        tenant_id=tenant_id,
        principal_kind="human",
        principal_id=str(user.id),
        permission=TENANT_POLICY_MANAGE,
        resource_type="sso_provider",
        target_fingerprint_value=fingerprint,
        outcome="executed" if requires_approval else "allowed",
        reason_code=(
            "approved_provider_deletion_executed"
            if requires_approval
            else "provider_deleted"
        ),
        action_request_id=action_request_id,
        approver_principal_id=str(approver_id) if approver_id is not None else None,
    )
    await db.commit()


@router.post(
    "/providers/{provider_id}/test",
    dependencies=[Depends(require_permission(TENANT_POLICY_MANAGE))],
)
async def test_provider(
    provider_id: uuid.UUID = Path(...),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    db: AsyncSession = Depends(get_db),
):
    """Preflight — OIDC discovery fetch / SAML metadata build."""
    repo = SsoProviderRepository(db)
    bundle = await repo.get_with_config(provider_id, tenant_id=tenant_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="not found")
    cfg = bundle.config
    if isinstance(cfg, OidcConfig):
        return await oidc.preflight_test(cfg)
    if isinstance(cfg, SamlConfig):
        return saml.preflight_test(cfg)
    raise HTTPException(status_code=500, detail="unknown protocol")


@router.get(
    "/audit",
    response_model=List[AuditRead],
    dependencies=[Depends(require_permission(AUDIT_READ))],
)
async def list_audit_events(
    limit: int = Query(default=100, ge=1, le=500),
    cursor: Optional[datetime] = Query(default=None),
    event: Optional[str] = Query(default=None, max_length=64),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    db: AsyncSession = Depends(get_db),
):
    """Paginated audit list, most-recent-first. ``cursor`` is the ``ts``
    of the last row from the previous page (exclusive)."""
    stmt = (
        select(db_models.AuthAuditEvent)
        .where(db_models.AuthAuditEvent.tenant_id == tenant_id)
        .order_by(db_models.AuthAuditEvent.ts.desc())
    )
    if cursor is not None:
        stmt = stmt.where(db_models.AuthAuditEvent.ts < cursor)
    if event:
        stmt = stmt.where(db_models.AuthAuditEvent.event == event)
    stmt = stmt.limit(limit)
    result = await db.execute(stmt)
    rows = list(result.scalars().all())
    return [AuditRead.model_validate(row) for row in rows]


__all__ = ["router"]
