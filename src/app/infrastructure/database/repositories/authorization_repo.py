"""Persistence and concurrency boundary for role and SoD authorization state."""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from collections.abc import Collection, Mapping
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.config import settings
from app.config.logging_config import correlation_id_var
from app.infrastructure.database import models as db_models
from app.shared.lib.permissions import PLATFORM_OWNER, permissions_for_roles


class AuthorizationConflictError(RuntimeError):
    """The requested authorization transition conflicts with durable state."""


class AuthorizationDeniedError(RuntimeError):
    """The principal or action request does not satisfy authorization policy."""


def _secret_bytes() -> bytes:
    configured = settings.SECRET_KEY
    value = (
        configured.get_secret_value()
        if hasattr(configured, "get_secret_value")
        else str(configured)
    )
    return value.encode("utf-8")


def target_fingerprint(*, resource_type: str, target_id: str) -> str:
    """Return a privacy-safe, deployment-keyed target identifier."""

    return hmac.new(
        _secret_bytes(),
        f"authz-target:{resource_type}:{target_id}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def payload_digest(payload: Mapping[str, Any]) -> str:
    """Bind approval to a canonical JSON representation of the action."""

    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class AuthorizationRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def role_keys_for_user(
        self, *, user: db_models.User, tenant_id: uuid.UUID
    ) -> frozenset[str]:
        rows = await self.db.scalars(
            select(db_models.RoleAssignment.role_key).where(
                db_models.RoleAssignment.user_id == user.id,
                (
                    (db_models.RoleAssignment.tenant_id == tenant_id)
                    | (db_models.RoleAssignment.tenant_id.is_(None))
                ),
            )
        )
        role_keys = set(rows.all())
        # Bounded rollout compatibility: migrations create this assignment,
        # but an old/bootstrap row encountered before backfill must fail safe
        # for availability without reintroducing global query bypass logic.
        if user.is_superuser:
            role_keys.add(PLATFORM_OWNER)
        return frozenset(role_keys)

    async def permissions_for_user(
        self, *, user: db_models.User, tenant_id: uuid.UUID
    ) -> frozenset[str]:
        return permissions_for_roles(
            await self.role_keys_for_user(user=user, tenant_id=tenant_id)
        )

    async def separation_of_duties_mode(self, *, tenant_id: uuid.UUID) -> str:
        """Return the tenant's fail-closed high-risk approval mode."""

        mode = await self.db.scalar(
            select(db_models.Tenant.separation_of_duties_mode).where(
                db_models.Tenant.id == tenant_id
            )
        )
        if mode not in {"off", "critical"}:
            raise AuthorizationDeniedError("tenant authorization policy unavailable")
        return mode

    async def create_action_request(
        self,
        *,
        tenant_id: uuid.UUID,
        requester_user_id: int,
        requester_permission: str,
        approver_permission: str,
        target_type: str,
        target_fingerprint_value: str,
        payload_digest_value: str,
        idempotency_key: str,
        expires_at: datetime,
    ) -> db_models.AuthorizationActionRequest:
        if expires_at <= datetime.now(timezone.utc):
            raise AuthorizationConflictError("action request expiry must be in future")
        stmt = (
            pg_insert(db_models.AuthorizationActionRequest)
            .values(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                requester_user_id=requester_user_id,
                requester_permission=requester_permission,
                approver_permission=approver_permission,
                target_type=target_type,
                target_fingerprint=target_fingerprint_value,
                payload_digest=payload_digest_value,
                idempotency_key=idempotency_key,
                expires_at=expires_at,
            )
            .on_conflict_do_nothing(
                constraint="uq_authorization_action_requests_tenant_idempotency"
            )
            .returning(db_models.AuthorizationActionRequest.id)
        )
        inserted_id = (await self.db.execute(stmt)).scalar_one_or_none()
        if inserted_id is not None:
            row = await self.db.get(db_models.AuthorizationActionRequest, inserted_id)
            if row is None:  # pragma: no cover - INSERT RETURNING contract
                raise AuthorizationConflictError("inserted action request disappeared")
            return row

        existing = await self.db.scalar(
            select(db_models.AuthorizationActionRequest).where(
                db_models.AuthorizationActionRequest.tenant_id == tenant_id,
                db_models.AuthorizationActionRequest.idempotency_key == idempotency_key,
            )
        )
        if existing is None:  # pragma: no cover - unique conflict contract
            raise AuthorizationConflictError("action request conflict was not readable")
        immutable_values = (
            existing.requester_user_id,
            existing.requester_permission,
            existing.approver_permission,
            existing.target_type,
            existing.target_fingerprint,
            existing.payload_digest,
        )
        requested_values = (
            requester_user_id,
            requester_permission,
            approver_permission,
            target_type,
            target_fingerprint_value,
            payload_digest_value,
        )
        if immutable_values != requested_values:
            raise AuthorizationConflictError(
                "idempotency key is bound to a different action"
            )
        return existing

    async def decide_action_request(
        self,
        *,
        request_id: uuid.UUID,
        tenant_id: uuid.UUID,
        approver_user_id: int,
        approver_permissions: Collection[str],
        requester_permissions: Collection[str],
        approved: bool,
        reason: str,
    ) -> db_models.AuthorizationActionRequest:
        row = await self.db.scalar(
            select(db_models.AuthorizationActionRequest)
            .where(
                db_models.AuthorizationActionRequest.id == request_id,
                db_models.AuthorizationActionRequest.tenant_id == tenant_id,
            )
            .with_for_update()
        )
        if row is None:
            raise AuthorizationDeniedError("action request not found")
        now = datetime.now(timezone.utc)
        if row.status != "pending":
            if (
                row.approver_user_id == approver_user_id
                and row.status == ("approved" if approved else "rejected")
            ):
                return row
            raise AuthorizationConflictError("action request already decided")
        if row.expires_at <= now:
            raise AuthorizationConflictError("action request expired")
        if row.requester_user_id == approver_user_id:
            raise AuthorizationDeniedError("requester cannot approve own action")
        if row.approver_permission not in approver_permissions:
            raise AuthorizationDeniedError("approver permission missing")
        if row.requester_permission not in requester_permissions:
            raise AuthorizationDeniedError("requester permission no longer active")
        normalized_reason = reason.strip()
        if not normalized_reason:
            raise AuthorizationConflictError("decision reason is required")
        row.status = "approved" if approved else "rejected"
        row.approver_user_id = approver_user_id
        row.decided_at = now
        row.decision_reason = normalized_reason[:500]
        return row

    async def mark_executed(
        self,
        *,
        request_id: uuid.UUID,
        tenant_id: uuid.UUID,
        payload_digest_value: str,
        requester_permissions: Collection[str],
        approver_permissions: Collection[str],
    ) -> db_models.AuthorizationActionRequest:
        row = await self.db.scalar(
            select(db_models.AuthorizationActionRequest)
            .where(
                db_models.AuthorizationActionRequest.id == request_id,
                db_models.AuthorizationActionRequest.tenant_id == tenant_id,
            )
            .with_for_update()
        )
        if row is None:
            raise AuthorizationDeniedError("action request not found")
        if row.status == "executed":
            return row
        if row.status != "approved":
            raise AuthorizationDeniedError("action request is not approved")
        if row.payload_digest != payload_digest_value:
            raise AuthorizationDeniedError("approved payload changed")
        if row.requester_permission not in requester_permissions:
            raise AuthorizationDeniedError("requester permission no longer active")
        if row.approver_permission not in approver_permissions:
            raise AuthorizationDeniedError("approver permission no longer active")
        row.status = "executed"
        row.executed_at = datetime.now(timezone.utc)
        return row

    def record_audit(
        self,
        *,
        tenant_id: uuid.UUID | None,
        principal_kind: str,
        principal_id: str,
        permission: str,
        resource_type: str,
        outcome: str,
        reason_code: str,
        target_fingerprint_value: str | None = None,
        action_request_id: uuid.UUID | None = None,
        approver_principal_id: str | None = None,
    ) -> db_models.AuthorizationAuditEvent:
        row = db_models.AuthorizationAuditEvent(
            tenant_id=tenant_id,
            principal_kind=principal_kind,
            principal_id=principal_id,
            permission=permission,
            resource_type=resource_type,
            target_fingerprint=target_fingerprint_value,
            outcome=outcome,
            reason_code=reason_code,
            correlation_id=correlation_id_var.get(),
            action_request_id=action_request_id,
            approver_principal_id=approver_principal_id,
        )
        self.db.add(row)
        return row
