"""Tenant-first persistence for enterprise integration principals and delivery."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import String, and_, cast, literal, or_, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models
from app.shared.lib.integration_contract import (
    payload_digest,
    redact_integration_payload,
    stable_idempotency_key,
)


def _required_delivery_feature(*, principal_kind: str, event_type: str) -> str | None:
    if principal_kind == "siem_webhook":
        return "siem_emit"
    if principal_kind == "jira_cloud" and event_type == "finding.ticket.sync":
        return "ticket_sync"
    return None


class IntegrationRepository:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def create_principal(
        self,
        *,
        principal_id: uuid.UUID,
        tenant_id: uuid.UUID,
        kind: str,
        display_name: str,
        config: dict[str, Any],
        secrets_encrypted: bytes,
        secret_fingerprint: str,
        created_by_user_id: int,
    ) -> db_models.IntegrationServicePrincipal:
        row = db_models.IntegrationServicePrincipal(
            id=principal_id,
            tenant_id=tenant_id,
            kind=kind,
            display_name=display_name,
            config=redact_integration_payload(config),
            secrets_encrypted=secrets_encrypted,
            secret_fingerprint=secret_fingerprint,
            created_by_user_id=created_by_user_id,
        )
        self.db.add(row)
        await self.db.flush()
        return row

    async def list_principals(
        self, *, tenant_id: uuid.UUID
    ) -> list[db_models.IntegrationServicePrincipal]:
        return list(
            (
                await self.db.scalars(
                    select(db_models.IntegrationServicePrincipal)
                    .where(db_models.IntegrationServicePrincipal.tenant_id == tenant_id)
                    .order_by(db_models.IntegrationServicePrincipal.created_at.desc())
                )
            ).all()
        )

    async def get_principal(
        self,
        *,
        tenant_id: uuid.UUID,
        principal_id: uuid.UUID,
        active_only: bool = False,
    ) -> db_models.IntegrationServicePrincipal | None:
        statement = select(db_models.IntegrationServicePrincipal).where(
            db_models.IntegrationServicePrincipal.id == principal_id,
            db_models.IntegrationServicePrincipal.tenant_id == tenant_id,
        )
        if active_only:
            statement = statement.where(
                db_models.IntegrationServicePrincipal.enabled.is_(True),
                db_models.IntegrationServicePrincipal.revoked_at.is_(None),
            )
        return await self.db.scalar(statement)

    async def get_active_principal_unscoped(
        self, *, principal_id: uuid.UUID, kind: str | None = None
    ) -> db_models.IntegrationServicePrincipal | None:
        """Public-webhook lookup; RLS still requires a system-bound session."""

        statement = select(db_models.IntegrationServicePrincipal).where(
            db_models.IntegrationServicePrincipal.id == principal_id,
            db_models.IntegrationServicePrincipal.enabled.is_(True),
            db_models.IntegrationServicePrincipal.revoked_at.is_(None),
        )
        if kind:
            statement = statement.where(
                db_models.IntegrationServicePrincipal.kind == kind
            )
        return await self.db.scalar(statement)

    async def revoke_principal(
        self,
        *,
        tenant_id: uuid.UUID,
        principal_id: uuid.UUID,
        actor_user_id: int,
        now: datetime | None = None,
    ) -> bool:
        timestamp = now or datetime.now(timezone.utc)
        result = await self.db.execute(
            update(db_models.IntegrationServicePrincipal)
            .where(
                db_models.IntegrationServicePrincipal.id == principal_id,
                db_models.IntegrationServicePrincipal.tenant_id == tenant_id,
                db_models.IntegrationServicePrincipal.revoked_at.is_(None),
            )
            .values(
                enabled=False,
                revoked_at=timestamp,
                revoked_by_user_id=actor_user_id,
                updated_at=timestamp,
            )
        )
        if not result.rowcount:
            return False
        await self.db.execute(
            update(db_models.IntegrationGrant)
            .where(
                db_models.IntegrationGrant.tenant_id == tenant_id,
                db_models.IntegrationGrant.principal_id == principal_id,
                db_models.IntegrationGrant.revoked_at.is_(None),
            )
            .values(revoked_at=timestamp, revoked_by_user_id=actor_user_id)
        )
        await self.db.execute(
            update(db_models.IntegrationOutbox)
            .where(
                db_models.IntegrationOutbox.tenant_id == tenant_id,
                db_models.IntegrationOutbox.principal_id == principal_id,
                db_models.IntegrationOutbox.state.in_(
                    ("pending", "retry", "delivering")
                ),
            )
            .values(state="dead_letter", last_error_code="principal_revoked")
        )
        return True

    async def grant_feature(
        self,
        *,
        tenant_id: uuid.UUID,
        principal_id: uuid.UUID,
        feature: str,
        scope: dict[str, Any],
        actor_user_id: int,
    ) -> db_models.IntegrationGrant:
        safe_scope = redact_integration_payload(scope)
        digest = payload_digest(safe_scope)
        statement = (
            pg_insert(db_models.IntegrationGrant)
            .values(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                principal_id=principal_id,
                feature=feature,
                scope=safe_scope,
                scope_digest=digest,
                created_by_user_id=actor_user_id,
            )
            .on_conflict_do_nothing(
                index_elements=["principal_id", "feature", "scope_digest"],
                index_where=db_models.IntegrationGrant.revoked_at.is_(None),
            )
            .returning(db_models.IntegrationGrant)
        )
        created = (await self.db.execute(statement)).scalar_one_or_none()
        if created is not None:
            return created
        existing = await self.db.scalar(
            select(db_models.IntegrationGrant).where(
                db_models.IntegrationGrant.tenant_id == tenant_id,
                db_models.IntegrationGrant.principal_id == principal_id,
                db_models.IntegrationGrant.feature == feature,
                db_models.IntegrationGrant.scope_digest == digest,
                db_models.IntegrationGrant.revoked_at.is_(None),
            )
        )
        if existing is None:
            raise RuntimeError("integration grant conflict row disappeared")
        return existing

    async def has_active_grant(
        self,
        *,
        tenant_id: uuid.UUID,
        principal_id: uuid.UUID,
        feature: str,
        event_type: str | None = None,
        lock: bool = False,
    ) -> bool:
        conditions = [
            db_models.IntegrationGrant.tenant_id == tenant_id,
            db_models.IntegrationGrant.principal_id == principal_id,
            db_models.IntegrationGrant.feature == feature,
            db_models.IntegrationGrant.revoked_at.is_(None),
        ]
        if event_type is not None:
            conditions.append(
                db_models.IntegrationGrant.scope.contains({"event_types": [event_type]})
            )
        statement = select(db_models.IntegrationGrant.id).where(*conditions)
        if lock:
            statement = statement.with_for_update(read=True)
        return await self.db.scalar(statement) is not None

    async def list_grants(
        self, *, tenant_id: uuid.UUID, principal_id: uuid.UUID
    ) -> list[db_models.IntegrationGrant]:
        return list(
            (
                await self.db.scalars(
                    select(db_models.IntegrationGrant)
                    .where(
                        db_models.IntegrationGrant.tenant_id == tenant_id,
                        db_models.IntegrationGrant.principal_id == principal_id,
                    )
                    .order_by(db_models.IntegrationGrant.created_at)
                )
            ).all()
        )

    async def revoke_grant(
        self,
        *,
        tenant_id: uuid.UUID,
        principal_id: uuid.UUID,
        grant_id: uuid.UUID,
        actor_user_id: int,
        now: datetime | None = None,
    ) -> tuple[db_models.IntegrationGrant | None, bool]:
        """Idempotently revoke one tenant grant and strand no matching work."""

        grant = await self.db.scalar(
            select(db_models.IntegrationGrant)
            .where(
                db_models.IntegrationGrant.id == grant_id,
                db_models.IntegrationGrant.tenant_id == tenant_id,
                db_models.IntegrationGrant.principal_id == principal_id,
            )
            .with_for_update()
        )
        if grant is None:
            return None, False
        if grant.revoked_at is not None:
            return grant, False

        timestamp = now or datetime.now(timezone.utc)
        grant.revoked_at = timestamp
        grant.revoked_by_user_id = actor_user_id

        event_types: tuple[str, ...]
        if grant.feature == "ticket_sync":
            event_types = ("finding.ticket.sync",)
        elif grant.feature == "siem_emit":
            event_types = ()
        else:
            await self.db.flush()
            return grant, True

        delivery_filters = [
            db_models.IntegrationOutbox.tenant_id == tenant_id,
            db_models.IntegrationOutbox.principal_id == principal_id,
            db_models.IntegrationOutbox.state.in_(("pending", "retry", "delivering")),
        ]
        if event_types:
            delivery_filters.append(
                db_models.IntegrationOutbox.event_type.in_(event_types)
            )
        delivery_statement = (
            update(db_models.IntegrationOutbox)
            .where(*delivery_filters)
            .values(
                state="dead_letter",
                lease_expires_at=None,
                last_error_code="grant_revoked",
            )
            .returning(db_models.IntegrationOutbox)
        )
        terminal_rows = (await self.db.execute(delivery_statement)).scalars().all()
        for delivery in terminal_rows:
            if delivery.attempts <= 0:
                continue
            await self.append_delivery_audit(
                row=delivery,
                outcome="dead_letter",
                http_status=None,
                response_excerpt=None,
                error_code="grant_revoked",
            )
        await self.db.flush()
        return grant, True

    async def record_inbound_receipt(
        self,
        *,
        tenant_id: uuid.UUID,
        principal_id: uuid.UUID,
        source_event_id: str,
        nonce: str,
        event_type: str,
        digest: str,
        occurred_at: datetime,
    ) -> tuple[db_models.IntegrationInboundReceipt, bool]:
        statement = (
            pg_insert(db_models.IntegrationInboundReceipt)
            .values(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                principal_id=principal_id,
                source_event_id=source_event_id,
                nonce=nonce,
                event_type=event_type,
                payload_digest=digest,
                occurred_at=occurred_at,
            )
            .on_conflict_do_nothing()
            .returning(db_models.IntegrationInboundReceipt)
        )
        created = (await self.db.execute(statement)).scalar_one_or_none()
        if created is not None:
            return created, True
        existing = await self.db.scalar(
            select(db_models.IntegrationInboundReceipt).where(
                db_models.IntegrationInboundReceipt.principal_id == principal_id,
                or_(
                    db_models.IntegrationInboundReceipt.source_event_id
                    == source_event_id,
                    db_models.IntegrationInboundReceipt.nonce == nonce,
                ),
            )
        )
        if existing is None:
            raise RuntimeError("integration receipt conflict row disappeared")
        if (
            existing.source_event_id != source_event_id
            or existing.payload_digest != digest
        ):
            raise ValueError("integration replay identity is bound to another payload")
        return existing, False

    async def enqueue(
        self,
        *,
        tenant_id: uuid.UUID,
        principal_id: uuid.UUID,
        event_type: str,
        idempotency_key: str,
        nonce: str,
        occurred_at: datetime,
        payload: dict[str, Any],
        max_attempts: int = 8,
        source_event_key: str | None = None,
    ) -> tuple[db_models.IntegrationOutbox, bool]:
        safe_payload = redact_integration_payload(payload)
        digest = payload_digest(safe_payload)
        outbox_id = uuid.uuid4()
        statement = (
            pg_insert(db_models.IntegrationOutbox)
            .values(
                id=outbox_id,
                tenant_id=tenant_id,
                principal_id=principal_id,
                event_type=event_type,
                idempotency_key=idempotency_key,
                source_event_key=source_event_key,
                nonce=nonce,
                occurred_at=occurred_at,
                payload_redacted=safe_payload,
                payload_digest=digest,
                max_attempts=max_attempts,
                next_attempt_at=occurred_at,
            )
            .on_conflict_do_nothing()
            .returning(db_models.IntegrationOutbox)
        )
        created = (await self.db.execute(statement)).scalar_one_or_none()
        if created is not None:
            return created, True
        existing = await self.db.scalar(
            select(db_models.IntegrationOutbox).where(
                db_models.IntegrationOutbox.tenant_id == tenant_id,
                db_models.IntegrationOutbox.idempotency_key == idempotency_key,
            )
        )
        if existing is None:
            raise RuntimeError("integration outbox conflict row disappeared")
        if (
            existing.principal_id != principal_id
            or existing.event_type != event_type
            or existing.payload_digest != digest
            or existing.source_event_key != source_event_key
        ):
            raise ValueError("integration idempotency key is bound to another event")
        return existing, False

    async def lease_due(
        self,
        *,
        now: datetime,
        limit: int = 20,
        lease_seconds: int = 60,
    ) -> list[db_models.IntegrationOutbox]:
        expired_result = await self.db.execute(
            update(db_models.IntegrationOutbox)
            .where(
                db_models.IntegrationOutbox.state == "delivering",
                db_models.IntegrationOutbox.lease_expires_at <= now,
                db_models.IntegrationOutbox.attempts
                >= db_models.IntegrationOutbox.max_attempts,
            )
            .values(
                state="dead_letter",
                lease_expires_at=None,
                last_error_code="lease_expired_max_attempts",
            )
            .returning(db_models.IntegrationOutbox)
        )
        for expired_row in expired_result.scalars().all():
            await self.append_delivery_audit(
                row=expired_row,
                outcome="dead_letter",
                http_status=None,
                response_excerpt=None,
                error_code="lease_expired_max_attempts",
            )
        rows = list(
            (
                await self.db.scalars(
                    select(db_models.IntegrationOutbox)
                    .where(
                        or_(
                            and_(
                                db_models.IntegrationOutbox.state.in_(
                                    ("pending", "retry")
                                ),
                                db_models.IntegrationOutbox.next_attempt_at <= now,
                                or_(
                                    db_models.IntegrationOutbox.lease_expires_at.is_(
                                        None
                                    ),
                                    db_models.IntegrationOutbox.lease_expires_at <= now,
                                ),
                            ),
                            and_(
                                db_models.IntegrationOutbox.state == "delivering",
                                db_models.IntegrationOutbox.lease_expires_at <= now,
                                db_models.IntegrationOutbox.attempts
                                < db_models.IntegrationOutbox.max_attempts,
                            ),
                        ),
                    )
                    .order_by(db_models.IntegrationOutbox.next_attempt_at)
                    .limit(limit)
                    .with_for_update(skip_locked=True)
                )
            ).all()
        )
        for row in rows:
            row.state = "delivering"
            row.attempts += 1
            row.lease_expires_at = now + timedelta(seconds=lease_seconds)
        await self.db.flush()
        return rows

    async def complete_delivery(
        self, *, row: db_models.IntegrationOutbox, now: datetime
    ) -> None:
        row.state = "delivered"
        row.delivered_at = now
        row.lease_expires_at = None
        row.last_error_code = None
        await self.db.flush()

    async def fail_delivery(
        self,
        *,
        row: db_models.IntegrationOutbox,
        now: datetime,
        error_code: str,
        retryable: bool,
        retry_after_seconds: int,
    ) -> None:
        terminal = not retryable or row.attempts >= row.max_attempts
        row.state = "dead_letter" if terminal else "retry"
        row.next_attempt_at = now + timedelta(seconds=retry_after_seconds)
        row.lease_expires_at = None
        row.last_error_code = error_code[:64]
        await self.db.flush()

    async def append_delivery_audit(
        self,
        *,
        row: db_models.IntegrationOutbox,
        outcome: str,
        http_status: int | None,
        response_excerpt: str | None,
        error_code: str | None,
    ) -> db_models.IntegrationDeliveryAudit:
        evidence = {
            "outbox_id": str(row.id),
            "attempt": row.attempts,
            "outcome": outcome,
            "http_status": http_status,
            "error_code": error_code,
        }
        audit = db_models.IntegrationDeliveryAudit(
            tenant_id=row.tenant_id,
            outbox_id=row.id,
            principal_id=row.principal_id,
            attempt=row.attempts,
            outcome=outcome,
            http_status=http_status,
            evidence_digest=payload_digest(evidence),
            response_excerpt_redacted=(response_excerpt or "")[:1024] or None,
            error_code=(error_code or "")[:64] or None,
        )
        self.db.add(audit)
        await self.db.flush()
        return audit

    async def list_outbox(
        self, *, tenant_id: uuid.UUID, limit: int = 100
    ) -> list[db_models.IntegrationOutbox]:
        return list(
            (
                await self.db.scalars(
                    select(db_models.IntegrationOutbox)
                    .where(db_models.IntegrationOutbox.tenant_id == tenant_id)
                    .order_by(db_models.IntegrationOutbox.created_at.desc())
                    .limit(limit)
                )
            ).all()
        )

    async def requeue_dead_letter(
        self,
        *,
        tenant_id: uuid.UUID,
        outbox_id: uuid.UUID,
        now: datetime | None = None,
    ) -> db_models.IntegrationOutbox | None:
        row = await self.db.scalar(
            select(db_models.IntegrationOutbox)
            .where(
                db_models.IntegrationOutbox.id == outbox_id,
                db_models.IntegrationOutbox.tenant_id == tenant_id,
            )
            .with_for_update()
        )
        if row is None:
            return None
        if row.state != "dead_letter":
            raise ValueError("only dead-letter deliveries can be requeued")
        principal = await self.get_principal(
            tenant_id=tenant_id, principal_id=row.principal_id, active_only=True
        )
        if principal is None:
            raise ValueError("revoked integration principal cannot be requeued")
        required_feature = _required_delivery_feature(
            principal_kind=principal.kind, event_type=row.event_type
        )
        if required_feature and not await self.has_active_grant(
            tenant_id=tenant_id,
            principal_id=row.principal_id,
            feature=required_feature,
            event_type=row.event_type if required_feature == "siem_emit" else None,
            lock=True,
        ):
            raise ValueError(
                "required integration grant must be repaired before requeue"
            )
        row.state = "retry"
        row.attempts = 0
        row.next_attempt_at = now or datetime.now(timezone.utc)
        row.lease_expires_at = None
        row.last_error_code = None
        await self.db.flush()
        return row

    async def list_audit(
        self, *, tenant_id: uuid.UUID, limit: int = 100
    ) -> list[db_models.IntegrationDeliveryAudit]:
        return list(
            (
                await self.db.scalars(
                    select(db_models.IntegrationDeliveryAudit)
                    .where(db_models.IntegrationDeliveryAudit.tenant_id == tenant_id)
                    .order_by(db_models.IntegrationDeliveryAudit.created_at.desc())
                    .limit(limit)
                )
            ).all()
        )

    async def get_ticket(
        self,
        *,
        tenant_id: uuid.UUID,
        principal_id: uuid.UUID,
        canonical_root_id: str,
    ) -> db_models.IntegrationFindingTicket | None:
        return await self.db.scalar(
            select(db_models.IntegrationFindingTicket).where(
                db_models.IntegrationFindingTicket.tenant_id == tenant_id,
                db_models.IntegrationFindingTicket.principal_id == principal_id,
                db_models.IntegrationFindingTicket.canonical_root_id
                == canonical_root_id,
            )
        )

    async def lock_ticket_identity(
        self, *, principal_id: uuid.UUID, canonical_root_id: str
    ) -> None:
        """Serialize provider lookup/create for one canonical ticket identity."""

        await self.db.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:identity, 20))"),
            {"identity": f"{principal_id}:{canonical_root_id}"},
        )

    async def create_ticket(
        self,
        *,
        tenant_id: uuid.UUID,
        principal_id: uuid.UUID,
        canonical_root_id: str,
        external_key: str,
        external_url: str | None,
        status: str,
        waiver_expires_at: datetime | None = None,
        reason: str = "created",
    ) -> db_models.IntegrationFindingTicket:
        statement = (
            pg_insert(db_models.IntegrationFindingTicket)
            .values(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                principal_id=principal_id,
                canonical_root_id=canonical_root_id,
                external_key=external_key,
                external_url=external_url,
                status=status,
                waiver_expires_at=waiver_expires_at,
            )
            .on_conflict_do_nothing(constraint="uq_integration_ticket_canonical_root")
            .returning(db_models.IntegrationFindingTicket)
        )
        row = (await self.db.execute(statement)).scalar_one_or_none()
        if row is None:
            existing = await self.get_ticket(
                tenant_id=tenant_id,
                principal_id=principal_id,
                canonical_root_id=canonical_root_id,
            )
            if existing is None:
                raise RuntimeError("canonical ticket conflict row disappeared")
            return existing
        self.db.add(
            db_models.IntegrationTicketHistory(
                tenant_id=tenant_id,
                ticket_id=row.id,
                from_status=None,
                to_status=status,
                reason=reason,
            )
        )
        await self.db.flush()
        return row

    async def transition_ticket(
        self,
        *,
        row: db_models.IntegrationFindingTicket,
        to_status: str,
        reason: str,
        event_id: uuid.UUID | None = None,
        waiver_expires_at: datetime | None = None,
    ) -> None:
        previous = row.status
        row.status = to_status
        row.waiver_expires_at = waiver_expires_at
        row.updated_at = datetime.now(timezone.utc)
        self.db.add(
            db_models.IntegrationTicketHistory(
                tenant_id=row.tenant_id,
                ticket_id=row.id,
                from_status=previous,
                to_status=to_status,
                reason=reason,
                event_id=event_id,
            )
        )
        await self.db.flush()

    async def list_tickets(
        self, *, tenant_id: uuid.UUID, limit: int = 100
    ) -> list[db_models.IntegrationFindingTicket]:
        return list(
            (
                await self.db.scalars(
                    select(db_models.IntegrationFindingTicket)
                    .where(db_models.IntegrationFindingTicket.tenant_id == tenant_id)
                    .order_by(db_models.IntegrationFindingTicket.updated_at.desc())
                    .limit(limit)
                )
            ).all()
        )

    async def enqueue_due_ticket_lifecycle_events(
        self, *, now: datetime, limit: int = 500
    ) -> int:
        """Materialize waiver lifecycle changes into the durable ticket outbox."""

        expiry_recorded = (
            select(db_models.FindingWaiverEvent.id)
            .where(
                db_models.FindingWaiverEvent.waiver_id == db_models.FindingWaiver.id,
                db_models.FindingWaiverEvent.action == "expired",
            )
            .exists()
        )
        expired_waivers = list(
            (
                await self.db.scalars(
                    select(db_models.FindingWaiver)
                    .where(
                        db_models.FindingWaiver.expires_at <= now,
                        ~expiry_recorded,
                    )
                    .order_by(db_models.FindingWaiver.expires_at.asc())
                    .limit(limit)
                )
            ).all()
        )
        for waiver in expired_waivers:
            await self.db.execute(
                pg_insert(db_models.FindingWaiverEvent)
                .values(
                    tenant_id=waiver.tenant_id,
                    waiver_id=waiver.id,
                    action="expired",
                    actor_user_id=None,
                    reason="Waiver expiry reached.",
                )
                .on_conflict_do_nothing(index_elements=["waiver_id", "action"])
            )

        active_ticket_grant = (
            select(db_models.IntegrationGrant.id)
            .where(
                db_models.IntegrationGrant.principal_id
                == db_models.IntegrationServicePrincipal.id,
                db_models.IntegrationGrant.tenant_id
                == db_models.IntegrationServicePrincipal.tenant_id,
                db_models.IntegrationGrant.feature == "ticket_sync",
                db_models.IntegrationGrant.revoked_at.is_(None),
            )
            .exists()
        )
        source_event_key = literal("waiver:") + cast(
            db_models.FindingWaiverEvent.id, String
        )
        already_materialized = (
            select(db_models.IntegrationOutbox.id)
            .where(
                db_models.IntegrationOutbox.principal_id
                == db_models.IntegrationServicePrincipal.id,
                db_models.IntegrationOutbox.source_event_key == source_event_key,
            )
            .exists()
        )
        rows = list(
            (
                await self.db.execute(
                    select(
                        db_models.FindingWaiverEvent,
                        db_models.FindingWaiver,
                        db_models.IntegrationServicePrincipal,
                        db_models.Finding,
                    )
                    .join(
                        db_models.FindingWaiver,
                        db_models.FindingWaiver.id
                        == db_models.FindingWaiverEvent.waiver_id,
                    )
                    .join(
                        db_models.IntegrationServicePrincipal,
                        db_models.IntegrationServicePrincipal.tenant_id
                        == db_models.FindingWaiver.tenant_id,
                    )
                    .outerjoin(
                        db_models.Finding,
                        db_models.Finding.id == db_models.FindingWaiver.finding_id,
                    )
                    .where(
                        db_models.FindingWaiverEvent.action.in_(
                            ("granted", "revoked", "expired")
                        ),
                        db_models.IntegrationServicePrincipal.kind == "jira_cloud",
                        db_models.IntegrationServicePrincipal.enabled.is_(True),
                        db_models.IntegrationServicePrincipal.revoked_at.is_(None),
                        active_ticket_grant,
                        ~already_materialized,
                    )
                    .order_by(db_models.FindingWaiverEvent.id.asc())
                    .limit(limit)
                )
            ).all()
        )
        created_count = 0
        for event, waiver, principal, finding in rows:
            action = str(event.action)
            desired_status = str(
                principal.config.get(
                    "waived_status" if action == "granted" else "reopen_status"
                )
                or ("waived" if action == "granted" else "open")
            )
            _, created = await self.enqueue(
                tenant_id=waiver.tenant_id,
                principal_id=principal.id,
                event_type="finding.ticket.sync",
                idempotency_key=stable_idempotency_key(
                    "waiver-ticket", event.id, principal.id
                ),
                nonce=stable_idempotency_key(
                    "waiver-ticket-nonce", event.id, principal.id
                ),
                occurred_at=event.created_at,
                source_event_key=f"waiver:{event.id}",
                payload={
                    "canonical_root_id": waiver.fingerprint,
                    "title": finding.title if finding is not None else "SCCAP finding",
                    "severity": (finding.severity if finding is not None else None)
                    or "unknown",
                    "status": desired_status,
                    "waiver_expires_at": (
                        waiver.expires_at.isoformat() if action == "granted" else None
                    ),
                    "reason": f"waiver_{action}",
                    "authorized_view": (
                        f"/analysis/results/{waiver.scan_id}"
                        if waiver.scan_id
                        else "/analysis/history"
                    ),
                },
            )
            created_count += int(created)
        await self.db.flush()
        return created_count

    async def record_source_submission(
        self,
        *,
        tenant_id: uuid.UUID,
        scan_id: uuid.UUID,
        provider: str,
        commit_sha: str,
        ref: str,
        repository_slug: str,
        trusted_context: bool,
        actor_user_id: int,
    ) -> db_models.IntegrationSourceSubmission:
        statement = (
            pg_insert(db_models.IntegrationSourceSubmission)
            .values(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                scan_id=scan_id,
                provider=provider,
                commit_sha=commit_sha,
                ref=ref,
                repository_slug=repository_slug,
                trusted_context=trusted_context,
                created_by_user_id=actor_user_id,
            )
            .on_conflict_do_nothing(constraint="uq_integration_source_submission_scan")
            .returning(db_models.IntegrationSourceSubmission)
        )
        created = (await self.db.execute(statement)).scalar_one_or_none()
        if created is not None:
            return created
        existing = await self.db.scalar(
            select(db_models.IntegrationSourceSubmission).where(
                db_models.IntegrationSourceSubmission.tenant_id == tenant_id,
                db_models.IntegrationSourceSubmission.scan_id == scan_id,
            )
        )
        if existing is None:
            raise RuntimeError("source submission conflict row disappeared")
        if (
            existing.provider != provider
            or existing.commit_sha != commit_sha
            or existing.ref != ref
            or existing.repository_slug != repository_slug
            or existing.trusted_context != trusted_context
        ):
            raise ValueError("scan source provenance is bound to another submission")
        return existing
