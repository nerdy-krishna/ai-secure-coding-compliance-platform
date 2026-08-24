"""Tenant-scoped persistence for provider billing reconciliation."""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from decimal import Decimal
from typing import Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models
from app.shared.lib.encryption import FernetEncrypt
from app.infrastructure.secrets.scoped import (
    decrypt_scoped_secret,
    encrypt_scoped_secret,
)
from app.shared.lib.provider_reconciliation import (
    Comparison,
    UsageSlice,
    opaque_dimension,
)


def encrypt_credentials(credentials: dict[str, str]) -> bytes:
    if not credentials or not credentials.get("api_key"):
        raise ValueError("provider billing credentials require an API key")
    plaintext = json.dumps(credentials, separators=(",", ":"), sort_keys=True)
    return FernetEncrypt.encrypt(plaintext).encode("utf-8")


def decrypt_credentials(ciphertext: bytes) -> dict[str, str]:
    payload = json.loads(FernetEncrypt.decrypt(ciphertext.decode("utf-8")))
    if not isinstance(payload, dict) or not isinstance(payload.get("api_key"), str):
        raise ValueError("invalid provider billing credential envelope")
    return {str(key): str(value) for key, value in payload.items()}


class ProviderReconciliationRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_connector(
        self,
        *,
        tenant_id: uuid.UUID,
        provider: str,
        display_name: str,
        credentials: dict[str, str],
        provider_project_ids: Sequence[str],
        enabled: bool,
        absolute_tolerance_micro_usd: int,
        percentage_tolerance: Decimal,
        lookback_minutes: int,
        poll_interval_minutes: int,
        created_by_user_id: int,
        now: datetime,
    ) -> db_models.ProviderBillingConnector:
        connector_id = uuid.uuid4()
        row = db_models.ProviderBillingConnector(
            id=connector_id,
            tenant_id=tenant_id,
            provider=provider,
            display_name=display_name,
            credentials_encrypted=(
                await encrypt_scoped_secret(
                    json.dumps(credentials, separators=(",", ":"), sort_keys=True),
                    scope={
                        "kind": "provider_billing_connector",
                        "tenant_id": str(tenant_id),
                        "id": str(connector_id),
                    },
                )
            ).encode(),
            provider_project_ids=list(provider_project_ids),
            # Endpoint access is recorded only after a live read succeeds.
            verified_scopes=[],
            enabled=enabled,
            absolute_tolerance_micro_usd=absolute_tolerance_micro_usd,
            percentage_tolerance=percentage_tolerance,
            lookback_minutes=lookback_minutes,
            poll_interval_minutes=poll_interval_minutes,
            next_run_at=now if enabled else None,
            created_by_user_id=created_by_user_id,
            created_at=now,
            updated_at=now,
        )
        self.db.add(row)
        await self.db.flush()
        return row

    async def update_connector(
        self,
        *,
        connector_id: uuid.UUID,
        tenant_id: uuid.UUID,
        credentials: dict[str, str] | None,
        enabled: bool,
        absolute_tolerance_micro_usd: int,
        percentage_tolerance: Decimal,
        lookback_minutes: int,
        poll_interval_minutes: int,
        provider_project_ids: Sequence[str],
        now: datetime,
    ) -> db_models.ProviderBillingConnector | None:
        row = await self.get_connector(
            connector_id=connector_id, tenant_id=tenant_id, for_update=True
        )
        if row is None:
            return None
        if credentials is not None:
            row.credentials_encrypted = (
                await encrypt_scoped_secret(
                    json.dumps(credentials, separators=(",", ":"), sort_keys=True),
                    scope={
                        "kind": "provider_billing_connector",
                        "tenant_id": str(tenant_id),
                        "id": str(row.id),
                    },
                )
            ).encode()
            row.verified_scopes = []
        row.enabled = enabled
        row.absolute_tolerance_micro_usd = absolute_tolerance_micro_usd
        row.percentage_tolerance = percentage_tolerance
        row.lookback_minutes = lookback_minutes
        row.poll_interval_minutes = poll_interval_minutes
        row.provider_project_ids = list(provider_project_ids)
        row.next_run_at = (
            now if enabled and row.next_run_at is None else row.next_run_at
        )
        if not enabled:
            row.next_run_at = None
        row.updated_at = now
        await self.db.flush()
        return row

    async def decrypt_connector_credentials(
        self, row: db_models.ProviderBillingConnector
    ) -> dict[str, str]:
        secret = await decrypt_scoped_secret(
            row.credentials_encrypted.decode(),
            scope={
                "kind": "provider_billing_connector",
                "tenant_id": str(row.tenant_id),
                "id": str(row.id),
            },
        )
        if secret.persisted_value is not None:
            row.credentials_encrypted = secret.persisted_value.encode()
            await self.db.commit()
        payload = json.loads(secret.plaintext)
        if not isinstance(payload, dict) or not isinstance(payload.get("api_key"), str):
            raise ValueError("invalid provider billing credential envelope")
        return {str(key): str(value) for key, value in payload.items()}

    async def get_connector(
        self, *, connector_id: uuid.UUID, tenant_id: uuid.UUID, for_update: bool = False
    ) -> db_models.ProviderBillingConnector | None:
        query = select(db_models.ProviderBillingConnector).where(
            db_models.ProviderBillingConnector.id == connector_id,
            db_models.ProviderBillingConnector.tenant_id == tenant_id,
        )
        if for_update:
            query = query.with_for_update()
        return await self.db.scalar(query)

    async def list_connectors(
        self, *, tenant_id: uuid.UUID
    ) -> list[db_models.ProviderBillingConnector]:
        rows = await self.db.scalars(
            select(db_models.ProviderBillingConnector)
            .where(db_models.ProviderBillingConnector.tenant_id == tenant_id)
            .order_by(db_models.ProviderBillingConnector.created_at.desc())
        )
        return list(rows)

    async def list_due_connectors(
        self, *, now: datetime, limit: int = 20
    ) -> list[db_models.ProviderBillingConnector]:
        rows = await self.db.scalars(
            select(db_models.ProviderBillingConnector)
            .where(
                db_models.ProviderBillingConnector.enabled.is_(True),
                db_models.ProviderBillingConnector.next_run_at.is_not(None),
                db_models.ProviderBillingConnector.next_run_at <= now,
            )
            .order_by(db_models.ProviderBillingConnector.next_run_at)
            .limit(limit)
        )
        return list(rows)

    async def canonical_slices(
        self,
        *,
        connector: db_models.ProviderBillingConnector,
        window_start: datetime,
        window_end: datetime,
    ) -> list[UsageSlice]:
        rows = await self.db.execute(
            select(db_models.LLMUsageRequest)
            .join(
                db_models.LLMUsageEvent,
                db_models.LLMUsageEvent.id == db_models.LLMUsageRequest.usage_event_id,
            )
            .where(
                db_models.LLMUsageEvent.tenant_id == connector.tenant_id,
                func.lower(db_models.LLMUsageRequest.provider)
                == connector.provider.lower(),
                db_models.LLMUsageRequest.received_at >= window_start,
                db_models.LLMUsageRequest.received_at < window_end,
            )
            .order_by(
                db_models.LLMUsageRequest.received_at, db_models.LLMUsageRequest.id
            )
        )
        requests = list(rows.scalars())
        response_counts: dict[str, int] = {}
        for request in requests:
            if request.provider_response_id:
                response_counts[request.provider_response_id] = (
                    response_counts.get(request.provider_response_id, 0) + 1
                )
        project = (
            connector.provider_project_ids[0]
            if len(connector.provider_project_ids) == 1
            else None
        )
        slices: list[UsageSlice] = []
        total_cost_micro_usd = 0
        for request in requests:
            duplicate_count = max(
                response_counts.get(request.provider_response_id or "", 1) - 1, 0
            )
            slices.append(
                UsageSlice(
                    provider=request.provider,
                    window_start=window_start,
                    window_end=window_end,
                    model=request.resolved_model or request.requested_model,
                    project=project,
                    service_tier=request.service_tier,
                    is_batch=request.is_batch,
                    currency=request.currency or "USD",
                    input_tokens=request.input_tokens,
                    output_tokens=request.output_tokens,
                    cache_read_tokens=request.cache_read_tokens,
                    cache_write_tokens=request.cache_write_tokens,
                    reasoning_tokens=request.reasoning_tokens,
                    cost_micro_usd=0,
                    external_id=str(request.id),
                    duplicate_count=duplicate_count,
                )
            )
            total_cost_micro_usd += _cost_micro_usd(request.total_cost)
        if requests:
            slices.append(
                UsageSlice(
                    provider=connector.provider,
                    window_start=window_start,
                    window_end=window_end,
                    model=None,
                    project=project,
                    service_tier=None,
                    is_batch=None,
                    currency="USD",
                    cost_micro_usd=total_cost_micro_usd,
                    kind="cost",
                )
            )
        return slices

    async def existing_run(
        self, *, idempotency_key: str
    ) -> db_models.ProviderReconciliationRun | None:
        return await self.db.scalar(
            select(db_models.ProviderReconciliationRun).where(
                db_models.ProviderReconciliationRun.idempotency_key == idempotency_key
            )
        )

    async def known_provider_item_ids(
        self, *, connector_id: uuid.UUID, tenant_id: uuid.UUID, limit: int = 2000
    ) -> set[str]:
        rows = await self.db.scalars(
            select(db_models.ProviderReconciliationEvidence.provider_item_ids)
            .join(
                db_models.ProviderReconciliationRun,
                db_models.ProviderReconciliationRun.id
                == db_models.ProviderReconciliationEvidence.run_id,
            )
            .where(
                db_models.ProviderReconciliationRun.connector_id == connector_id,
                db_models.ProviderReconciliationRun.tenant_id == tenant_id,
            )
            .order_by(db_models.ProviderReconciliationEvidence.created_at.desc())
            .limit(limit)
        )
        return {item_id for item_ids in rows for item_id in item_ids}

    async def record_completed_run(
        self,
        *,
        connector: db_models.ProviderBillingConnector,
        idempotency_key: str,
        window_start: datetime,
        window_end: datetime,
        trigger_kind: str,
        created_by_user_id: int | None,
        comparisons: Sequence[Comparison],
        provider_pages: int,
        started_at: datetime,
        completed_at: datetime,
    ) -> db_models.ProviderReconciliationRun:
        canonical_total = sum(
            item.canonical.cost_micro_usd for item in comparisons if item.canonical
        )
        provider_total = sum(
            item.provider.cost_micro_usd for item in comparisons if item.provider
        )
        unresolved_classes = {
            "missing_event",
            "duplicate_event",
            "token_category_mismatch",
            "price_catalog_mismatch",
            "unresolved",
        }
        unresolved = [
            item for item in comparisons if item.classification in unresolved_classes
        ]
        discrepancies = [
            item for item in comparisons if item.classification != "matched"
        ]
        unresolved_amount = sum(abs(item.variance_micro_usd) for item in unresolved)
        compared = len(comparisons)
        coverage = (
            Decimal("100")
            if compared == 0
            else Decimal(compared - len(unresolved))
            * Decimal("100")
            / Decimal(compared)
        )
        run = db_models.ProviderReconciliationRun(
            tenant_id=connector.tenant_id,
            connector_id=connector.id,
            idempotency_key=idempotency_key,
            window_start=window_start,
            window_end=window_end,
            status="completed",
            trigger_kind=trigger_kind,
            canonical_micro_usd=canonical_total,
            provider_micro_usd=provider_total,
            variance_micro_usd=provider_total - canonical_total,
            unresolved_micro_usd=unresolved_amount,
            coverage_percent=coverage,
            compared_dimensions=compared,
            unresolved_dimensions=len(unresolved),
            provider_pages=provider_pages,
            created_by_user_id=created_by_user_id,
            started_at=started_at,
            completed_at=completed_at,
        )
        self.db.add(run)
        await self.db.flush()
        for item in comparisons:
            ours, theirs = item.canonical, item.provider
            basis = ours or theirs
            assert basis is not None
            provider_ids = list(
                (theirs.metadata.get("external_ids") if theirs else ()) or ()
            )
            evidence = db_models.ProviderReconciliationEvidence(
                tenant_id=connector.tenant_id,
                run_id=run.id,
                dimension_key=item.dimension_key,
                classification=item.classification,
                canonical_micro_usd=ours.cost_micro_usd if ours else 0,
                provider_micro_usd=theirs.cost_micro_usd if theirs else 0,
                variance_micro_usd=item.variance_micro_usd,
                within_tolerance=item.within_tolerance,
                canonical_tokens=ours.tokens if ours else {},
                provider_tokens=theirs.tokens if theirs else {},
                normalized_dimensions={
                    "provider": basis.provider,
                    "model": basis.model,
                    "service_tier": basis.service_tier,
                    "is_batch": bool(basis.is_batch),
                    "currency": basis.currency,
                    "window_start": basis.window_start.isoformat(),
                    "window_end": basis.window_end.isoformat(),
                    # Never persist raw provider project/key identifiers in
                    # reconciliation evidence. These opaque values remain
                    # stable enough for attribution and duplicate analysis.
                    "projects": list(
                        theirs.metadata.get("project_ids", ())
                        if theirs
                        else (opaque_dimension(None),)
                    ),
                    "api_keys": list(
                        theirs.metadata.get("api_key_ids", ())
                        if theirs
                        else (opaque_dimension(None),)
                    ),
                },
                provider_item_ids=provider_ids,
                details=item.details,
            )
            self.db.add(evidence)
            await self.db.flush()
            if item.classification in ("provider_adjustment_credit", "timing_lag"):
                self.db.add(
                    db_models.ProviderReconciliationAdjustment(
                        tenant_id=connector.tenant_id,
                        run_id=run.id,
                        evidence_id=evidence.id,
                        kind=item.classification,
                        amount_micro_usd=item.variance_micro_usd,
                        currency="USD",
                    )
                )
        if discrepancies:
            self.db.add(
                db_models.ProviderReconciliationAlertOutbox(
                    tenant_id=connector.tenant_id,
                    run_id=run.id,
                    severity="warning",
                    payload={
                        "event": "provider_usage_reconciliation_discrepancy",
                        "run_id": str(run.id),
                        "connector_id": str(connector.id),
                        "unresolved_micro_usd": unresolved_amount,
                        "unresolved_dimensions": len(unresolved),
                        "classified_dimensions": len(discrepancies) - len(unresolved),
                    },
                )
            )
        return run

    async def record_failed_run(
        self,
        *,
        connector: db_models.ProviderBillingConnector,
        idempotency_key: str,
        window_start: datetime,
        window_end: datetime,
        trigger_kind: str,
        created_by_user_id: int | None,
        started_at: datetime,
        completed_at: datetime,
        error_code: str,
    ) -> db_models.ProviderReconciliationRun:
        run = db_models.ProviderReconciliationRun(
            tenant_id=connector.tenant_id,
            connector_id=connector.id,
            idempotency_key=idempotency_key,
            window_start=window_start,
            window_end=window_end,
            status="failed",
            trigger_kind=trigger_kind,
            error_code=error_code[:64],
            created_by_user_id=created_by_user_id,
            started_at=started_at,
            completed_at=completed_at,
        )
        self.db.add(run)
        await self.db.flush()
        self.db.add(
            db_models.ProviderReconciliationAlertOutbox(
                tenant_id=connector.tenant_id,
                run_id=run.id,
                severity="error",
                payload={
                    "event": "provider_usage_reconciliation_failed",
                    "run_id": str(run.id),
                    "connector_id": str(connector.id),
                    "error_code": error_code[:64],
                },
            )
        )
        return run

    async def mark_connector_ran(
        self,
        connector: db_models.ProviderBillingConnector,
        *,
        now: datetime,
        verified: bool,
    ) -> None:
        # Connector scheduling metadata is mutable; reconciliation evidence is not.
        from datetime import timedelta

        connector.last_run_at = now
        connector.next_run_at = (
            now + timedelta(minutes=connector.poll_interval_minutes)
            if connector.enabled
            else None
        )
        if verified:
            connector.verified_scopes = [
                "organization.usage.read",
                "organization.costs.read",
            ]
        connector.updated_at = now

    async def list_runs(
        self, *, tenant_id: uuid.UUID, cursor: uuid.UUID | None, limit: int
    ) -> list[db_models.ProviderReconciliationRun]:
        query = select(db_models.ProviderReconciliationRun).where(
            db_models.ProviderReconciliationRun.tenant_id == tenant_id
        )
        if cursor:
            anchor = await self.db.scalar(
                select(db_models.ProviderReconciliationRun.completed_at).where(
                    db_models.ProviderReconciliationRun.id == cursor,
                    db_models.ProviderReconciliationRun.tenant_id == tenant_id,
                )
            )
            if anchor:
                query = query.where(
                    db_models.ProviderReconciliationRun.completed_at < anchor
                )
        return list(
            await self.db.scalars(
                query.order_by(
                    db_models.ProviderReconciliationRun.completed_at.desc()
                ).limit(limit)
            )
        )

    async def get_run(
        self, *, run_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> db_models.ProviderReconciliationRun | None:
        return await self.db.scalar(
            select(db_models.ProviderReconciliationRun).where(
                db_models.ProviderReconciliationRun.id == run_id,
                db_models.ProviderReconciliationRun.tenant_id == tenant_id,
            )
        )

    async def list_evidence(
        self,
        *,
        run_id: uuid.UUID,
        tenant_id: uuid.UUID,
        cursor: uuid.UUID | None,
        limit: int,
    ) -> list[db_models.ProviderReconciliationEvidence]:
        query = select(db_models.ProviderReconciliationEvidence).where(
            db_models.ProviderReconciliationEvidence.run_id == run_id,
            db_models.ProviderReconciliationEvidence.tenant_id == tenant_id,
        )
        if cursor:
            query = query.where(db_models.ProviderReconciliationEvidence.id > cursor)
        return list(
            await self.db.scalars(
                query.order_by(db_models.ProviderReconciliationEvidence.id).limit(limit)
            )
        )

    async def summary(
        self, *, tenant_id: uuid.UUID
    ) -> db_models.ProviderReconciliationRun | None:
        return await self.db.scalar(
            select(db_models.ProviderReconciliationRun)
            .where(db_models.ProviderReconciliationRun.tenant_id == tenant_id)
            .order_by(db_models.ProviderReconciliationRun.completed_at.desc())
            .limit(1)
        )


def _cost_micro_usd(value: Decimal | None) -> int:
    if value is None:
        return 0
    return int((value * Decimal("1000000")).to_integral_value())


__all__ = [
    "ProviderReconciliationRepository",
    "decrypt_credentials",
    "encrypt_credentials",
]
