"""Application boundary for read-only provider billing reconciliation."""

from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Callable

from sqlalchemy.exc import IntegrityError

from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.provider_reconciliation_repo import (
    ProviderReconciliationRepository,
    decrypt_credentials,
)
from app.infrastructure.provider_billing import (
    OpenAIOrganizationBillingClient,
    ProviderBillingClient,
    ProviderBillingUnavailable,
    fetch_all_pages,
)
from app.shared.lib.provider_reconciliation import UsageSlice, compare_usage


logger = logging.getLogger(__name__)


class ConnectorDisabledError(ValueError):
    pass


ClientFactory = Callable[
    [db_models.ProviderBillingConnector, dict[str, str]], ProviderBillingClient
]


def _default_client_factory(
    connector: db_models.ProviderBillingConnector, credentials: dict[str, str]
) -> ProviderBillingClient:
    if connector.provider == "openai":
        return OpenAIOrganizationBillingClient(
            api_key=credentials["api_key"],
            project_ids=tuple(connector.provider_project_ids),
        )
    raise ValueError("unsupported provider billing connector")


class ProviderReconciliationService:
    def __init__(
        self,
        repo: ProviderReconciliationRepository,
        *,
        client_factory: ClientFactory = _default_client_factory,
    ) -> None:
        self.repo = repo
        self.client_factory = client_factory

    async def run(
        self,
        *,
        connector_id: uuid.UUID,
        tenant_id: uuid.UUID,
        window_start: datetime,
        window_end: datetime,
        trigger_kind: str,
        created_by_user_id: int | None,
        idempotency_key: str | None = None,
        allow_disabled: bool = False,
    ) -> db_models.ProviderReconciliationRun:
        start = _utc(window_start)
        end = _utc(window_end)
        if end <= start:
            raise ValueError("reconciliation window end must be after start")
        if end - start > timedelta(days=31):
            raise ValueError("reconciliation window cannot exceed 31 days")
        connector = await self.repo.get_connector(
            connector_id=connector_id, tenant_id=tenant_id
        )
        if connector is None:
            raise LookupError("provider billing connector not found")
        if not connector.enabled and not allow_disabled:
            raise ConnectorDisabledError("provider billing connector is disabled")
        key = idempotency_key or _run_key(connector_id, start, end)
        existing = await self.repo.existing_run(idempotency_key=key)
        if existing is not None:
            if existing.tenant_id != tenant_id or existing.connector_id != connector_id:
                raise ValueError(
                    "reconciliation idempotency key already belongs to another target"
                )
            return existing

        started_at = datetime.now(timezone.utc)
        try:
            decryptor = getattr(self.repo, "decrypt_connector_credentials", None)
            credentials = (
                await decryptor(connector)
                if decryptor is not None
                else decrypt_credentials(connector.credentials_encrypted)
            )
            client = self.client_factory(connector, credentials)
            provider_rows, page_count = await fetch_all_pages(
                client, window_start=start, window_end=end
            )
            last_run_at = getattr(connector, "last_run_at", None)
            if last_run_at is not None:
                known_ids = await self.repo.known_provider_item_ids(
                    connector_id=connector.id, tenant_id=connector.tenant_id
                )
                provider_rows = [
                    (
                        replace(row, late_arrival=True)
                        if _is_late_arrival(
                            row, known_ids=known_ids, last_run_at=last_run_at
                        )
                        else row
                    )
                    for row in provider_rows
                ]
            canonical_rows = await self.repo.canonical_slices(
                connector=connector, window_start=start, window_end=end
            )
            comparisons = compare_usage(
                canonical_rows,
                provider_rows,
                absolute_tolerance_micro_usd=connector.absolute_tolerance_micro_usd,
                percentage_tolerance=connector.percentage_tolerance,
            )
            completed_at = datetime.now(timezone.utc)
            try:
                run = await self.repo.record_completed_run(
                    connector=connector,
                    idempotency_key=key,
                    window_start=start,
                    window_end=end,
                    trigger_kind=trigger_kind,
                    created_by_user_id=created_by_user_id,
                    comparisons=comparisons,
                    provider_pages=page_count,
                    started_at=started_at,
                    completed_at=completed_at,
                )
            except IntegrityError as exc:
                return await self._recover_duplicate(
                    exc,
                    key=key,
                    tenant_id=tenant_id,
                    connector_id=connector_id,
                )
        except (ProviderBillingUnavailable, ValueError, KeyError) as exc:
            completed_at = datetime.now(timezone.utc)
            error_code = (
                "provider_unavailable"
                if isinstance(exc, ProviderBillingUnavailable)
                else "connector_or_provider_payload_invalid"
            )
            logger.warning(
                "provider_reconciliation.provider_unavailable",
                extra={"connector_id": str(connector.id), "error_code": error_code},
            )
            try:
                run = await self.repo.record_failed_run(
                    connector=connector,
                    idempotency_key=key,
                    window_start=start,
                    window_end=end,
                    trigger_kind=trigger_kind,
                    created_by_user_id=created_by_user_id,
                    started_at=started_at,
                    completed_at=completed_at,
                    error_code=error_code,
                )
            except IntegrityError as conflict:
                return await self._recover_duplicate(
                    conflict,
                    key=key,
                    tenant_id=tenant_id,
                    connector_id=connector_id,
                )
        await self.repo.mark_connector_ran(
            connector, now=completed_at, verified=run.status == "completed"
        )
        try:
            await self.repo.db.commit()
        except IntegrityError as commit_error:
            # A concurrent scheduler/manual request may have won the unique
            # idempotency key after both completed provider reads.
            return await self._recover_duplicate(
                commit_error,
                key=key,
                tenant_id=tenant_id,
                connector_id=connector_id,
            )
        return run

    async def _recover_duplicate(
        self,
        error: IntegrityError,
        *,
        key: str,
        tenant_id: uuid.UUID,
        connector_id: uuid.UUID,
    ) -> db_models.ProviderReconciliationRun:
        await self.repo.db.rollback()
        existing = await self.repo.existing_run(idempotency_key=key)
        if (
            existing is not None
            and existing.tenant_id == tenant_id
            and existing.connector_id == connector_id
        ):
            return existing
        raise error


def _run_key(connector_id: uuid.UUID, start: datetime, end: datetime) -> str:
    raw = (
        f"provider-reconciliation:{connector_id}:{start.isoformat()}:{end.isoformat()}"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("reconciliation timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _is_late_arrival(
    row: UsageSlice,
    *,
    known_ids: set[str],
    last_run_at: datetime,
) -> bool:
    if not row.external_id or row.external_id in known_ids:
        return False
    bucket_end = row.metadata.get("provider_bucket_end")
    if not bucket_end:
        return False
    try:
        return _utc(datetime.fromisoformat(str(bucket_end))) <= _utc(last_run_at)
    except (TypeError, ValueError):
        return False


__all__ = ["ConnectorDisabledError", "ProviderReconciliationService"]
