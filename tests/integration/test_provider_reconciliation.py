"""PostgreSQL contracts for append-only provider reconciliation."""

from __future__ import annotations

import unittest
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.services.provider_reconciliation_service import (
    ProviderReconciliationService,
)
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import engine
from app.infrastructure.database.repositories.provider_reconciliation_repo import (
    ProviderReconciliationRepository,
)
from app.infrastructure.database.tenant_context import bind_principal, reset_principal
from app.infrastructure.provider_billing import ProviderPage
from app.shared.lib.provider_reconciliation import UsageSlice
from tests.integration.support import integration_test


class FixtureClient:
    def __init__(self, row: UsageSlice):
        self.row = row
        self.calls = 0

    async def fetch_page(self, **kwargs):
        del kwargs
        self.calls += 1
        return ProviderPage(rows=(self.row,), next_cursor=None)


@integration_test
class ProviderReconciliationPersistenceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.binding = bind_principal(
            tenant_id=None,
            principal_kind="system",
            principal_id="provider-reconciliation-test",
            system_scope=True,
        )
        self.connection = await engine.connect()
        self.outer_transaction = await self.connection.begin()
        async with self._session() as db:
            suffix = uuid.uuid4().hex[:12]
            tenant = db_models.Tenant(
                slug=f"reconciliation-{suffix}", display_name="Reconciliation test"
            )
            db.add(tenant)
            await db.flush()
            user = db_models.User(
                email=f"reconciliation-{suffix}@example.invalid",
                hashed_password="not-a-real-password",
                is_active=True,
                is_superuser=False,
                is_verified=True,
                tenant_id=tenant.id,
            )
            db.add(user)
            await db.flush()
            connector = await ProviderReconciliationRepository(db).create_connector(
                tenant_id=tenant.id,
                provider="openai",
                display_name="Read-only fixture",
                credentials={"api_key": "fixture-read-only-secret-key"},
                provider_project_ids=[],
                enabled=True,
                absolute_tolerance_micro_usd=10,
                percentage_tolerance=Decimal("1"),
                lookback_minutes=180,
                poll_interval_minutes=60,
                created_by_user_id=user.id,
                now=datetime.now(timezone.utc),
            )
            await db.commit()
            self.tenant_id = tenant.id
            self.connector_id = connector.id
            self.user_id = user.id
            self.assertNotIn(
                b"fixture-read-only-secret-key", connector.credentials_encrypted
            )

    async def asyncTearDown(self) -> None:
        await self.outer_transaction.rollback()
        await self.connection.close()
        reset_principal(self.binding)
        await engine.dispose()

    def _session(self) -> AsyncSession:
        return AsyncSession(
            bind=self.connection,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        )

    async def test_run_is_idempotent_and_never_rewrites_canonical_usage(self) -> None:
        start = datetime(2026, 8, 23, tzinfo=timezone.utc)
        end = start + timedelta(days=1)
        fixture = FixtureClient(
            UsageSlice(
                provider="openai",
                window_start=start,
                window_end=end,
                model="gpt-5",
                service_tier="default",
                input_tokens=100,
                output_tokens=10,
                cache_read_tokens=30,
                cost_micro_usd=1200,
                external_id="provider-item-1",
            )
        )
        async with self._session() as db:
            repo = ProviderReconciliationRepository(db)
            service = ProviderReconciliationService(
                repo, client_factory=lambda *_: fixture
            )
            before = await db.scalar(
                select(func.count()).select_from(db_models.LLMUsageEvent)
            )
            arguments = dict(
                connector_id=self.connector_id,
                tenant_id=self.tenant_id,
                window_start=start,
                window_end=end,
                trigger_kind="manual",
                created_by_user_id=self.user_id,
                idempotency_key="integration-provider-reconciliation-run",
            )
            first = await service.run(**arguments)
            second = await service.run(**arguments)
            after = await db.scalar(
                select(func.count()).select_from(db_models.LLMUsageEvent)
            )
            run_count = await db.scalar(
                select(func.count()).select_from(db_models.ProviderReconciliationRun)
            )
            evidence = await db.scalar(
                select(db_models.ProviderReconciliationEvidence).where(
                    db_models.ProviderReconciliationEvidence.run_id == first.id
                )
            )
            alert_count = await db.scalar(
                select(func.count()).select_from(
                    db_models.ProviderReconciliationAlertOutbox
                )
            )
            self.assertEqual(first.id, second.id)
            self.assertEqual(1, fixture.calls)
            self.assertEqual(1, run_count)
            self.assertEqual(before, after)
            self.assertEqual("missing_event", evidence.classification)
            self.assertEqual(["provider-item-1"], evidence.provider_item_ids)
            self.assertEqual(1, alert_count)


if __name__ == "__main__":
    unittest.main()
