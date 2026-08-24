"""PostgreSQL proof for exact, tenant-safe usage-center aggregation."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from uuid import uuid4

from sqlalchemy import delete

from app.core.services.usage_center_service import UsageCenterService
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.repositories.usage_center_repo import (
    UsageCenterRepository,
    UsageQuery,
)
from app.infrastructure.database.tenant_context import bind_principal, reset_principal
from tests.integration.support import integration_test


@integration_test
class UsageCenterQueryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.binding = bind_principal(
            tenant_id=None,
            principal_kind="system",
            principal_id="usage-center-integration",
            system_scope=True,
        )
        suffix = uuid4().hex[:12]
        async with AsyncSessionLocal() as db:
            tenant_a = db_models.Tenant(
                slug=f"usage-center-a-{suffix}", display_name="Usage Center A"
            )
            tenant_b = db_models.Tenant(
                slug=f"usage-center-b-{suffix}", display_name="Usage Center B"
            )
            db.add_all([tenant_a, tenant_b])
            await db.flush()
            user_a = db_models.User(
                email=f"usage-center-a-{suffix}@example.invalid",
                hashed_password="not-real",
                is_active=True,
                is_verified=True,
                tenant_id=tenant_a.id,
            )
            user_b = db_models.User(
                email=f"usage-center-b-{suffix}@example.invalid",
                hashed_password="not-real",
                is_active=True,
                is_verified=True,
                tenant_id=tenant_b.id,
            )
            db.add_all([user_a, user_b])
            await db.flush()
            now = datetime.now(timezone.utc)
            group_a = uuid4()
            group_b = uuid4()
            db.add_all(
                [
                    self._event(
                        tenant_id=tenant_a.id,
                        user_id=user_a.id,
                        amount=Decimal("0.123456789012"),
                        now=now,
                        group_id=group_a,
                    ),
                    self._event(
                        tenant_id=tenant_b.id,
                        user_id=user_b.id,
                        amount=Decimal("999.000000000000"),
                        now=now,
                        group_id=group_b,
                    ),
                ]
            )
            await db.commit()
            self.tenant_a = tenant_a.id
            self.tenant_b = tenant_b.id
            self.user_a = user_a.id
            self.user_b = user_b.id
            self.now = now
            self.group_a = group_a

    @staticmethod
    def _event(
        *, tenant_id, user_id: int, amount: Decimal, now: datetime, group_id
    ) -> db_models.LLMUsageEvent:
        event_id = uuid4()
        return db_models.LLMUsageEvent(
            id=event_id,
            idempotency_key=f"usage-center:{event_id}",
            operation_kind="chat",
            operation_id=str(uuid4()),
            stage="advisor",
            agent_name="chat_agent",
            user_id=user_id,
            tenant_id=tenant_id,
            group_ids=[group_id],
            provider="openai",
            requested_model="gpt-test",
            resolved_models=["gpt-test-2026"],
            request_count=1,
            tool_call_count=0,
            input_tokens=100,
            output_tokens=20,
            total_tokens=120,
            cache_read_tokens=25,
            cache_write_tokens=0,
            reasoning_tokens=5,
            usage_source="provider",
            quality_state="normalized",
            cost_status="exact",
            currency="USD",
            total_cost=amount,
            created_at=now,
        )

    async def asyncTearDown(self) -> None:
        async with AsyncSessionLocal() as db:
            await db.execute(
                delete(db_models.LLMUsageEvent).where(
                    db_models.LLMUsageEvent.tenant_id.in_(
                        (self.tenant_a, self.tenant_b)
                    )
                )
            )
            await db.execute(
                delete(db_models.User).where(
                    db_models.User.id.in_((self.user_a, self.user_b))
                )
            )
            await db.execute(
                delete(db_models.Tenant).where(
                    db_models.Tenant.id.in_((self.tenant_a, self.tenant_b))
                )
            )
            await db.commit()
        reset_principal(self.binding)
        await engine.dispose()

    async def test_summary_and_drilldown_never_cross_tenant(self) -> None:
        query = UsageQuery(
            tenant_id=self.tenant_a,
            from_at=self.now - timedelta(minutes=1),
            to_at=self.now + timedelta(minutes=1),
            visible_user_ids=(self.user_a,),
        )
        async with AsyncSessionLocal() as db:
            repo = UsageCenterRepository(db)
            totals = await UsageCenterService(repo).summary(query)
            events = await repo.list_events(query, limit=10)
            breakdown, count = await repo.breakdown(
                query, dimension="operation", page=1, page_size=10
            )
            groups, group_count = await repo.breakdown(
                query, dimension="group", page=1, page_size=10
            )
        self.assertEqual(totals.actual_cost, Decimal("0.123456789012"))
        self.assertEqual(totals.total_tokens, 120)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].tenant_id, self.tenant_a)
        self.assertEqual(count, 1)
        self.assertEqual(breakdown[0].key, "chat")
        self.assertEqual(group_count, 1)
        self.assertEqual(groups[0].key, str(self.group_a))


if __name__ == "__main__":
    unittest.main()
