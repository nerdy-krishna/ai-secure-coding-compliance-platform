"""Real PostgreSQL proof that concurrent reservations cannot overspend."""

from __future__ import annotations

import asyncio
import unittest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import delete, select, text

from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.repositories.usage_budget_repo import (
    BudgetAmounts,
    BudgetReservationRequest,
    UsageBudgetRepository,
)
from app.infrastructure.database.tenant_context import bind_principal, reset_principal
from tests.integration.support import integration_test


@integration_test
class UsageBudgetConcurrencyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        binding = bind_principal(
            tenant_id=None,
            principal_kind="system",
            principal_id="usage-budget-test-setup",
            system_scope=True,
        )
        try:
            async with AsyncSessionLocal() as db:
                suffix = uuid4().hex[:12]
                tenant = db_models.Tenant(
                    slug=f"budget-race-{suffix}", display_name="Budget race tenant"
                )
                db.add(tenant)
                await db.flush()
                user = db_models.User(
                    email=f"budget-race-{suffix}@example.invalid",
                    hashed_password="not-a-real-password",
                    is_active=True,
                    is_superuser=False,
                    is_verified=True,
                    tenant_id=tenant.id,
                )
                db.add(user)
                await db.flush()
                db.add(
                    db_models.RoleAssignment(
                        user_id=user.id,
                        tenant_id=tenant.id,
                        role_key="tenant_admin",
                    )
                )
                groups = [
                    db_models.UserGroup(
                        name=f"budget-group-a-{suffix}",
                        created_by=user.id,
                        tenant_id=tenant.id,
                    ),
                    db_models.UserGroup(
                        name=f"budget-group-b-{suffix}",
                        created_by=user.id,
                        tenant_id=tenant.id,
                    ),
                ]
                db.add_all(groups)
                await db.flush()
                db.add_all(
                    [
                        db_models.UserGroupMembership(
                            group_id=group.id, user_id=user.id, role="member"
                        )
                        for group in groups
                    ]
                )
                project = db_models.Project(
                    user_id=user.id,
                    tenant_id=tenant.id,
                    name=f"budget-race-{suffix}",
                )
                scan = db_models.Scan(
                    project=project,
                    user_id=user.id,
                    tenant_id=tenant.id,
                    scan_type="AUDIT",
                    status="QUEUED",
                    frameworks=[],
                    summary={},
                )
                db.add_all([project, scan])
                await db.flush()
                attempt = db_models.ScanAttempt(
                    scan_id=scan.id,
                    tenant_id=tenant.id,
                    sequence=1,
                    trigger="initial",
                    status="active",
                    actor_user_id=user.id,
                    graph_thread_id=f"budget-race-{suffix}",
                )
                db.add(attempt)
                await db.flush()
                scan.current_attempt_id = attempt.id
                stage = f"budget-race-{suffix}"
                repo = UsageBudgetRepository(db)
                policy = await repo.create_policy(
                    tenant_id=tenant.id,
                    scope_kind="tenant",
                    window_kind="day",
                    reason="Concurrency integration-test policy",
                    created_by_user_id=user.id,
                    stage=stage,
                    cap_total_tokens=100,
                    soft_threshold_low=50,
                    commit=False,
                )
                group_policies = [
                    await repo.create_policy(
                        tenant_id=tenant.id,
                        scope_kind="group",
                        target_group_id=group.id,
                        window_kind="day",
                        reason="Overlapping group concurrency test policy",
                        created_by_user_id=user.id,
                        stage=stage,
                        cap_total_tokens=100,
                        commit=False,
                    )
                    for group in groups
                ]
                await db.commit()
                self.tenant_id = tenant.id
                self.user_id = user.id
                self.policy_ids = [policy.id, *(row.id for row in group_policies)]
                self.group_ids = tuple(group.id for group in groups)
                self.project_id = project.id
                self.scan_id = scan.id
                self.attempt_id = attempt.id
                self.stage = stage
        finally:
            reset_principal(binding)

    async def asyncTearDown(self) -> None:
        binding = bind_principal(
            tenant_id=None,
            principal_kind="system",
            principal_id="usage-budget-test-cleanup",
            system_scope=True,
        )
        try:
            async with AsyncSessionLocal() as db:
                for table in (
                    "usage_budget_policies",
                    "usage_budget_settlements",
                    "usage_budget_overrides",
                    "usage_budget_threshold_events",
                ):
                    await db.execute(
                        text(
                            f"ALTER TABLE {table} DISABLE TRIGGER "
                            "sccap_usage_budget_immutable"
                        )
                    )
                await db.execute(
                    delete(db_models.UsageBudgetNotificationOutbox).where(
                        db_models.UsageBudgetNotificationOutbox.tenant_id
                        == self.tenant_id
                    )
                )
                await db.execute(
                    delete(db_models.UsageBudgetThresholdEvent).where(
                        db_models.UsageBudgetThresholdEvent.tenant_id == self.tenant_id
                    )
                )
                await db.execute(
                    delete(db_models.UsageBudgetAllocation).where(
                        db_models.UsageBudgetAllocation.tenant_id == self.tenant_id
                    )
                )
                await db.execute(
                    delete(db_models.UsageBudgetSettlement).where(
                        db_models.UsageBudgetSettlement.tenant_id == self.tenant_id
                    )
                )
                await db.execute(
                    delete(db_models.UsageBudgetReservation).where(
                        db_models.UsageBudgetReservation.tenant_id == self.tenant_id
                    )
                )
                await db.execute(
                    delete(db_models.UsageBudgetCounter).where(
                        db_models.UsageBudgetCounter.tenant_id == self.tenant_id
                    )
                )
                await db.execute(
                    delete(db_models.UsageBudgetOverride).where(
                        db_models.UsageBudgetOverride.tenant_id == self.tenant_id
                    )
                )
                await db.execute(
                    delete(db_models.UsageBudgetPolicy).where(
                        db_models.UsageBudgetPolicy.tenant_id == self.tenant_id
                    )
                )
                await db.execute(
                    delete(db_models.RoleAssignment).where(
                        db_models.RoleAssignment.tenant_id == self.tenant_id
                    )
                )
                await db.execute(
                    delete(db_models.UserGroupMembership).where(
                        db_models.UserGroupMembership.group_id.in_(self.group_ids)
                    )
                )
                await db.execute(
                    delete(db_models.UserGroup).where(
                        db_models.UserGroup.id.in_(self.group_ids)
                    )
                )
                scan = await db.get(db_models.Scan, self.scan_id)
                if scan is not None:
                    scan.current_attempt_id = None
                    await db.flush()
                await db.execute(
                    delete(db_models.ScanAttempt).where(
                        db_models.ScanAttempt.id == self.attempt_id
                    )
                )
                await db.execute(
                    delete(db_models.Scan).where(db_models.Scan.id == self.scan_id)
                )
                await db.execute(
                    delete(db_models.Project).where(
                        db_models.Project.id == self.project_id
                    )
                )
                await db.execute(
                    delete(db_models.User).where(db_models.User.id == self.user_id)
                )
                await db.execute(
                    delete(db_models.Tenant).where(
                        db_models.Tenant.id == self.tenant_id
                    )
                )
                for table in (
                    "usage_budget_policies",
                    "usage_budget_settlements",
                    "usage_budget_overrides",
                    "usage_budget_threshold_events",
                ):
                    await db.execute(
                        text(
                            f"ALTER TABLE {table} ENABLE TRIGGER "
                            "sccap_usage_budget_immutable"
                        )
                    )
                await db.commit()
        finally:
            reset_principal(binding)
            await engine.dispose()

    async def _reserve(self, key: str):
        binding = bind_principal(
            tenant_id=self.tenant_id,
            principal_kind="human",
            principal_id=str(self.user_id),
        )
        try:
            async with AsyncSessionLocal() as db:
                return await UsageBudgetRepository(db).reserve(
                    BudgetReservationRequest(
                        tenant_id=self.tenant_id,
                        idempotency_key=key,
                        operation_kind="scan",
                        request_key=key,
                        stage=self.stage,
                        estimate=BudgetAmounts(total_tokens=60),
                        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                        actor_user_id=self.user_id,
                        group_ids=self.group_ids,
                        scan_attempt_id=self.attempt_id,
                        window_kinds=("day",),
                    )
                )
        finally:
            reset_principal(binding)

    async def test_only_one_contender_can_take_last_allowance(self) -> None:
        first, second = await asyncio.gather(
            self._reserve(f"race-a:{uuid4()}"),
            self._reserve(f"race-b:{uuid4()}"),
        )
        self.assertEqual(sum(decision.allowed for decision in (first, second)), 1)
        denied = first if not first.allowed else second
        self.assertEqual(denied.denial.dimension, "total_tokens")
        self.assertEqual(denied.denial.remaining, 40)

        binding = bind_principal(
            tenant_id=self.tenant_id,
            principal_kind="human",
            principal_id=str(self.user_id),
        )
        try:
            async with AsyncSessionLocal() as db:
                counters = list(
                    (
                        await db.scalars(
                            select(db_models.UsageBudgetCounter).where(
                                db_models.UsageBudgetCounter.policy_id.in_(
                                    self.policy_ids
                                )
                            )
                        )
                    ).all()
                )
                self.assertEqual(len(counters), 3)
                self.assertEqual(
                    [counter.held_total_tokens for counter in counters],
                    [60, 60, 60],
                )
                counter = next(
                    row for row in counters if row.policy_id == self.policy_ids[0]
                )
                threshold = await db.scalar(
                    select(db_models.UsageBudgetThresholdEvent).where(
                        db_models.UsageBudgetThresholdEvent.counter_id == counter.id,
                        db_models.UsageBudgetThresholdEvent.dimension
                        == "total_tokens",
                        db_models.UsageBudgetThresholdEvent.threshold_percent == 50,
                    )
                )
                self.assertIsNotNone(threshold)
                notification = await db.scalar(
                    select(db_models.UsageBudgetNotificationOutbox).where(
                        db_models.UsageBudgetNotificationOutbox.threshold_event_id
                        == threshold.id,
                        db_models.UsageBudgetNotificationOutbox.recipient_user_id
                        == self.user_id,
                    )
                )
                self.assertEqual(notification.state, "pending")
        finally:
            reset_principal(binding)


if __name__ == "__main__":
    unittest.main()
