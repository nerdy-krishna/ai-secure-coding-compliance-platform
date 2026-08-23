"""PostgreSQL integration tests for atomic scan lifecycle decisions."""

from __future__ import annotations

import asyncio
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.models import ApprovalRequest, ScanRunControlRequest
from app.core.services.scan.lifecycle import ScanLifecycleService
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.repositories.approval_gate_repo import (
    ApprovalGateRepository,
)
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.shared.lib.scan_status import (
    STATUS_CANCELLED,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PENDING_APPROVAL,
    STATUS_PENDING_PRESCAN_APPROVAL,
    STATUS_PENDING_PROFILING_APPROVAL,
    STATUS_QUEUED,
    STATUS_QUEUED_FOR_SCAN,
)
from app.shared.lib.scan_task_status import STATUS_SCAN_TASK_COMPLETED
from tests.integration.support import integration_test


@integration_test
class AtomicScanLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.connection = await engine.connect()
        self.outer_transaction = await self.connection.begin()

        async with self._session() as db:
            user = db_models.User(
                email=f"atomic-lifecycle-{uuid4()}@example.invalid",
                hashed_password="not-a-real-password-hash",
                is_active=True,
                is_superuser=False,
                is_verified=True,
            )
            db.add(user)
            await db.commit()
            self.user_id = user.id

    async def asyncTearDown(self) -> None:
        await self.outer_transaction.rollback()
        await self.connection.close()
        # IsolatedAsyncioTestCase creates a new event loop for each test.
        await engine.dispose()

    def _session(self) -> AsyncSession:
        return AsyncSession(
            bind=self.connection,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        )

    async def _create_scan(
        self,
        db: AsyncSession,
        *,
        scan_status: str,
        with_restart_artifacts: bool = False,
    ) -> tuple[db_models.User, db_models.Scan]:
        user = await db.get(db_models.User, self.user_id)
        assert user is not None
        project = db_models.Project(
            user_id=self.user_id,
            name=f"atomic-lifecycle-{uuid4()}",
        )
        scan = db_models.Scan(
            project=project,
            user_id=self.user_id,
            scan_type="AUDIT",
            status=scan_status,
            frameworks=[],
            summary={"stale": True},
            risk_score=99,
            completed_at=datetime.now(timezone.utc),
        )
        db.add_all([project, scan])
        await db.flush()

        if with_restart_artifacts:
            db.add_all(
                [
                    db_models.ScanTask(
                        scan_id=scan.id,
                        task_type="analysis",
                        task_key="src/example.py",
                        input_hash="i" * 64,
                        prompt_hash="p" * 64,
                        version_hash="v" * 64,
                        input_payload={"path": "src/example.py"},
                        result_payload={"findings": []},
                        status=STATUS_SCAN_TASK_COMPLETED,
                    ),
                    db_models.Finding(
                        scan_id=scan.id,
                        file_path="src/example.py",
                        title="Derived result",
                        severity="High",
                        finding_bucket="consolidated",
                    ),
                    db_models.Finding(
                        scan_id=scan.id,
                        file_path="src/example.py",
                        title="Preserved scanner evidence",
                        severity="High",
                        finding_bucket="sast",
                    ),
                    db_models.CodeSnapshot(
                        scan_id=scan.id,
                        snapshot_type="ORIGINAL_SUBMISSION",
                        file_map={"src/example.py": "original-hash"},
                    ),
                    db_models.CodeSnapshot(
                        scan_id=scan.id,
                        snapshot_type="REMEDIATED",
                        file_map={"src/example.py": "derived-hash"},
                    ),
                ]
            )
        await db.commit()
        return user, scan

    async def _outbox_rows(
        self, db: AsyncSession, scan_id
    ) -> list[db_models.ScanOutbox]:
        return list(
            (
                await db.scalars(
                    select(db_models.ScanOutbox).where(
                        db_models.ScanOutbox.scan_id == scan_id
                    )
                )
            ).all()
        )

    async def test_approval_is_atomic_outbox_only_and_duplicate_is_idempotent(
        self,
    ) -> None:
        async with self._session() as db:
            user, scan = await self._create_scan(
                db, scan_status=STATUS_PENDING_APPROVAL
            )
            service = ScanLifecycleService(ScanRepository(db))
            audit_writer = AsyncMock(wraps=service.repo.create_scan_event)
            service.repo.create_scan_event = audit_writer  # type: ignore[method-assign]
            request = ApprovalRequest(kind="cost_approval", approved=True)

            with patch(
                "app.infrastructure.messaging.publisher.publish_message",
                new=AsyncMock(return_value=True),
            ) as publisher:
                first = await service.approve_scan(
                    scan.id, user, request, idempotency_key="same-decision"
                )
                duplicate = await service.approve_scan(
                    scan.id, user, request, idempotency_key="same-decision"
                )

            self.assertEqual(first.gate_id, duplicate.gate_id)
            publisher.assert_not_awaited()
            self.assertEqual(
                await db.scalar(
                    select(db_models.Scan.status).where(db_models.Scan.id == scan.id)
                ),
                STATUS_QUEUED_FOR_SCAN,
            )
            rows = await self._outbox_rows(db, scan.id)
            self.assertEqual(len(rows), 1)
            self.assertIsNone(rows[0].published_at)
            self.assertEqual(rows[0].payload["action"], "resume_analysis")
            self.assertEqual(rows[0].payload["kind"], "cost_approval")
            self.assertTrue(rows[0].payload["approved"])
            self.assertEqual(rows[0].payload["gate_id"], str(first.gate_id))
            self.assertEqual(rows[0].idempotency_key, f"approval-gate:{first.gate_id}")

            with self.assertRaises(HTTPException) as conflict:
                await service.approve_scan(
                    scan.id,
                    user,
                    ApprovalRequest(
                        kind="cost_approval",
                        approved=False,
                        gate_id=first.gate_id,
                    ),
                    idempotency_key="conflicting-decision",
                )
            self.assertEqual(conflict.exception.status_code, 409)
            self.assertEqual(
                conflict.exception.detail,
                "This gate already has a different durable decision; the first decision wins.",
            )
            rejected_calls = [
                invocation
                for invocation in audit_writer.await_args_list
                if invocation.kwargs.get("stage_name") == "APPROVAL_DECISION_REJECTED"
            ]
            self.assertEqual(len(rejected_calls), 1)

    async def test_decline_commits_auditable_event_and_outbox_intent(self) -> None:
        async with self._session() as db:
            user, scan = await self._create_scan(
                db, scan_status=STATUS_PENDING_PROFILING_APPROVAL
            )
            service = ScanLifecycleService(ScanRepository(db))

            await service.approve_scan(
                scan.id,
                user,
                ApprovalRequest(kind="profiling_approval", approved=False),
            )

            stages = set(
                (
                    await db.scalars(
                        select(db_models.ScanEvent.stage_name).where(
                            db_models.ScanEvent.scan_id == scan.id
                        )
                    )
                ).all()
            )
            rows = await self._outbox_rows(db, scan.id)
            self.assertEqual(
                await db.scalar(
                    select(db_models.Scan.status).where(db_models.Scan.id == scan.id)
                ),
                STATUS_QUEUED_FOR_SCAN,
            )
            self.assertEqual(stages, {"PROFILING_USER_DECLINED", "QUEUED_FOR_SCAN"})
            self.assertEqual(len(rows), 1)
            self.assertFalse(rows[0].payload["approved"])

    async def test_prescan_override_gate_uses_the_same_guarded_boundary(self) -> None:
        async with self._session() as db:
            user, scan = await self._create_scan(
                db, scan_status=STATUS_PENDING_PRESCAN_APPROVAL
            )
            service = ScanLifecycleService(ScanRepository(db))

            await service.approve_scan(
                scan.id,
                user,
                ApprovalRequest(
                    kind="prescan_approval",
                    approved=True,
                    override_critical_secret=True,
                ),
            )

            stages = set(
                (
                    await db.scalars(
                        select(db_models.ScanEvent.stage_name).where(
                            db_models.ScanEvent.scan_id == scan.id
                        )
                    )
                ).all()
            )
            self.assertEqual(
                stages,
                {"PRESCAN_OVERRIDE_CRITICAL_SECRET", "QUEUED_FOR_SCAN"},
            )
            self.assertEqual(len(await self._outbox_rows(db, scan.id)), 1)

    async def test_approval_failure_rolls_back_status_event_and_outbox(self) -> None:
        async with self._session() as db:
            user, scan = await self._create_scan(
                db, scan_status=STATUS_PENDING_APPROVAL
            )
            scan_id = scan.id
            service = ScanLifecycleService(ScanRepository(db))
            enqueue = service.outbox.enqueue

            async def fail_after_enqueue(*args, **kwargs):
                await enqueue(*args, **kwargs)
                raise RuntimeError("injected lifecycle failure")

            service.outbox.enqueue = fail_after_enqueue  # type: ignore[method-assign]
            with patch("app.core.services.scan.lifecycle.logger"):
                with self.assertRaisesRegex(RuntimeError, "injected lifecycle failure"):
                    await service.approve_scan(
                        scan_id,
                        user,
                        ApprovalRequest(kind="cost_approval", approved=True),
                    )

            self.assertEqual(
                await db.scalar(
                    select(db_models.Scan.status).where(db_models.Scan.id == scan_id)
                ),
                STATUS_PENDING_APPROVAL,
            )
            self.assertEqual(
                await db.scalar(
                    select(func.count())
                    .select_from(db_models.ScanEvent)
                    .where(db_models.ScanEvent.scan_id == scan_id)
                ),
                0,
            )
            self.assertEqual(len(await self._outbox_rows(db, scan_id)), 0)

    async def test_resume_preserves_completed_work_and_enqueues_routing_fields(
        self,
    ) -> None:
        async with self._session() as db:
            user, scan = await self._create_scan(
                db,
                scan_status=STATUS_CANCELLED,
                with_restart_artifacts=True,
            )
            service = ScanLifecycleService(ScanRepository(db))

            result = await service.resume_or_restart_scan(
                scan.id, user, ScanRunControlRequest(mode="resume")
            )

            rows = await self._outbox_rows(db, scan.id)
            self.assertEqual(result["artifact_counts"], {STATUS_SCAN_TASK_COMPLETED: 1})
            self.assertEqual(
                await db.scalar(
                    select(func.count())
                    .select_from(db_models.ScanTask)
                    .where(db_models.ScanTask.scan_id == scan.id)
                ),
                1,
            )
            self.assertEqual(rows[0].payload["action"], "manual_resume")
            self.assertEqual(rows[0].payload["mode"], "resume")

    async def test_restart_cleanup_and_dispatch_commit_together(self) -> None:
        async with self._session() as db:
            user, scan = await self._create_scan(
                db,
                scan_status=STATUS_FAILED,
                with_restart_artifacts=True,
            )
            service = ScanLifecycleService(ScanRepository(db))

            result = await service.resume_or_restart_scan(
                scan.id, user, ScanRunControlRequest(mode="restart")
            )

            finding_buckets = list(
                (
                    await db.scalars(
                        select(db_models.Finding.finding_bucket).where(
                            db_models.Finding.scan_id == scan.id
                        )
                    )
                ).all()
            )
            snapshot_types = list(
                (
                    await db.scalars(
                        select(db_models.CodeSnapshot.snapshot_type).where(
                            db_models.CodeSnapshot.scan_id == scan.id
                        )
                    )
                ).all()
            )
            rows = await self._outbox_rows(db, scan.id)
            scan_values = (
                await db.execute(
                    select(
                        db_models.Scan.status,
                        db_models.Scan.summary,
                        db_models.Scan.risk_score,
                    ).where(db_models.Scan.id == scan.id)
                )
            ).one()

            self.assertEqual(result["deleted_tasks"], 1)
            self.assertEqual(result["deleted_findings"], 1)
            self.assertEqual(result["deleted_derived_snapshots"], 1)
            self.assertEqual(scan_values, (STATUS_QUEUED, None, None))
            self.assertEqual(finding_buckets, ["sast"])
            self.assertEqual(snapshot_types, ["ORIGINAL_SUBMISSION"])
            self.assertEqual(rows[0].payload["action"], "manual_restart")
            self.assertEqual(rows[0].payload["mode"], "restart")

    async def test_restart_failure_rolls_back_cleanup_and_requeue(self) -> None:
        async with self._session() as db:
            user, scan = await self._create_scan(
                db,
                scan_status=STATUS_FAILED,
                with_restart_artifacts=True,
            )
            scan_id = scan.id
            service = ScanLifecycleService(ScanRepository(db))
            enqueue = service.outbox.enqueue

            async def fail_after_enqueue(*args, **kwargs):
                await enqueue(*args, **kwargs)
                raise RuntimeError("injected restart failure")

            service.outbox.enqueue = fail_after_enqueue  # type: ignore[method-assign]
            with patch("app.core.services.scan.lifecycle.logger"):
                with self.assertRaisesRegex(RuntimeError, "injected restart failure"):
                    await service.resume_or_restart_scan(
                        scan_id, user, ScanRunControlRequest(mode="restart")
                    )

            self.assertEqual(
                await db.scalar(
                    select(db_models.Scan.status).where(db_models.Scan.id == scan_id)
                ),
                STATUS_FAILED,
            )
            self.assertEqual(
                await db.scalar(
                    select(func.count())
                    .select_from(db_models.ScanTask)
                    .where(db_models.ScanTask.scan_id == scan_id)
                ),
                1,
            )
            self.assertEqual(
                await db.scalar(
                    select(func.count())
                    .select_from(db_models.Finding)
                    .where(db_models.Finding.scan_id == scan_id)
                ),
                2,
            )
            self.assertEqual(
                await db.scalar(
                    select(func.count())
                    .select_from(db_models.CodeSnapshot)
                    .where(db_models.CodeSnapshot.scan_id == scan_id)
                ),
                2,
            )
            self.assertEqual(len(await self._outbox_rows(db, scan_id)), 0)

    async def test_cancel_failure_rolls_back_terminal_status(self) -> None:
        async with self._session() as db:
            user, scan = await self._create_scan(db, scan_status=STATUS_QUEUED)
            scan_id = scan.id
            service = ScanLifecycleService(ScanRepository(db))
            service.repo.create_scan_event = AsyncMock(
                side_effect=RuntimeError("injected cancellation failure")
            )

            with patch("app.core.services.scan.lifecycle.logger"):
                with self.assertRaisesRegex(
                    RuntimeError, "injected cancellation failure"
                ):
                    await service.cancel_scan(scan_id, user)

            self.assertEqual(
                await db.scalar(
                    select(db_models.Scan.status).where(db_models.Scan.id == scan_id)
                ),
                STATUS_QUEUED,
            )

    async def test_cancel_closes_the_active_gate_in_the_same_transaction(self) -> None:
        async with self._session() as db:
            user, scan = await self._create_scan(
                db, scan_status=STATUS_PENDING_PROFILING_APPROVAL
            )
            gate = await ApprovalGateRepository(db).create_or_get_pending(
                scan_id=scan.id,
                kind="profiling_approval",
                node_name="profiling_cost_gate",
                display_name="Approve file profiling cost",
                purpose="Authorize profiling.",
                evidence={"upper_bound_estimated_cost": 0.25},
            )

            await ScanLifecycleService(ScanRepository(db)).cancel_scan(scan.id, user)

            await db.refresh(gate)
            self.assertEqual(gate.state, "cancelled")
            self.assertEqual(
                await db.scalar(
                    select(db_models.Scan.status).where(db_models.Scan.id == scan.id)
                ),
                STATUS_CANCELLED,
            )
            cancellation_events = (
                await db.scalars(
                    select(db_models.ScanEvent)
                    .where(
                        db_models.ScanEvent.scan_id == scan.id,
                        db_models.ScanEvent.stage_name == "CANCELLATION",
                    )
                    .order_by(db_models.ScanEvent.id)
                )
            ).all()
            self.assertEqual(
                [event.status for event in cancellation_events],
                ["REQUESTED", "OBSERVED", "COMPLETED"],
            )
            self.assertTrue(
                all(event.schema_version == 1 for event in cancellation_events)
            )
            self.assertTrue(
                all(
                    event.activity_kind == "cancellation"
                    for event in cancellation_events
                )
            )

    async def test_late_worker_writes_cannot_overwrite_completed_scan(self) -> None:
        async with self._session() as db:
            _user, scan = await self._create_scan(db, scan_status=STATUS_COMPLETED)
            scan_id = scan.id
            repo = ScanRepository(db)

            failed = await repo.update_status(scan_id, STATUS_FAILED)
            running_event = await repo.record_scan_event(
                scan_id, "RUNNING_AGENTS", "STARTED"
            )
            finalized = await repo.save_final_reports_and_status(
                scan_id=scan_id,
                status=STATUS_COMPLETED,
                summary={"replaced": True},
                risk_score=1,
            )

            status_and_summary = (
                await db.execute(
                    select(db_models.Scan.status, db_models.Scan.summary).where(
                        db_models.Scan.id == scan_id
                    )
                )
            ).one()
            event_count = await db.scalar(
                select(func.count())
                .select_from(db_models.ScanEvent)
                .where(db_models.ScanEvent.scan_id == scan_id)
            )

            self.assertFalse(failed)
            self.assertFalse(running_event)
            self.assertFalse(finalized)
            self.assertEqual(status_and_summary, (STATUS_COMPLETED, {"stale": True}))
            self.assertEqual(event_count, 0)

    async def test_normal_writer_cannot_use_manual_terminal_reset_edge(self) -> None:
        async with self._session() as db:
            _user, scan = await self._create_scan(db, scan_status=STATUS_FAILED)
            changed = await ScanRepository(db).update_status(scan.id, STATUS_QUEUED)

            self.assertFalse(changed)
            self.assertEqual(
                await db.scalar(
                    select(db_models.Scan.status).where(db_models.Scan.id == scan.id)
                ),
                STATUS_FAILED,
            )


@integration_test
class ApprovalGateLeaseTests(unittest.IsolatedAsyncioTestCase):
    async def test_concurrent_claim_crash_recovery_and_stale_gate_are_one_shot(
        self,
    ) -> None:
        """Independent PostgreSQL sessions model competing consumer processes."""
        user_id: int | None = None
        project_id = None
        scan_id = None
        try:
            async with AsyncSessionLocal() as db:
                user = db_models.User(
                    email=f"gate-lease-{uuid4()}@example.invalid",
                    hashed_password="not-a-real-password-hash",
                    is_active=True,
                    is_superuser=False,
                    is_verified=True,
                )
                project = db_models.Project(user=user, name=f"gate-lease-{uuid4()}")
                scan = db_models.Scan(
                    project=project,
                    user=user,
                    scan_type="AUDIT",
                    status=STATUS_QUEUED_FOR_SCAN,
                    frameworks=[],
                )
                db.add_all([user, project, scan])
                await db.commit()
                user_id, project_id, scan_id = user.id, project.id, scan.id

                gates = ApprovalGateRepository(db)
                gate = await gates.create_or_get_pending(
                    scan_id=scan.id,
                    kind="cost_approval",
                    node_name="cost_gate",
                    display_name="Approve full security analysis cost",
                    purpose="Authorize the full analysis estimate.",
                    evidence={"upper_bound_estimated_cost": 1.25},
                )
                await gates.record_decision(
                    gate,
                    actor_user_id=user.id,
                    approved=True,
                    override_critical_secret=False,
                    idempotency_key="lease-test-decision",
                )
                await db.commit()
                gate_id = gate.gate_id

            async def claim(owner: str) -> str:
                async with AsyncSessionLocal() as claim_db:
                    status, _ = await ApprovalGateRepository(claim_db).claim_resume(
                        gate_id, owner=owner, lease_seconds=60
                    )
                    return status

            claims = await asyncio.gather(claim("consumer-a"), claim("consumer-b"))
            self.assertCountEqual(claims, ["claimed", "busy"])

            async with AsyncSessionLocal() as db:
                self.assertTrue(await ApprovalGateRepository(db).mark_resumed(gate_id))
                resumed = await ApprovalGateRepository(db).get(gate_id)
                self.assertIsNotNone(resumed)
                self.assertEqual(resumed.state, "resumed")

            # Model a worker dying without releasing its lease. Once the bounded
            # lease expires after interrupt() returned but before checkpoint
            # completion, one replacement consumer can reclaim it.
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(db_models.ApprovalGate)
                    .where(db_models.ApprovalGate.gate_id == gate_id)
                    .values(
                        resume_lease_expires_at=datetime.now(timezone.utc)
                        - timedelta(seconds=1)
                    )
                )
                await db.commit()
            self.assertEqual(await claim("consumer-c"), "claimed")

            async with AsyncSessionLocal() as db:
                self.assertTrue(await ApprovalGateRepository(db).complete(gate_id))
            self.assertEqual(await claim("late-redelivery"), "completed")

            async with AsyncSessionLocal() as db:
                next_gate = await ApprovalGateRepository(db).create_or_get_pending(
                    scan_id=scan_id,
                    kind="cost_approval",
                    node_name="cost_gate",
                    display_name="Approve full security analysis cost",
                    purpose="Authorize a later restarted analysis estimate.",
                    evidence={"upper_bound_estimated_cost": 2.5},
                )
            self.assertNotEqual(next_gate.gate_id, gate_id)
            self.assertEqual(next_gate.sequence, 2)
            self.assertEqual(await claim("stale-prior-gate"), "completed")
        finally:
            if user_id is not None:
                async with AsyncSessionLocal() as db:
                    if scan_id is not None:
                        await db.execute(
                            delete(db_models.Scan).where(db_models.Scan.id == scan_id)
                        )
                    if project_id is not None:
                        await db.execute(
                            delete(db_models.Project).where(
                                db_models.Project.id == project_id
                            )
                        )
                    await db.execute(
                        delete(db_models.User).where(db_models.User.id == user_id)
                    )
                    await db.commit()
            await engine.dispose()


if __name__ == "__main__":
    unittest.main()
