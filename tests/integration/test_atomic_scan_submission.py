"""PostgreSQL integration tests for the scan-submission transaction boundary."""

from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, patch
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.services.scan.submission import ScanSubmissionService
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import engine
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from tests.integration.support import integration_test


@integration_test
class AtomicScanSubmissionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.connection = await engine.connect()
        self.outer_transaction = await self.connection.begin()

        async with self._session() as db:
            user = db_models.User(
                email=f"atomic-scan-{uuid4()}@example.invalid",
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
        # IsolatedAsyncioTestCase creates a fresh event loop per test. Dispose
        # pooled asyncpg connections before the next loop starts.
        await engine.dispose()

    def _session(self) -> AsyncSession:
        # Service-level commits release only their savepoint. The surrounding
        # connection transaction is rolled back in teardown, so tests never
        # leave projects, scans, source, or outbox rows in the developer DB.
        return AsyncSession(
            bind=self.connection,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        )

    async def _submit(self, db: AsyncSession, project_name: str, content: str):
        service = ScanSubmissionService(ScanRepository(db))
        with patch(
            "app.core.services.scan.submission.validate_framework_selection",
            new=AsyncMock(return_value=None),
        ), patch(
            "app.infrastructure.messaging.publisher.publish_message",
            new=AsyncMock(return_value=True),
        ) as publisher:
            scan = await service._process_and_launch_scan(
                project_name=project_name,
                user_id=self.user_id,
                files_data=[
                    {
                        "path": "src/example.py",
                        "content": content,
                        "language": "python",
                    }
                ],
                scan_type="AUDIT",
                correlation_id=f"test-{uuid4()}",
                reasoning_llm_config_id=None,  # type: ignore[arg-type]
                frameworks=[],
            )
        publisher.assert_not_awaited()
        return scan

    async def test_success_commits_complete_aggregate_and_one_outbox_intent(
        self,
    ) -> None:
        project_name = f"atomic-success-{uuid4()}"
        async with self._session() as db:
            scan = await self._submit(db, project_name, "print('success')\n")

            snapshot_count = await db.scalar(
                select(func.count())
                .select_from(db_models.CodeSnapshot)
                .where(db_models.CodeSnapshot.scan_id == scan.id)
            )
            event_count = await db.scalar(
                select(func.count())
                .select_from(db_models.ScanEvent)
                .where(db_models.ScanEvent.scan_id == scan.id)
            )
            outbox_rows = list(
                (
                    await db.scalars(
                        select(db_models.ScanOutbox).where(
                            db_models.ScanOutbox.scan_id == scan.id
                        )
                    )
                ).all()
            )

            self.assertEqual(snapshot_count, 1)
            self.assertEqual(event_count, 1)
            self.assertEqual(len(outbox_rows), 1)
            self.assertIsNone(outbox_rows[0].published_at)
            self.assertEqual(outbox_rows[0].payload["scan_id"], str(scan.id))
            self.assertEqual(outbox_rows[0].payload["outbox_id"], str(outbox_rows[0].id))
            self.assertEqual(outbox_rows[0].payload["tenant_id"], str(scan.tenant_id))
            self.assertTrue(
                outbox_rows[0].payload["correlation_id"].startswith("test-")
            )

    async def test_failure_rolls_back_project_scan_snapshot_event_and_outbox(
        self,
    ) -> None:
        project_name = f"atomic-rollback-{uuid4()}"
        async with self._session() as db:
            service = ScanSubmissionService(ScanRepository(db))
            enqueue = service.outbox.enqueue

            async def fail_after_enqueue(*args, **kwargs):
                await enqueue(*args, **kwargs)
                raise RuntimeError("injected failure before aggregate commit")

            service.outbox.enqueue = fail_after_enqueue  # type: ignore[method-assign]
            with patch(
                "app.core.services.scan.submission.validate_framework_selection",
                new=AsyncMock(return_value=None),
            ), patch("app.core.services.scan.submission.logger"):
                with self.assertRaisesRegex(RuntimeError, "injected failure"):
                    await service._process_and_launch_scan(
                        project_name=project_name,
                        user_id=self.user_id,
                        files_data=[
                            {
                                "path": "src/rollback.py",
                                "content": "print('rollback')\n",
                                "language": "python",
                            }
                        ],
                        scan_type="AUDIT",
                        correlation_id=f"test-{uuid4()}",
                        reasoning_llm_config_id=None,  # type: ignore[arg-type]
                        frameworks=[],
                    )

            project_count = await db.scalar(
                select(func.count())
                .select_from(db_models.Project)
                .where(db_models.Project.name == project_name)
            )
            scan_count = await db.scalar(
                select(func.count())
                .select_from(db_models.Scan)
                .join(db_models.Project)
                .where(db_models.Project.name == project_name)
            )
            outbox_count = await db.scalar(
                select(func.count())
                .select_from(db_models.ScanOutbox)
                .join(db_models.Scan)
                .join(db_models.Project)
                .where(db_models.Project.name == project_name)
            )

            self.assertEqual(project_count, 0)
            self.assertEqual(scan_count, 0)
            self.assertEqual(outbox_count, 0)


if __name__ == "__main__":
    unittest.main()
