"""Real PostgreSQL contract for durable scanner coverage and lineage."""

from __future__ import annotations

import unittest
from uuid import uuid4

from sqlalchemy import delete, select

from app.core.schemas import VulnerabilityFinding
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.repositories.scan_attempt_repo import (
    ScanAttemptRepository,
)
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.database.repositories.scanner_coverage_repo import (
    CoverageOutcome,
    CoveragePlanItem,
    ScannerCoverageRepository,
)
from tests.integration.support import integration_test


@integration_test
class ScannerCoveragePersistenceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        async with AsyncSessionLocal() as db:
            user = db_models.User(
                email=f"scanner-coverage-{uuid4()}@example.invalid",
                hashed_password="not-a-real-password",
                is_active=True,
                is_superuser=True,
                is_verified=True,
            )
            db.add(user)
            await db.flush()
            project = db_models.Project(user_id=user.id, name=f"coverage-{uuid4()}")
            scan = db_models.Scan(
                project=project,
                user_id=user.id,
                scan_type="AUDIT",
                status="RUNNING",
                frameworks=[],
                summary={},
            )
            db.add_all([project, scan])
            await db.flush()
            attempt = await ScanAttemptRepository(db).create_initial(
                scan, actor_user_id=user.id, commit=False
            )
            await db.commit()
            self.user_id = user.id
            self.project_id = project.id
            self.scan_id = scan.id
            self.attempt_id = attempt.id

    async def asyncTearDown(self) -> None:
        try:
            async with AsyncSessionLocal() as db:
                await ScanRepository(db).delete_project(self.project_id)
                await db.execute(
                    delete(db_models.User).where(db_models.User.id == self.user_id)
                )
                await db.commit()
        finally:
            await engine.dispose()

    async def test_partial_degradation_persists_and_finding_links_exact_entry(
        self,
    ) -> None:
        async with AsyncSessionLocal() as db:
            coverage = ScannerCoverageRepository(db)
            planned = await coverage.plan(
                self.scan_id,
                [
                    CoveragePlanItem("bandit", "app.py"),
                    CoveragePlanItem("semgrep", "app.py"),
                ],
            )
            entries = await coverage.record_outcomes(
                self.scan_id,
                [
                    CoverageOutcome(
                        "bandit",
                        "app.py",
                        "completed",
                        finding_count=1,
                        native_evidence_available=True,
                    ),
                    CoverageOutcome(
                        "semgrep",
                        "app.py",
                        "timeout",
                        reason_code="scanner_timeout",
                        reason="Scanner timed out.",
                    ),
                ],
            )
            finding = VulnerabilityFinding(
                coverage_entry_id=planned[("bandit", "app.py")].id,
                coverage_entry_ids=[planned[("bandit", "app.py")].id],
                title="Unsafe subprocess invocation",
                description="Untrusted input reaches a shell.",
                severity="High",
                line_number=4,
                remediation="Use an argument vector.",
                confidence="High",
                file_path="app.py",
                source="bandit",
                references=[],
            )
            await ScanRepository(db).save_findings(
                self.scan_id, [finding], finding_bucket="sast"
            )

            manifest = await coverage.manifest(self.scan_id)
            self.assertEqual(manifest["overall_status"], "degraded")
            self.assertFalse(manifest["is_complete"])
            self.assertEqual(manifest["counts"]["completed"], 1)
            self.assertEqual(manifest["counts"]["timeout"], 1)
            row = await db.scalar(
                select(db_models.Finding).where(db_models.Finding.id == finding.id)
            )
            self.assertEqual(
                row.coverage_entry_id, entries[("bandit", "app.py")].id
            )
            self.assertEqual(
                row.coverage_entry_ids, [entries[("bandit", "app.py")].id]
            )

            failed = await coverage.evaluate_policy(
                self.scan_id,
                failing_states=["failed", "timeout"],
                waive=False,
                audit_reason="Release policy requires complete deterministic coverage.",
                actor_user_id=self.user_id,
            )
            waived = await coverage.evaluate_policy(
                self.scan_id,
                failing_states=["failed", "timeout"],
                waive=True,
                audit_reason="Emergency release accepted by the authorized approver.",
                actor_user_id=self.user_id,
            )
            self.assertEqual(failed.outcome, "fail")
            self.assertEqual(waived.outcome, "waived")
            self.assertEqual(failed.matching_entry_ids, waived.matching_entry_ids)


if __name__ == "__main__":
    unittest.main()
