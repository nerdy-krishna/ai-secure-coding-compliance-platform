"""PostgreSQL replay contract for governed finding fix candidates."""

from __future__ import annotations

import unittest
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.schemas import FixResult, FixSuggestion, VulnerabilityFinding
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import engine
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.shared.lib.finding_lineage_identity import (
    anchor_fingerprint,
    canonical_finding_id,
    fix_candidate_id,
    patch_fingerprint,
    raw_finding_id,
)
from app.shared.lib.patch_planner import ResolvedPatchRange
from tests.integration.support import integration_test


@integration_test
class FindingFixLineagePersistenceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.connection = await engine.connect()
        self.outer_transaction = await self.connection.begin()
        async with self._session() as db:
            user = db_models.User(
                email=f"lineage-{uuid4()}@example.invalid",
                hashed_password="not-a-real-password-hash",
                is_active=True,
                is_superuser=False,
                is_verified=True,
            )
            db.add(user)
            await db.flush()
            project = db_models.Project(name=f"lineage-{uuid4()}", user_id=user.id)
            db.add(project)
            await db.flush()
            scan = db_models.Scan(
                project_id=project.id, user_id=user.id, scan_type="SUGGEST"
            )
            db.add(scan)
            await db.commit()
            self.scan_id = scan.id

    async def asyncTearDown(self) -> None:
        await self.outer_transaction.rollback()
        await self.connection.close()
        await engine.dispose()

    def _session(self) -> AsyncSession:
        return AsyncSession(
            bind=self.connection,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        )

    def _candidate(self) -> FixResult:
        raw_id = raw_finding_id(self.scan_id, "analysis-task-a", 0)
        canonical_id = canonical_finding_id([raw_id])
        source_hash = "c" * 64
        suggestion = FixSuggestion(
            description="Parameterize the query",
            original_snippet="db.execute(query)",
            code="db.execute(query, params)",
        )
        anchor = anchor_fingerprint(
            file_path="app.py",
            source_snapshot_hash=source_hash,
            line_number=12,
            original_snippet=suggestion.original_snippet,
        )
        patch = patch_fingerprint(anchor=anchor, replacement_code=suggestion.code)
        finding = VulnerabilityFinding(
            raw_finding_id=raw_id,
            canonical_finding_id=canonical_id,
            contributing_raw_finding_ids=[raw_id],
            source_snapshot_hash=source_hash,
            title="SQL injection",
            description="Unsafe query construction",
            severity="High",
            line_number=12,
            remediation="Use bound parameters",
            confidence="High",
            references=[],
            file_path="app.py",
        )
        return FixResult(
            finding=finding,
            suggestion=suggestion,
            candidate_id=fix_candidate_id(raw_id=raw_id, patch=patch),
            raw_finding_id=raw_id,
            canonical_finding_id=canonical_id,
            source_snapshot_hash=source_hash,
            anchor_fingerprint=anchor,
            patch_fingerprint=patch,
            disposition="selected",
            decision_reason="Deterministic surviving candidate.",
            validation_status="passed",
            resolved_range=ResolvedPatchRange(
                start_byte=10,
                end_byte=27,
                start_line=12,
                start_column=1,
                end_line=12,
                end_column=18,
            ),
            context_fingerprint="d" * 64,
            patch_hunk_id=uuid4(),
            applicability_status="planned",
            required_imports=["from db import bind"],
        )

    async def test_replay_replaces_batch_without_duplicate_rows(self) -> None:
        candidate = self._candidate()
        async with self._session() as db:
            repo = ScanRepository(db)
            first = await repo.replace_fix_candidates_for_scan(
                self.scan_id, [candidate], batch=1
            )
            replay = await repo.replace_fix_candidates_for_scan(
                self.scan_id, [candidate], batch=1
            )
            count = await db.scalar(
                select(func.count()).select_from(db_models.FindingFixCandidate)
            )
            row = await db.scalar(select(db_models.FindingFixCandidate))

        self.assertEqual((first, replay, count), (1, 1, 1))
        self.assertEqual(row.candidate_id, candidate.candidate_id)
        self.assertEqual(row.disposition, "selected")
        self.assertEqual(row.source_snapshot_hash, candidate.source_snapshot_hash)
        self.assertEqual(row.resolved_range["start_byte"], 10)
        self.assertEqual(row.patch_hunk_id, candidate.patch_hunk_id)
        self.assertEqual(row.applicability_status, "planned")


if __name__ == "__main__":
    unittest.main()
