"""Real PostgreSQL + MinIO contracts for immutable scan evidence."""

from __future__ import annotations

import unittest
from uuid import uuid4

from sqlalchemy import delete, select

from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.repositories.evidence_repo import EvidenceRepository
from app.infrastructure.database.repositories.scan_artifact_repo import (
    ARTIFACT_TYPE_SCANNER_REPORTS,
    ScanArtifactRepository,
)
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.database.repositories.scan_attempt_repo import (
    ScanAttemptRepository,
)
from app.infrastructure.evidence.object_store import (
    EvidenceIntegrityError,
    EvidenceObjectStore,
)
from app.infrastructure.messaging.evidence_retention_sweeper import (
    _process_deletions,
)
from tests.integration.support import integration_test


@integration_test
class ScanAttemptEvidenceStoreTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        async with AsyncSessionLocal() as db:
            user = db_models.User(
                email=f"attempt-evidence-{uuid4()}@example.invalid",
                hashed_password="not-a-real-password",
                is_active=True,
                is_superuser=True,
                is_verified=True,
            )
            db.add(user)
            await db.flush()
            project = db_models.Project(
                user_id=user.id, name=f"attempt-evidence-{uuid4()}"
            )
            scan = db_models.Scan(
                project=project,
                user_id=user.id,
                scan_type="AUDIT",
                status="FAILED",
                frameworks=["owasp-top-10"],
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
            self.initial_attempt_id = attempt.id
            self.evidence_ids: list = []

    async def asyncTearDown(self) -> None:
        # The tests process every object deletion before removing tombstone rows.
        async with AsyncSessionLocal() as db:
            evidence = list(
                (
                    await db.scalars(
                        select(db_models.EvidenceObject).where(
                            db_models.EvidenceObject.id.in_(self.evidence_ids)
                        )
                    )
                ).all()
            )
            repo = EvidenceRepository(db)
            for row in evidence:
                if row.legal_hold:
                    row.legal_hold = False
                if row.state == "available":
                    await repo.schedule_deletion(
                        row,
                        actor_user_id=self.user_id,
                        reason="integration_cleanup",
                        commit=False,
                    )
            await db.commit()
        await _process_deletions()
        try:
            async with AsyncSessionLocal() as db:
                await ScanRepository(db).delete_project(self.project_id)
                await db.execute(
                    delete(db_models.EvidenceGovernanceEvent).where(
                        db_models.EvidenceGovernanceEvent.evidence_id.in_(
                            self.evidence_ids
                        )
                    )
                )
                await db.execute(
                    delete(db_models.EvidenceManifest).where(
                        db_models.EvidenceManifest.scan_id.is_(None)
                    )
                )
                await db.execute(
                    delete(db_models.EvidenceObject).where(
                        db_models.EvidenceObject.id.in_(self.evidence_ids)
                    )
                )
                await db.execute(
                    delete(db_models.User).where(db_models.User.id == self.user_id)
                )
                await db.commit()
        finally:
            await engine.dispose()

    async def test_resume_reuses_attempt_and_restart_creates_a_new_identity(
        self,
    ) -> None:
        async with AsyncSessionLocal() as db:
            attempts = ScanAttemptRepository(db)
            resumed = await attempts.activate_resume(self.scan_id)
            self.assertEqual(resumed.id, self.initial_attempt_id)
            restarted = await attempts.create_restart(
                self.scan_id, actor_user_id=self.user_id
            )
            self.assertNotEqual(restarted.id, self.initial_attempt_id)
            self.assertEqual(restarted.sequence, 2)
            self.assertEqual(restarted.parent_attempt_id, self.initial_attempt_id)
            prior = await db.get(db_models.ScanAttempt, self.initial_attempt_id)
            scan = await db.get(db_models.Scan, self.scan_id)
            self.assertEqual(prior.status, "superseded")
            self.assertEqual(scan.current_attempt_id, restarted.id)

    async def test_encrypted_generations_chain_manifests_and_verify_digests(
        self,
    ) -> None:
        first_payload = {"schema_version": 1, "reports": {"semgrep": {"results": []}}}
        second_payload = {"schema_version": 1, "reports": {"semgrep": {"results": [1]}}}
        async with AsyncSessionLocal() as db:
            artifacts = ScanArtifactRepository(db)
            first = await artifacts.create_next_version(
                scan_id=self.scan_id,
                artifact_type=ARTIFACT_TYPE_SCANNER_REPORTS,
                payload=first_payload,
            )
            second = await artifacts.create_next_version(
                scan_id=self.scan_id,
                artifact_type=ARTIFACT_TYPE_SCANNER_REPORTS,
                payload=second_payload,
            )
            retried = await artifacts.upsert(
                scan_id=self.scan_id,
                artifact_type=ARTIFACT_TYPE_SCANNER_REPORTS,
                version=2,
                payload=second_payload,
            )
            self.evidence_ids.extend([first.evidence_id, second.evidence_id])
            self.assertIsNotNone(first.evidence_id)
            self.assertIsNotNone(second.evidence_id)
            self.assertEqual(retried.id, second.id)
            self.assertEqual(await artifacts.resolve_payload(second), second_payload)

            manifests = list(
                (
                    await db.scalars(
                        select(db_models.EvidenceManifest)
                        .where(
                            db_models.EvidenceManifest.attempt_id
                            == self.initial_attempt_id
                        )
                        .order_by(db_models.EvidenceManifest.generation)
                    )
                ).all()
            )
            self.assertEqual([row.generation for row in manifests], [1, 2])
            self.assertEqual(
                manifests[1].previous_manifest_sha256,
                manifests[0].manifest_sha256,
            )
            self.assertEqual(len(manifests[1].entries), 2)

            finalized = await EvidenceRepository(db).finalize_attempt(
                self.initial_attempt_id,
                actor_user_id=self.user_id,
            )
            self.assertTrue(finalized.finalized)
            self.assertEqual(finalized.generation, 3)
            self.assertEqual(
                finalized.previous_manifest_sha256, manifests[1].manifest_sha256
            )

            evidence = await db.get(db_models.EvidenceObject, second.evidence_id)
            request = {
                "Bucket": EvidenceObjectStore().bucket,
                "Key": evidence.object_key,
                "VersionId": evidence.object_version,
            }
            raw = EvidenceObjectStore().client.get_object(**request)["Body"].read()
            self.assertNotIn(b'"reports"', raw)
            original_digest = evidence.plaintext_sha256
            evidence.plaintext_sha256 = "0" * 64
            with self.assertRaises(EvidenceIntegrityError):
                await EvidenceRepository(db).read_json(evidence, audit=False)
            evidence.plaintext_sha256 = original_digest
            await db.rollback()

    async def test_legal_hold_blocks_then_audits_exact_version_deletion(self) -> None:
        async with AsyncSessionLocal() as db:
            artifact = await ScanArtifactRepository(db).create_next_version(
                scan_id=self.scan_id,
                artifact_type=ARTIFACT_TYPE_SCANNER_REPORTS,
                payload={"schema_version": 1, "reports": {}},
            )
            self.evidence_ids.append(artifact.evidence_id)
            repo = EvidenceRepository(db)
            evidence = await repo.set_legal_hold(
                artifact.evidence_id,
                enabled=True,
                actor_user_id=self.user_id,
                reason="integration legal hold",
            )
            with self.assertRaises(PermissionError):
                await repo.schedule_deletion(
                    evidence,
                    actor_user_id=self.user_id,
                    reason="must fail",
                )
            evidence = await repo.set_legal_hold(
                artifact.evidence_id,
                enabled=False,
                actor_user_id=self.user_id,
                reason="integration release",
            )
            await repo.schedule_deletion(
                evidence,
                actor_user_id=self.user_id,
                reason="integration deletion",
            )

        self.assertEqual(await _process_deletions(), 1)
        async with AsyncSessionLocal() as db:
            evidence = await db.get(db_models.EvidenceObject, artifact.evidence_id)
            self.assertEqual(evidence.state, "deleted")
            self.assertEqual(evidence.wrapped_data_key, b"")
            actions = list(
                await db.scalars(
                    select(db_models.EvidenceGovernanceEvent.action).where(
                        db_models.EvidenceGovernanceEvent.evidence_id
                        == artifact.evidence_id
                    )
                )
            )
            self.assertIn("LEGAL_HOLD_PLACED", actions)
            self.assertIn("DELETION_REJECTED_LEGAL_HOLD", actions)
            self.assertIn("LEGAL_HOLD_RELEASED", actions)
            self.assertIn("EVIDENCE_DELETED", actions)


if __name__ == "__main__":
    unittest.main()
