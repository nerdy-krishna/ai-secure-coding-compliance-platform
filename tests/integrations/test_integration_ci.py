from __future__ import annotations

import unittest
import uuid
from datetime import datetime, timezone
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import AsyncMock

from fastapi import HTTPException, UploadFile

from app.api.v1.routers.integration_ci import persisted_ci_policy, submit_ci_archive


class IntegrationCiTests(unittest.IsolatedAsyncioTestCase):
    async def test_submission_binds_full_commit_and_persists_provenance(self) -> None:
        tenant_id = uuid.uuid4()
        scan = SimpleNamespace(id=uuid.uuid4(), project_id=uuid.uuid4())
        db = SimpleNamespace(commit=AsyncMock())
        service = SimpleNamespace(
            repo=SimpleNamespace(db=db),
            create_scan_from_archive=AsyncMock(return_value=scan),
        )
        user = SimpleNamespace(id=17, tenant_id=tenant_id)
        reasoning_id = uuid.uuid4()

        result = await submit_ci_archive(
            provider="github",
            commit_sha="a" * 40,
            ref="refs/heads/main",
            repository_slug="acme/repo",
            trusted_context=True,
            project_name="repo",
            frameworks="owasp-top-10",
            archive_file=UploadFile(filename="source.zip", file=BytesIO(b"zip")),
            scan_type="AUDIT",
            reasoning_llm_config_id=reasoning_id,
            utility_llm_config_id=reasoning_id,
            tenant_id=tenant_id,
            user=user,
            service=service,
            llm_repo=SimpleNamespace(),
        )

        self.assertEqual(result.scan_id, scan.id)
        self.assertEqual(result.commit_sha, "a" * 40)
        provenance = service.create_scan_from_archive.await_args.kwargs[
            "source_provenance"
        ]
        self.assertEqual(provenance.tenant_id, tenant_id)
        self.assertEqual(provenance.commit_sha, "a" * 40)
        self.assertTrue(provenance.trusted_context)

    async def test_untrusted_submission_is_rejected_before_secret_backed_work(
        self,
    ) -> None:
        service = SimpleNamespace(create_scan_from_archive=AsyncMock())
        with self.assertRaises(HTTPException) as raised:
            await submit_ci_archive(
                provider="github",
                commit_sha="a" * 40,
                ref="refs/heads/main",
                repository_slug="acme/repo",
                trusted_context=False,
                project_name="repo",
                frameworks="owasp-top-10",
                archive_file=UploadFile(filename="source.zip", file=BytesIO(b"zip")),
                scan_type="AUDIT",
                reasoning_llm_config_id=uuid.uuid4(),
                utility_llm_config_id=uuid.uuid4(),
                tenant_id=uuid.uuid4(),
                user=SimpleNamespace(id=17),
                service=service,
                llm_repo=SimpleNamespace(),
            )
        self.assertEqual(raised.exception.status_code, 403)
        service.create_scan_from_archive.assert_not_awaited()

    async def test_policy_returns_only_current_attempt_persisted_outcome(self) -> None:
        tenant_id = uuid.uuid4()
        scan_id = uuid.uuid4()
        attempt_id = uuid.uuid4()
        evaluation = SimpleNamespace(
            id=uuid.uuid4(),
            policy_version_id=uuid.uuid4(),
            outcome="fail",
            coverage_complete=True,
            created_at=datetime.now(timezone.utc),
        )
        db = SimpleNamespace(scalar=AsyncMock(return_value=evaluation))
        service = SimpleNamespace(
            repo=SimpleNamespace(db=db),
            get_scan_status=AsyncMock(
                return_value=SimpleNamespace(
                    status="COMPLETED", current_attempt_id=attempt_id
                )
            ),
        )

        result = await persisted_ci_policy(
            scan_id=scan_id,
            tenant_id=tenant_id,
            user=SimpleNamespace(id=17),
            visible_user_ids=[17],
            service=service,
        )

        self.assertTrue(result.terminal)
        self.assertEqual(result.outcome, "fail")
        self.assertIn(str(scan_id), result.report_url or "")
        statement = str(db.scalar.await_args.args[0])
        self.assertIn("finding_policy_evaluations.attempt_id", statement)


if __name__ == "__main__":
    unittest.main()
