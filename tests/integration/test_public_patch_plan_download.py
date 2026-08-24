"""Public HTTP contract for the persisted deterministic patch plan."""

from __future__ import annotations

import os
import unittest
from uuid import uuid4

import httpx
from fastapi_users.password import PasswordHelper
from sqlalchemy import delete

from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.models import Project, RoleAssignment, Scan, User
from app.infrastructure.database.repositories.scan_artifact_repo import (
    ARTIFACT_TYPE_PATCH_PLAN,
    ScanArtifactRepository,
)
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.shared.lib.scan_status import STATUS_COMPLETED
from app.shared.lib.permissions import ANALYST
from tests.integration.support import integration_test


@integration_test
class PublicPatchPlanDownloadIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.base_url = os.getenv(
            "SCCAP_INTEGRATION_BASE_URL", "http://127.0.0.1:8000"
        ).rstrip("/")
        self.email = f"integration-patch-plan-{uuid4()}@example.com"
        self.password = f"A7!{uuid4()}z"
        async with AsyncSessionLocal() as db:
            user = User(
                email=self.email,
                hashed_password=PasswordHelper().hash(self.password),
                is_active=True,
                is_superuser=False,
                is_verified=True,
            )
            db.add(user)
            await db.flush()
            db.add(
                RoleAssignment(
                    user_id=user.id,
                    tenant_id=user.tenant_id,
                    role_key=ANALYST,
                )
            )
            project = Project(user_id=user.id, name=f"patch-plan-{uuid4()}")
            scan = Scan(
                project=project,
                user_id=user.id,
                scan_type="SUGGEST",
                status=STATUS_COMPLETED,
                frameworks=[],
                summary={},
            )
            db.add_all([project, scan])
            await db.commit()
            self.payload = {
                "schema_version": 2,
                "scan_id": str(scan.id),
                "files": [
                    {
                        "file_path": "src/app.py",
                        "source_snapshot_hash": "a" * 64,
                        "output_hash": "b" * 64,
                        "status": "planned",
                        "hunks": [
                            {
                                "patch_hunk_id": str(uuid4()),
                                "candidate_ids": [str(uuid4())],
                                "resolved_range": {
                                    "start_byte": 0,
                                    "end_byte": 5,
                                    "start_line": 1,
                                    "start_column": 1,
                                    "end_line": 1,
                                    "end_column": 6,
                                },
                                "context_fingerprint": "c" * 64,
                                "original_text": "bad()",
                                "replacement_text": "safe()",
                            }
                        ],
                        "conflict_components": [],
                        "requirements": [
                            {
                                "candidate_id": str(uuid4()),
                                "required_imports": ["from secure import safe"],
                                "required_dependencies": ["secure-lib==1.0"],
                                "configuration_changes": [],
                                "migration_changes": [],
                                "required_commands": ["pytest -q"],
                                "manual_steps": ["Rotate the legacy credential."],
                            }
                        ],
                        "validation_checks": [
                            {
                                "stage": "python_compile",
                                "profile": "python_compile",
                                "status": "passed",
                                "blocking": True,
                                "tool": "python",
                                "tool_version": "Python 3.13.7",
                                "completed_at": "2026-08-24T12:00:00Z",
                                "detail": "Compiled successfully.",
                            }
                        ],
                        "unified_diff": "--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n-bad()\n+safe()\n",
                    }
                ],
                "candidate_decisions": [],
            }
            await ScanArtifactRepository(db).upsert(
                scan_id=scan.id,
                artifact_type=ARTIFACT_TYPE_PATCH_PLAN,
                version=1,
                payload=self.payload,
            )
            self.user_id = user.id
            self.project_id = project.id
            self.scan_id = scan.id
        self.client = httpx.AsyncClient(base_url=self.base_url, timeout=15.0)

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        async with AsyncSessionLocal() as db:
            await ScanRepository(db).delete_project(self.project_id)
            await db.execute(
                delete(RoleAssignment).where(RoleAssignment.user_id == self.user_id)
            )
            await db.execute(delete(User).where(User.id == self.user_id))
            await db.commit()
        await engine.dispose()

    async def test_owner_can_download_exact_patch_plan_artifact(self) -> None:
        login = await self.client.post(
            "/api/v1/auth/login",
            data={"username": self.email, "password": self.password},
        )
        self.assertEqual(login.status_code, 200, login.text)
        response = await self.client.get(
            f"/api/v1/scans/{self.scan_id}/patch-plan",
            headers={"Authorization": f"Bearer {login.json()['access_token']}"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), self.payload)
        self.assertEqual(
            response.headers["content-disposition"],
            f'attachment; filename="scan-{self.scan_id}-patch-plan.json"',
        )

        patch = await self.client.get(
            f"/api/v1/scans/{self.scan_id}/patch-plan?format=patch",
            headers={"Authorization": f"Bearer {login.json()['access_token']}"},
        )
        self.assertEqual(patch.status_code, 200, patch.text)
        self.assertIn("Required command: pytest -q", patch.text)
        self.assertIn("Manual step: Rotate the legacy credential.", patch.text)
        self.assertIn("@@ -1 +1 @@", patch.text)
        self.assertEqual(patch.headers["content-type"], "text/x-diff; charset=utf-8")


if __name__ == "__main__":
    unittest.main()
