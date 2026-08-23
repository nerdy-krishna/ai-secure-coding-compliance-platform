"""Public HTTP integration contract for persisted native scanner reports."""

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
    ARTIFACT_TYPE_SCANNER_REPORTS,
    ScanArtifactRepository,
)
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.shared.lib.scan_status import STATUS_COMPLETED
from app.shared.lib.permissions import ANALYST
from tests.integration.support import integration_test


@integration_test
class PublicScannerReportDownloadIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.base_url = os.getenv(
            "SCCAP_INTEGRATION_BASE_URL", "http://127.0.0.1:8000"
        ).rstrip("/")
        self.email = f"integration-scanner-report-{uuid4()}@example.com"
        self.password = f"A7!{uuid4()}z"
        self.attacker_email = f"integration-scanner-report-denied-{uuid4()}@example.com"
        self.attacker_password = f"B8!{uuid4()}y"
        self.expected_payload = {
            "schema_version": 1,
            "reports": {
                "semgrep": {
                    "version": "integration-fixture",
                    "results": [
                        {
                            "check_id": "integration.python.sql-injection",
                            "path": "src/example.py",
                            "start": {"line": 7, "col": 1},
                        }
                    ],
                },
                "bandit": {"results": []},
                "gitleaks": [],
                "osv": {"results": []},
            },
            "scanner_statuses": {
                "semgrep": "completed",
                "bandit": "completed",
                "gitleaks": "completed",
                "osv": "completed",
            },
            "toolchain_provenance": {
                "semgrep": {
                    "status": "verified",
                    "immutable": True,
                    "binary": {"version": "1.95.0", "sha256": "a" * 64},
                    "rules": {
                        "status": "verified",
                        "selected_rule_count": 1,
                        "ruleset_sha256": "b" * 64,
                        "rules": [
                            {
                                "id": "integration.python.sql-injection",
                                "content_sha256": "c" * 64,
                            }
                        ],
                    },
                }
            },
        }

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

            attacker = User(
                email=self.attacker_email,
                hashed_password=PasswordHelper().hash(self.attacker_password),
                is_active=True,
                is_superuser=False,
                is_verified=True,
            )
            db.add(attacker)
            await db.flush()
            db.add_all(
                [
                    RoleAssignment(
                        user_id=user.id,
                        tenant_id=user.tenant_id,
                        role_key=ANALYST,
                    ),
                    RoleAssignment(
                        user_id=attacker.id,
                        tenant_id=attacker.tenant_id,
                        role_key=ANALYST,
                    ),
                ]
            )

            project = Project(
                user_id=user.id,
                name=f"integration-scanner-report-{uuid4()}",
            )
            scan = Scan(
                project=project,
                user_id=user.id,
                scan_type="AUDIT",
                status=STATUS_COMPLETED,
                frameworks=[],
                summary={},
            )
            db.add_all([project, scan])
            await db.commit()

            self.expected_payload["scan_id"] = str(scan.id)
            artifacts = ScanArtifactRepository(db)
            first = await artifacts.create_next_version(
                scan_id=scan.id,
                artifact_type=ARTIFACT_TYPE_SCANNER_REPORTS,
                payload={"schema_version": 1, "scan_id": str(scan.id), "reports": {}},
            )
            second = await artifacts.create_next_version(
                scan_id=scan.id,
                artifact_type=ARTIFACT_TYPE_SCANNER_REPORTS,
                payload=self.expected_payload,
            )
            self.assertEqual((first.version, second.version), (1, 2))
            self.assertEqual(
                (
                    await artifacts.get_by_type(
                        scan.id, ARTIFACT_TYPE_SCANNER_REPORTS, version=1
                    )
                ).payload,
                first.payload,
            )
            self.user_id = user.id
            self.attacker_user_id = attacker.id
            self.project_id = project.id
            self.scan_id = scan.id

        self.client = httpx.AsyncClient(base_url=self.base_url, timeout=15.0)

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        async with AsyncSessionLocal() as db:
            await ScanRepository(db).delete_project(self.project_id)
            await db.execute(
                delete(RoleAssignment).where(
                    RoleAssignment.user_id.in_(
                        [self.user_id, self.attacker_user_id]
                    )
                )
            )
            await db.execute(delete(User).where(User.id == self.user_id))
            await db.execute(delete(User).where(User.id == self.attacker_user_id))
            await db.commit()
        await engine.dispose()

    async def test_download_returns_the_persisted_native_scanner_bundle(self) -> None:
        login = await self.client.post(
            "/api/v1/auth/login",
            data={"username": self.email, "password": self.password},
        )
        self.assertEqual(login.status_code, 200, login.text)

        response = await self.client.get(
            f"/api/v1/scans/{self.scan_id}/scanner-reports",
            headers={"Authorization": f"Bearer {login.json()['access_token']}"},
        )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(
            response.headers["content-disposition"],
            f'attachment; filename="scan-{self.scan_id}-scanner-reports.json"',
        )
        self.assertEqual(response.json(), self.expected_payload)

        denied_login = await self.client.post(
            "/api/v1/auth/login",
            data={
                "username": self.attacker_email,
                "password": self.attacker_password,
            },
        )
        self.assertEqual(denied_login.status_code, 200, denied_login.text)
        denied = await self.client.get(
            f"/api/v1/scans/{self.scan_id}/scanner-reports",
            headers={"Authorization": f"Bearer {denied_login.json()['access_token']}"},
        )
        self.assertEqual(denied.status_code, 404, denied.text)

        result_response = await self.client.get(
            f"/api/v1/scans/{self.scan_id}/result",
            headers={"Authorization": f"Bearer {login.json()['access_token']}"},
        )
        self.assertEqual(result_response.status_code, 200, result_response.text)
        visible = result_response.json()["toolchain_provenance"]["semgrep"]
        self.assertEqual(visible["rules"]["selected_rule_count"], 1)
        self.assertNotIn("rules", visible["rules"])


if __name__ == "__main__":
    unittest.main()
