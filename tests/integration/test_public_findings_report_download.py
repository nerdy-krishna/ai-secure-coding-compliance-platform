"""Public HTTP integration contract for generated findings reports."""

from __future__ import annotations

import csv
import io
import json
import os
import unittest
from datetime import datetime, timezone
from uuid import uuid4

import httpx
from fastapi_users.password import PasswordHelper
from sqlalchemy import delete

from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.models import (
    Finding,
    Project,
    RoleAssignment,
    Scan,
    User,
)
from app.infrastructure.database.repositories.scan_artifact_repo import (
    ARTIFACT_TYPE_SCANNER_REPORTS,
    ScanArtifactRepository,
)
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.shared.lib.scan_status import STATUS_COMPLETED
from app.shared.lib.permissions import ANALYST
from tests.integration.support import integration_test


@integration_test
class PublicFindingsReportDownloadIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.base_url = os.getenv(
            "SCCAP_INTEGRATION_BASE_URL", "http://127.0.0.1:8000"
        ).rstrip("/")
        self.email = f"integration-findings-report-{uuid4()}@example.com"
        self.password = f"A7!{uuid4()}z"
        self.finding_title = "Unsanitized query <integration>"

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

            project = Project(
                user_id=user.id,
                name=f"integration-findings-report-{uuid4()}",
            )
            scan = Scan(
                project=project,
                user_id=user.id,
                scan_type="AUDIT",
                status=STATUS_COMPLETED,
                frameworks=["OWASP ASVS"],
                repository_map={
                    "files": {"src/example.py": {"errors": [], "language": "python"}}
                },
                summary={
                    "summary": {
                        "total_findings_count": 1,
                        "files_analyzed_count": 1,
                        "severity_counts": {"HIGH": 1},
                    },
                    "overall_risk_score": {"score": 8.8, "severity": "High"},
                },
                completed_at=datetime.now(timezone.utc),
                source_type="upload",
            )
            db.add_all([project, scan])
            await db.flush()
            db.add(
                Finding(
                    scan_id=scan.id,
                    file_path="src/example.py",
                    line_number=7,
                    vulnerable_snippet='cursor.execute("SELECT " + user_input)',
                    title=self.finding_title,
                    description="User-controlled input reaches a SQL query.",
                    severity="High",
                    remediation="Use a parameterized query.",
                    cwe="CWE-89",
                    confidence="High",
                    source="semgrep",
                    cvss_score=8.8,
                    references=["https://cwe.mitre.org/data/definitions/89.html"],
                    finding_bucket="consolidated",
                )
            )
            await db.commit()

            await ScanArtifactRepository(db).create_next_version(
                scan_id=scan.id,
                artifact_type=ARTIFACT_TYPE_SCANNER_REPORTS,
                payload={
                    "schema_version": 1,
                    "toolchain_provenance": {
                        "semgrep": {
                            "status": "verified",
                            "immutable": True,
                            "reasons": [],
                            "binary": {
                                "version": "1.95.0",
                                "sha256": "a" * 64,
                            },
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
                },
            )

            self.user_id = user.id
            self.project_id = project.id
            self.scan_id = scan.id

        self.client = httpx.AsyncClient(base_url=self.base_url, timeout=30.0)

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

    async def test_each_supported_findings_report_is_downloadable(self) -> None:
        login = await self.client.post(
            "/api/v1/auth/login",
            data={"username": self.email, "password": self.password},
        )
        self.assertEqual(login.status_code, 200, login.text)
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

        responses = {}
        for report_format in ("html", "csv", "pdf", "sarif"):
            response = await self.client.get(
                f"/api/v1/scans/{self.scan_id}/report",
                params={"format": report_format},
                headers=headers,
            )
            self.assertEqual(response.status_code, 200, response.text)
            self.assertIn(
                f"scan-{self.scan_id}-report.{report_format}",
                response.headers["content-disposition"],
            )
            responses[report_format] = response

        self.assertIn("Unsanitized query &lt;integration&gt;", responses["html"].text)
        self.assertIn("Deterministic scanner provenance", responses["html"].text)
        self.assertIn("1.95.0", responses["html"].text)
        csv_rows = list(csv.DictReader(io.StringIO(responses["csv"].text)))
        self.assertEqual(len(csv_rows), 1)
        self.assertEqual(csv_rows[0]["title"], self.finding_title)
        self.assertEqual(csv_rows[0]["scanner_version"], "1.95.0")
        self.assertEqual(csv_rows[0]["scanner_provenance_status"], "verified")
        self.assertTrue(responses["pdf"].content.startswith(b"%PDF-"))
        sarif = json.loads(responses["sarif"].content)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(
            sarif["runs"][0]["properties"]["sccapToolchainProvenance"]["semgrep"][
                "binary"
            ]["version"],
            "1.95.0",
        )
        self.assertEqual(
            sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
                "region"
            ]["startLine"],
            7,
        )


if __name__ == "__main__":
    unittest.main()
