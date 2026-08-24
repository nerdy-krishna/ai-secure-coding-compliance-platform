"""Live distinct-actor finding-waiver workflow contract."""

from __future__ import annotations

import os
import unittest
from uuid import uuid4

import httpx
from fastapi_users.password import PasswordHelper
from sqlalchemy import delete

from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.models import (
    AuthorizationActionRequest,
    Finding,
    Project,
    RoleAssignment,
    Scan,
    Tenant,
    User,
)
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.shared.lib.permissions import ANALYST, SECURITY_APPROVER
from app.shared.lib.scan_status import STATUS_COMPLETED
from tests.integration.support import integration_test


@integration_test
class FindingWaiverWorkflowIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        suffix = uuid4().hex[:12]
        self.password = f"W8!{uuid4()}n"
        self.base_url = os.getenv(
            "SCCAP_INTEGRATION_BASE_URL", "http://127.0.0.1:8000"
        ).rstrip("/")
        async with AsyncSessionLocal() as db:
            tenant = Tenant(
                slug=f"waiver-{suffix}",
                display_name="Waiver Tenant",
                separation_of_duties_mode="critical",
            )
            db.add(tenant)
            await db.flush()
            requester = User(
                email=f"waiver-requester-{suffix}@example.com",
                hashed_password=PasswordHelper().hash(self.password),
                is_active=True,
                is_superuser=False,
                is_verified=True,
                tenant_id=tenant.id,
            )
            approver = User(
                email=f"waiver-approver-{suffix}@example.com",
                hashed_password=PasswordHelper().hash(self.password),
                is_active=True,
                is_superuser=False,
                is_verified=True,
                tenant_id=tenant.id,
            )
            db.add_all([requester, approver])
            await db.flush()
            db.add_all(
                [
                    RoleAssignment(
                        user_id=requester.id,
                        tenant_id=tenant.id,
                        role_key=ANALYST,
                    ),
                    RoleAssignment(
                        user_id=approver.id,
                        tenant_id=tenant.id,
                        role_key=SECURITY_APPROVER,
                    ),
                ]
            )
            project = Project(
                user_id=requester.id,
                tenant_id=tenant.id,
                name=f"waiver-project-{suffix}",
            )
            scan = Scan(
                project=project,
                user_id=requester.id,
                tenant_id=tenant.id,
                scan_type="AUDIT",
                status=STATUS_COMPLETED,
                frameworks=[],
                summary={},
            )
            finding = Finding(
                scan=scan,
                tenant_id=tenant.id,
                file_path="src/example.py",
                title="Waiver candidate",
                severity="High",
                finding_bucket="consolidated",
            )
            db.add_all([project, scan, finding])
            await db.commit()
            self.tenant_id = tenant.id
            self.user_ids = [requester.id, approver.id]
            self.requester_email = requester.email
            self.approver_email = approver.email
            self.project_id = project.id
            self.scan_id = scan.id
            self.finding_id = finding.id
        self.client = httpx.AsyncClient(base_url=self.base_url, timeout=15.0)

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        async with AsyncSessionLocal() as db:
            await db.execute(
                delete(AuthorizationActionRequest).where(
                    AuthorizationActionRequest.tenant_id == self.tenant_id
                )
            )
            await db.execute(
                delete(RoleAssignment).where(RoleAssignment.user_id.in_(self.user_ids))
            )
            await ScanRepository(db).delete_project(self.project_id)
            await db.execute(delete(User).where(User.id.in_(self.user_ids)))
            await db.execute(delete(Tenant).where(Tenant.id == self.tenant_id))
            await db.commit()
        await engine.dispose()

    async def _headers(self, email: str) -> dict[str, str]:
        response = await self.client.post(
            "/api/v1/auth/login",
            data={"username": email, "password": self.password},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    async def test_critical_waiver_requires_exact_distinct_approval(self) -> None:
        disposition_url = (
            f"/api/v1/scans/{self.scan_id}/findings/{self.finding_id}/disposition"
        )
        waiver_url = (
            f"/api/v1/scans/{self.scan_id}/findings/{self.finding_id}"
            "/waiver-requests"
        )
        body = {
            "disposition": "risk_accepted",
            "note": "Compensating control is active.",
        }
        requester = await self._headers(self.requester_email)
        approver = await self._headers(self.approver_email)

        direct = await self.client.patch(disposition_url, headers=requester, json=body)
        self.assertEqual(direct.status_code, 409, direct.text)
        requested = await self.client.post(
            waiver_url,
            headers={**requester, "X-Idempotency-Key": f"waiver-{uuid4()}"},
            json=body,
        )
        self.assertEqual(requested.status_code, 201, requested.text)
        request_id = requested.json()["id"]

        self_decision = await self.client.post(
            f"/api/v1/admin/authorization/actions/{request_id}/decision",
            headers=requester,
            json={"approved": True, "reason": "self"},
        )
        self.assertEqual(self_decision.status_code, 403, self_decision.text)
        approved = await self.client.post(
            f"/api/v1/admin/authorization/actions/{request_id}/decision",
            headers=approver,
            json={"approved": True, "reason": "control evidence reviewed"},
        )
        self.assertEqual(approved.status_code, 200, approved.text)

        execute_url = f"{waiver_url}/{request_id}/execute"
        changed_payload = await self.client.post(
            execute_url,
            headers=requester,
            json={**body, "note": "Different note"},
        )
        self.assertEqual(changed_payload.status_code, 409, changed_payload.text)
        executed = await self.client.post(execute_url, headers=requester, json=body)
        self.assertEqual(executed.status_code, 200, executed.text)
        self.assertEqual(executed.json()["disposition"], "risk_accepted")


if __name__ == "__main__":
    unittest.main()
