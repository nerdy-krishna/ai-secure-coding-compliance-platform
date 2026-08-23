"""Live authorization contract for the tenant findings audit surface."""

from __future__ import annotations

import os
import unittest
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
    Tenant,
    User,
)
from app.shared.lib.permissions import ANALYST, AUDITOR
from tests.integration.support import integration_test


@integration_test
class AdminFindingsAuthorizationIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        suffix = uuid4().hex[:12]
        self.password = f"A7!{uuid4()}z"
        self.base_url = os.getenv(
            "SCCAP_INTEGRATION_BASE_URL", "http://127.0.0.1:8000"
        ).rstrip("/")
        async with AsyncSessionLocal() as db:
            tenants = [
                Tenant(slug=f"find-a-{suffix}", display_name="Finding Tenant A"),
                Tenant(slug=f"find-b-{suffix}", display_name="Finding Tenant B"),
            ]
            db.add_all(tenants)
            await db.flush()
            users = [
                User(
                    email=f"finding-{kind}-{suffix}@example.com",
                    hashed_password=PasswordHelper().hash(self.password),
                    is_active=True,
                    is_superuser=False,
                    is_verified=True,
                    tenant_id=tenants[tenant_index].id,
                )
                for kind, tenant_index in (("auditor", 0), ("analyst", 0), ("foreign", 1))
            ]
            db.add_all(users)
            await db.flush()
            db.add_all(
                [
                    RoleAssignment(
                        user_id=users[0].id,
                        tenant_id=tenants[0].id,
                        role_key=AUDITOR,
                    ),
                    RoleAssignment(
                        user_id=users[1].id,
                        tenant_id=tenants[0].id,
                        role_key=ANALYST,
                    ),
                    RoleAssignment(
                        user_id=users[2].id,
                        tenant_id=tenants[1].id,
                        role_key=ANALYST,
                    ),
                ]
            )
            projects = [
                Project(
                    name=f"project-{index}-{suffix}",
                    user_id=users[user_index].id,
                    tenant_id=tenants[index].id,
                )
                for index, user_index in ((0, 0), (1, 2))
            ]
            db.add_all(projects)
            await db.flush()
            scans = [
                Scan(
                    project_id=projects[index].id,
                    user_id=users[user_index].id,
                    tenant_id=tenants[index].id,
                    scan_type="AUDIT",
                    status="COMPLETED",
                )
                for index, user_index in ((0, 0), (1, 2))
            ]
            db.add_all(scans)
            await db.flush()
            findings = [
                Finding(
                    scan_id=scans[index].id,
                    tenant_id=tenants[index].id,
                    file_path=f"tenant-{label}.py",
                    title=f"Tenant {label} private finding",
                    description="private",
                    remediation="private",
                    severity="High",
                    confidence="High",
                    finding_bucket="consolidated",
                    source="bandit",
                )
                for index, label in ((0, "a"), (1, "b"))
            ]
            db.add_all(findings)
            await db.commit()
            self.tenant_ids = [tenant.id for tenant in tenants]
            self.user_ids = [user.id for user in users]
            self.project_ids = [project.id for project in projects]
            self.scan_ids = [scan.id for scan in scans]
            self.finding_ids = [finding.id for finding in findings]
            self.emails = [user.email for user in users]
        self.client = httpx.AsyncClient(base_url=self.base_url, timeout=15.0)

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        async with AsyncSessionLocal() as db:
            await db.execute(delete(Finding).where(Finding.id.in_(self.finding_ids)))
            await db.execute(delete(Scan).where(Scan.id.in_(self.scan_ids)))
            await db.execute(delete(Project).where(Project.id.in_(self.project_ids)))
            await db.execute(
                delete(RoleAssignment).where(RoleAssignment.user_id.in_(self.user_ids))
            )
            await db.execute(delete(User).where(User.id.in_(self.user_ids)))
            await db.execute(delete(Tenant).where(Tenant.id.in_(self.tenant_ids)))
            await db.commit()
        await engine.dispose()

    async def _headers(self, user_index: int) -> dict[str, str]:
        response = await self.client.post(
            "/api/v1/auth/login",
            data={"username": self.emails[user_index], "password": self.password},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    async def test_audit_permission_is_tenant_scoped(self) -> None:
        denied = await self.client.get(
            "/api/v1/admin/findings", headers=await self._headers(1)
        )
        self.assertEqual(denied.status_code, 403, denied.text)

        response = await self.client.get(
            "/api/v1/admin/findings", headers=await self._headers(0)
        )
        self.assertEqual(response.status_code, 200, response.text)
        ids = {row["id"] for row in response.json()["items"]}
        self.assertIn(self.finding_ids[0], ids)
        self.assertNotIn(self.finding_ids[1], ids)
