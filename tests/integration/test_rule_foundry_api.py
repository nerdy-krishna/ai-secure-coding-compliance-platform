"""Authenticated tenant and permission contract for the Rule Foundry API."""

from __future__ import annotations

import os
import unittest
from uuid import uuid4

import httpx
from fastapi_users.password import PasswordHelper
from sqlalchemy import delete, text

from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.models import (
    Finding,
    Project,
    RoleAssignment,
    RuleFoundryCandidate,
    RuleFoundryEvent,
    Scan,
    Tenant,
    User,
)
from app.infrastructure.database.tenant_context import bind_principal, reset_principal
from app.shared.lib.permissions import AUDITOR, DEVELOPER
from tests.integration.support import integration_test


@integration_test
class RuleFoundryApiIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        suffix = uuid4().hex[:12]
        self.password = f"G7!{uuid4()}x"
        self.base_url = os.getenv(
            "SCCAP_INTEGRATION_BASE_URL", "http://127.0.0.1:8000"
        ).rstrip("/")
        async with AsyncSessionLocal() as db:
            tenant_a = Tenant(slug=f"foundry-a-{suffix}", display_name="Foundry A")
            tenant_b = Tenant(slug=f"foundry-b-{suffix}", display_name="Foundry B")
            db.add_all([tenant_a, tenant_b])
            await db.flush()
            creator = User(
                email=f"foundry-creator-{suffix}@example.com",
                hashed_password=PasswordHelper().hash(self.password),
                is_active=True,
                is_superuser=False,
                is_verified=True,
                tenant_id=tenant_a.id,
            )
            auditor = User(
                email=f"foundry-auditor-{suffix}@example.com",
                hashed_password=PasswordHelper().hash(self.password),
                is_active=True,
                is_superuser=False,
                is_verified=True,
                tenant_id=tenant_a.id,
            )
            foreign_auditor = User(
                email=f"foundry-foreign-{suffix}@example.com",
                hashed_password=PasswordHelper().hash(self.password),
                is_active=True,
                is_superuser=False,
                is_verified=True,
                tenant_id=tenant_b.id,
            )
            unassigned = User(
                email=f"foundry-none-{suffix}@example.com",
                hashed_password=PasswordHelper().hash(self.password),
                is_active=True,
                is_superuser=False,
                is_verified=True,
                tenant_id=tenant_a.id,
            )
            db.add_all([creator, auditor, foreign_auditor, unassigned])
            await db.flush()
            db.add_all(
                [
                    RoleAssignment(user_id=creator.id, tenant_id=tenant_a.id, role_key=DEVELOPER),
                    RoleAssignment(user_id=auditor.id, tenant_id=tenant_a.id, role_key=AUDITOR),
                    RoleAssignment(
                        user_id=foreign_auditor.id,
                        tenant_id=tenant_b.id,
                        role_key=AUDITOR,
                    ),
                ]
            )
            project = Project(
                user_id=creator.id,
                tenant_id=tenant_a.id,
                name=f"foundry-{suffix}",
            )
            db.add(project)
            await db.flush()
            scan = Scan(
                project_id=project.id,
                user_id=creator.id,
                tenant_id=tenant_a.id,
                scan_type="audit",
                status="COMPLETED",
            )
            db.add(scan)
            await db.flush()
            finding = Finding(
                scan_id=scan.id,
                tenant_id=tenant_a.id,
                file_path="src/auth.py",
                line_number=10,
                title="Runtime-only authorization invariant",
                description="Requires request identity and external policy state.",
                severity="High",
                cwe="CWE-862",
                source="agent",
                disposition="confirmed",
                finding_bucket="consolidated",
            )
            db.add(finding)
            await db.commit()
            self.tenant_ids = [tenant_a.id, tenant_b.id]
            self.user_ids = [creator.id, auditor.id, foreign_auditor.id, unassigned.id]
            self.project_id = project.id
            self.scan_id = scan.id
            self.finding_id = finding.id
            self.users = {
                "creator": creator.email,
                "auditor": auditor.email,
                "foreign": foreign_auditor.email,
                "none": unassigned.email,
            }
        self.client = httpx.AsyncClient(base_url=self.base_url, timeout=15.0)

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        binding = bind_principal(
            tenant_id=None,
            principal_kind="system",
            principal_id="rule-foundry-test-cleanup",
            system_scope=True,
        )
        try:
            async with AsyncSessionLocal() as db:
                await db.execute(
                    text(
                        "ALTER TABLE rule_foundry_events DISABLE TRIGGER "
                        "sccap_rule_foundry_immutable"
                    )
                )
                await db.execute(
                    delete(RuleFoundryEvent).where(
                        RuleFoundryEvent.tenant_id.in_(self.tenant_ids)
                    )
                )
                await db.execute(
                    delete(RuleFoundryCandidate).where(
                        RuleFoundryCandidate.tenant_id.in_(self.tenant_ids)
                    )
                )
                await db.execute(delete(Finding).where(Finding.id == self.finding_id))
                await db.execute(delete(Scan).where(Scan.id == self.scan_id))
                await db.execute(delete(Project).where(Project.id == self.project_id))
                await db.execute(
                    delete(RoleAssignment).where(
                        RoleAssignment.user_id.in_(self.user_ids)
                    )
                )
                await db.execute(delete(User).where(User.id.in_(self.user_ids)))
                await db.execute(delete(Tenant).where(Tenant.id.in_(self.tenant_ids)))
                await db.execute(
                    text(
                        "ALTER TABLE rule_foundry_events ENABLE TRIGGER "
                        "sccap_rule_foundry_immutable"
                    )
                )
                await db.commit()
        finally:
            reset_principal(binding)
        await engine.dispose()

    async def _headers(self, label: str) -> dict[str, str]:
        response = await self.client.post(
            "/api/v1/auth/login",
            data={"username": self.users[label], "password": self.password},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    async def test_nonrepresentable_candidate_is_tenant_scoped_and_not_promotable(self) -> None:
        created = await self.client.post(
            "/api/v1/admin/rule-sources/foundry/candidates",
            headers=await self._headers("creator"),
            json={
                "finding_id": self.finding_id,
                "predicate_kind": "semantic_runtime",
                "bounded": False,
                "uses_project_specific_names": False,
                "requires_hidden_runtime_state": True,
            },
        )
        self.assertEqual(created.status_code, 201, created.text)
        body = created.json()
        self.assertEqual(body["registry_kind"], "ai_dataflow")
        self.assertEqual(body["status"], "ai_dataflow")
        self.assertTrue(body["non_representable_reason"])

        visible = await self.client.get(
            "/api/v1/admin/rule-sources/foundry/candidates",
            headers=await self._headers("auditor"),
        )
        self.assertEqual(visible.status_code, 200, visible.text)
        self.assertIn(body["id"], {item["id"] for item in visible.json()["items"]})

        foreign = await self.client.get(
            f"/api/v1/admin/rule-sources/foundry/candidates/{body['id']}",
            headers=await self._headers("foreign"),
        )
        self.assertEqual(foreign.status_code, 404, foreign.text)

        forbidden = await self.client.get(
            "/api/v1/admin/rule-sources/foundry/candidates",
            headers=await self._headers("none"),
        )
        self.assertEqual(forbidden.status_code, 403, forbidden.text)


if __name__ == "__main__":
    unittest.main()
