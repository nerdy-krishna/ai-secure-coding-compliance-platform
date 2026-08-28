"""Live step-up and explicit-target contracts for platform tenant entry."""

from __future__ import annotations

import os
import unittest
from uuid import uuid4

import httpx
from fastapi_users.password import PasswordHelper
from sqlalchemy import delete, select

from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.models import (
    AuthorizationAuditEvent,
    RoleAssignment,
    Tenant,
    User,
)
from app.shared.lib.permissions import ANALYST, PLATFORM_OWNER, TENANT_ADMIN
from tests.integration.support import integration_test


@integration_test
class PlatformTenantEntryIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        suffix = uuid4().hex[:12]
        self.password = f"P8!{uuid4()}m"
        self.base_url = os.getenv(
            "SCCAP_INTEGRATION_BASE_URL",
            "http://127.0.0.1:8000",
        ).rstrip("/")
        async with AsyncSessionLocal() as db:
            home = Tenant(slug=f"entry-home-{suffix}", display_name="Entry Home")
            target = Tenant(slug=f"entry-target-{suffix}", display_name="Entry Target")
            db.add_all([home, target])
            await db.flush()
            specs = [
                ("owner", home.id),
                ("admin", home.id),
                ("home-member", home.id),
                ("target-member", target.id),
                ("target-critical", target.id),
            ]
            users = [
                User(
                    email=f"{label}-{suffix}@example.com",
                    hashed_password=PasswordHelper().hash(self.password),
                    is_active=True,
                    is_superuser=(label == "owner"),
                    is_verified=True,
                    tenant_id=tenant_id,
                )
                for label, tenant_id in specs
            ]
            db.add_all(users)
            await db.flush()
            db.add_all(
                [
                    RoleAssignment(
                        user_id=users[0].id,
                        tenant_id=None,
                        role_key=PLATFORM_OWNER,
                    ),
                    RoleAssignment(
                        user_id=users[1].id,
                        tenant_id=home.id,
                        role_key=TENANT_ADMIN,
                    ),
                    *[
                        RoleAssignment(
                            user_id=user.id,
                            tenant_id=user.tenant_id,
                            role_key=ANALYST,
                        )
                        for user in users[2:]
                    ],
                ]
            )
            await db.commit()
            self.home_tenant_id = home.id
            self.target_tenant_id = target.id
            self.tenant_ids = [home.id, target.id]
            self.user_ids = [user.id for user in users]
            self.users = {
                label: (user.id, user.email)
                for user, (label, _tenant_id) in zip(users, specs)
            }
        self.client = httpx.AsyncClient(base_url=self.base_url, timeout=15.0)

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        async with AsyncSessionLocal() as db:
            await db.execute(
                delete(RoleAssignment).where(RoleAssignment.user_id.in_(self.user_ids))
            )
            await db.execute(delete(User).where(User.id.in_(self.user_ids)))
            await db.execute(delete(Tenant).where(Tenant.id.in_(self.tenant_ids)))
            await db.commit()
        await engine.dispose()

    async def _headers(self, label: str) -> dict[str, str]:
        _user_id, email = self.users[label]
        response = await self.client.post(
            "/api/v1/auth/login",
            data={"username": email, "password": self.password},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    async def test_browser_session_defaults_switches_and_survives_rotation(
        self,
    ) -> None:
        entry_endpoint = "/api/v1/admin/tenants/entry"
        _owner_id, owner_email = self.users["owner"]
        login = await self.client.post(
            "/api/v1/auth/login",
            data={"username": owner_email, "password": self.password},
        )
        self.assertEqual(login.status_code, 200, login.text)
        browser_headers = {
            "Origin": self.base_url,
            "X-CSRF-Token": login.headers["x-csrf-token"],
        }

        initial = await self.client.get(entry_endpoint)
        self.assertEqual(initial.status_code, 200, initial.text)
        self.assertEqual(
            initial.json()["tenant_id"],
            "00000000-0000-0000-0000-000000000001",
        )
        self.assertTrue(initial.json()["is_default"])

        issued = await self.client.post(
            entry_endpoint,
            headers=browser_headers,
            json={"tenant_id": str(self.target_tenant_id)},
        )
        self.assertEqual(issued.status_code, 200, issued.text)
        self.assertEqual(issued.json()["tenant_id"], str(self.target_tenant_id))
        self.assertNotIn("entry_token", issued.json())
        self.assertNotIn("expires_in", issued.json())

        selected = await self.client.get(entry_endpoint)
        self.assertEqual(selected.status_code, 200, selected.text)
        self.assertEqual(selected.json()["tenant_id"], str(self.target_tenant_id))
        target_users = await self.client.get("/api/v1/admin/users")
        self.assertEqual(target_users.status_code, 200, target_users.text)
        target_ids = {row["id"] for row in target_users.json()}
        self.assertIn(self.users["target-member"][0], target_ids)
        self.assertNotIn(self.users["home-member"][0], target_ids)

        refresh = await self.client.post(
            "/api/v1/auth/refresh",
            headers=browser_headers,
        )
        self.assertEqual(refresh.status_code, 200, refresh.text)
        after_rotation = await self.client.get(entry_endpoint)
        self.assertEqual(after_rotation.status_code, 200, after_rotation.text)
        self.assertEqual(after_rotation.json()["tenant_id"], str(self.target_tenant_id))

        cleared = await self.client.delete(entry_endpoint, headers=browser_headers)
        self.assertEqual(cleared.status_code, 204, cleared.text)
        after_clear = await self.client.get(entry_endpoint)
        self.assertEqual(after_clear.status_code, 200, after_clear.text)
        self.assertTrue(after_clear.json()["is_default"])

        async with AsyncSessionLocal() as db:
            audit_row = await db.scalar(
                select(AuthorizationAuditEvent).where(
                    AuthorizationAuditEvent.principal_id == str(self.users["owner"][0]),
                    AuthorizationAuditEvent.resource_type == "active_tenant",
                    AuthorizationAuditEvent.outcome == "allowed",
                )
            )
            self.assertIsNotNone(audit_row)
            self.assertEqual(audit_row.tenant_id, self.target_tenant_id)
            self.assertNotIn(str(self.target_tenant_id), audit_row.target_fingerprint)


if __name__ == "__main__":
    unittest.main()
