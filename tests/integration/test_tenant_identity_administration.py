"""Live permission and tenant-boundary contracts for human identity admin."""

from __future__ import annotations

import os
import unittest
from uuid import uuid4

import httpx
from fastapi_users.password import PasswordHelper
from sqlalchemy import delete, select

from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.models import RoleAssignment, Tenant, User
from app.shared.lib.permissions import ANALYST, AUDITOR, TENANT_ADMIN
from tests.integration.support import integration_test


@integration_test
class TenantIdentityAdministrationIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        suffix = uuid4().hex[:12]
        self.suffix = suffix
        self.password = f"A7!{uuid4()}z"
        self.base_url = os.getenv(
            "SCCAP_INTEGRATION_BASE_URL",
            "http://127.0.0.1:8000",
        ).rstrip("/")
        async with AsyncSessionLocal() as db:
            own_tenant = Tenant(
                slug=f"identity-own-{suffix}",
                display_name="Identity Own Tenant",
            )
            foreign_tenant = Tenant(
                slug=f"identity-foreign-{suffix}",
                display_name="Identity Foreign Tenant",
            )
            db.add_all([own_tenant, foreign_tenant])
            await db.flush()
            specs = [
                ("admin", own_tenant.id, TENANT_ADMIN),
                ("auditor", own_tenant.id, AUDITOR),
                ("analyst", own_tenant.id, ANALYST),
                ("member", own_tenant.id, ANALYST),
                ("foreign", foreign_tenant.id, ANALYST),
            ]
            users = [
                User(
                    email=f"identity-{label}-{suffix}@example.com",
                    hashed_password=PasswordHelper().hash(self.password),
                    is_active=True,
                    is_superuser=False,
                    is_verified=True,
                    tenant_id=tenant_id,
                )
                for label, tenant_id, _role in specs
            ]
            db.add_all(users)
            await db.flush()
            db.add_all(
                [
                    RoleAssignment(
                        user_id=user.id,
                        tenant_id=tenant_id,
                        role_key=role,
                    )
                    for user, (_label, tenant_id, role) in zip(users, specs)
                ]
            )
            await db.commit()
            self.tenant_ids = [own_tenant.id, foreign_tenant.id]
            self.user_ids = [user.id for user in users]
            self.users = {
                label: (user.id, user.email)
                for user, (label, _tenant_id, _role) in zip(users, specs)
            }

        self.client = httpx.AsyncClient(base_url=self.base_url, timeout=15.0)

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        async with AsyncSessionLocal() as db:
            all_user_ids = list(
                (
                    await db.scalars(
                        select(User.id).where(User.tenant_id.in_(self.tenant_ids))
                    )
                ).all()
            )
            await db.execute(
                delete(RoleAssignment).where(RoleAssignment.user_id.in_(all_user_ids))
            )
            await db.execute(delete(User).where(User.id.in_(all_user_ids)))
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

    async def test_identity_read_manage_and_cross_tenant_concealment(self) -> None:
        endpoint = "/api/v1/admin/users"
        analyst_list = await self.client.get(
            endpoint,
            headers=await self._headers("analyst"),
        )
        self.assertEqual(analyst_list.status_code, 403, analyst_list.text)

        auditor_headers = await self._headers("auditor")
        auditor_list = await self.client.get(endpoint, headers=auditor_headers)
        self.assertEqual(auditor_list.status_code, 200, auditor_list.text)
        auditor_ids = {row["id"] for row in auditor_list.json()}
        self.assertIn(self.users["member"][0], auditor_ids)
        self.assertNotIn(self.users["foreign"][0], auditor_ids)
        auditor_update = await self.client.patch(
            f"{endpoint}/{self.users['member'][0]}",
            json={"is_verified": False},
            headers=auditor_headers,
        )
        self.assertEqual(auditor_update.status_code, 403, auditor_update.text)

        admin_headers = await self._headers("admin")
        forbidden_platform = await self.client.post(
            endpoint,
            json={
                "email": f"identity-platform-{self.suffix}@example.com",
                "is_superuser": True,
                "is_active": True,
                "is_verified": True,
            },
            headers=admin_headers,
        )
        self.assertEqual(forbidden_platform.status_code, 400, forbidden_platform.text)

        created_email = f"identity-created-{self.suffix}@example.com"
        created = await self.client.post(
            endpoint,
            json={
                "email": created_email,
                "is_superuser": False,
                "is_active": True,
                "is_verified": True,
            },
            headers=admin_headers,
        )
        self.assertEqual(created.status_code, 201, created.text)
        created_body = created.json()
        created_id = created_body["id"]
        self.assertFalse(created_body["is_superuser"])
        self.assertEqual(created_body["role_keys"], [ANALYST])

        legacy_elevation = await self.client.patch(
            f"{endpoint}/{created_id}",
            json={"is_superuser": True},
            headers=admin_headers,
        )
        self.assertEqual(legacy_elevation.status_code, 400, legacy_elevation.text)

        updated = await self.client.patch(
            f"{endpoint}/{created_id}",
            json={"is_active": False, "is_verified": False},
            headers=admin_headers,
        )
        self.assertEqual(updated.status_code, 200, updated.text)
        self.assertFalse(updated.json()["is_active"])

        foreign_update = await self.client.patch(
            f"{endpoint}/{self.users['foreign'][0]}",
            json={"is_verified": False},
            headers=admin_headers,
        )
        self.assertEqual(foreign_update.status_code, 404, foreign_update.text)

        deleted = await self.client.delete(
            f"{endpoint}/{created_id}",
            headers=admin_headers,
        )
        self.assertEqual(deleted.status_code, 204, deleted.text)

        async with AsyncSessionLocal() as db:
            await db.execute(
                delete(RoleAssignment).where(
                    RoleAssignment.user_id == self.users["admin"][0],
                    RoleAssignment.role_key == TENANT_ADMIN,
                )
            )
            await db.commit()
        stale_role = await self.client.get(endpoint, headers=admin_headers)
        self.assertEqual(stale_role.status_code, 403, stale_role.text)


if __name__ == "__main__":
    unittest.main()
