"""Live tenant and permission contracts for SSO administration."""

from __future__ import annotations

import os
import unittest
from uuid import uuid4

import httpx
from fastapi_users.password import PasswordHelper
from sqlalchemy import delete, select

from app.infrastructure.auth.sso.repository import SsoProviderRepository
from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.models import RoleAssignment, SsoProvider, Tenant, User
from app.shared.lib.permissions import ANALYST, AUDITOR, TENANT_ADMIN
from tests.integration.support import integration_test


@integration_test
class TenantSsoAdministrationIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        suffix = uuid4().hex[:12]
        self.suffix = suffix
        self.password = f"S9!{uuid4()}q"
        self.base_url = os.getenv(
            "SCCAP_INTEGRATION_BASE_URL",
            "http://127.0.0.1:8000",
        ).rstrip("/")
        async with AsyncSessionLocal() as db:
            own_tenant = Tenant(
                slug=f"sso-own-{suffix}", display_name="SSO Own Tenant"
            )
            foreign_tenant = Tenant(
                slug=f"sso-foreign-{suffix}", display_name="SSO Foreign Tenant"
            )
            db.add_all([own_tenant, foreign_tenant])
            await db.flush()
            specs = [
                ("admin", own_tenant.id, TENANT_ADMIN),
                ("auditor", own_tenant.id, AUDITOR),
                ("analyst", own_tenant.id, ANALYST),
            ]
            users = [
                User(
                    email=f"sso-{label}-{suffix}@example.com",
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
                RoleAssignment(
                    user_id=user.id,
                    tenant_id=tenant_id,
                    role_key=role,
                )
                for user, (_label, tenant_id, role) in zip(users, specs)
            )
            foreign_provider = await SsoProviderRepository(db).create(
                name=f"foreign-{suffix}",
                display_name="Foreign Provider",
                protocol="oidc",
                config_plain={
                    "issuer_url": "https://foreign-idp.example.test",
                    "client_id": "foreign-client",
                    "client_secret": "foreign-secret",
                },
                tenant_id=foreign_tenant.id,
            )
            await db.commit()
            self.tenant_ids = [own_tenant.id, foreign_tenant.id]
            self.own_tenant_id = own_tenant.id
            self.foreign_tenant_id = foreign_tenant.id
            self.foreign_provider_id = foreign_provider.id
            self.users = {
                label: (user.id, user.email)
                for user, (label, _tenant_id, _role) in zip(users, specs)
            }

        self.client = httpx.AsyncClient(base_url=self.base_url, timeout=15.0)

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        async with AsyncSessionLocal() as db:
            user_ids = list(
                (
                    await db.scalars(
                        select(User.id).where(User.tenant_id.in_(self.tenant_ids))
                    )
                ).all()
            )
            await db.execute(
                delete(RoleAssignment).where(RoleAssignment.user_id.in_(user_ids))
            )
            await db.execute(
                delete(SsoProvider).where(SsoProvider.tenant_id.in_(self.tenant_ids))
            )
            await db.execute(delete(User).where(User.id.in_(user_ids)))
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

    async def test_sso_admin_is_permission_and_tenant_scoped(self) -> None:
        endpoint = "/api/v1/admin/sso/providers"
        analyst = await self.client.get(
            endpoint, headers=await self._headers("analyst")
        )
        self.assertEqual(analyst.status_code, 403, analyst.text)

        auditor_headers = await self._headers("auditor")
        auditor = await self.client.get(endpoint, headers=auditor_headers)
        self.assertEqual(auditor.status_code, 403, auditor.text)

        admin_headers = await self._headers("admin")
        initial = await self.client.get(endpoint, headers=admin_headers)
        self.assertEqual(initial.status_code, 200, initial.text)
        self.assertNotIn(
            str(self.foreign_provider_id), {row["id"] for row in initial.json()}
        )
        concealed = await self.client.get(
            f"{endpoint}/{self.foreign_provider_id}", headers=admin_headers
        )
        self.assertEqual(concealed.status_code, 404, concealed.text)

        created = await self.client.post(
            endpoint,
            headers=admin_headers,
            json={
                "name": f"own-{self.suffix}",
                "display_name": "Own Provider",
                "protocol": "oidc",
                "config": {
                    "issuer_url": "https://own-idp.example.test",
                    "client_id": "own-client",
                    "client_secret": "own-secret",
                },
                "enabled": True,
                "jit_policy": "deny",
            },
        )
        self.assertEqual(created.status_code, 201, created.text)
        created_id = created.json()["id"]
        self.assertEqual(created.json()["config"]["client_secret"], "***")

        cross_update = await self.client.patch(
            f"{endpoint}/{self.foreign_provider_id}",
            headers=admin_headers,
            json={"display_name": "Blocked"},
        )
        self.assertEqual(cross_update.status_code, 404, cross_update.text)

        audit_rows = await self.client.get(
            "/api/v1/admin/sso/audit", headers=auditor_headers
        )
        self.assertEqual(audit_rows.status_code, 200, audit_rows.text)
        self.assertTrue(
            any(row["event"] == "auth.provider.created" for row in audit_rows.json())
        )

        own_domains = await self.client.get(
            f"/api/v1/admin/tenants/{self.own_tenant_id}/domains",
            headers=admin_headers,
        )
        self.assertEqual(own_domains.status_code, 200, own_domains.text)
        foreign_domains = await self.client.get(
            f"/api/v1/admin/tenants/{self.foreign_tenant_id}/domains",
            headers=admin_headers,
        )
        self.assertEqual(foreign_domains.status_code, 404, foreign_domains.text)

        tenant_list = await self.client.get(
            "/api/v1/admin/tenants", headers=admin_headers
        )
        self.assertEqual(tenant_list.status_code, 403, tenant_list.text)

        async with AsyncSessionLocal() as db:
            provider = await db.scalar(
                select(SsoProvider).where(SsoProvider.id == created_id)
            )
            self.assertIsNotNone(provider)
            self.assertEqual(provider.tenant_id, self.own_tenant_id)
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
