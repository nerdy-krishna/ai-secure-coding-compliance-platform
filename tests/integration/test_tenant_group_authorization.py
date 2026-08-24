"""Live API and PostgreSQL contracts for tenant-scoped group management."""

from __future__ import annotations

import os
import unittest
from uuid import UUID, uuid4

import httpx
from fastapi_users.password import PasswordHelper
from sqlalchemy import delete
from sqlalchemy.exc import DBAPIError

from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.models import (
    RoleAssignment,
    Tenant,
    User,
    UserGroup,
    UserGroupMembership,
)
from app.shared.lib.permissions import ANALYST, TENANT_ADMIN
from tests.integration.support import integration_test


@integration_test
class TenantGroupAuthorizationIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        suffix = uuid4().hex[:12]
        self.password = f"A7!{uuid4()}z"
        self.base_url = os.getenv(
            "SCCAP_INTEGRATION_BASE_URL",
            "http://127.0.0.1:8000",
        ).rstrip("/")
        async with AsyncSessionLocal() as db:
            own_tenant = Tenant(
                slug=f"group-own-{suffix}",
                display_name="Group Own Tenant",
            )
            foreign_tenant = Tenant(
                slug=f"group-foreign-{suffix}",
                display_name="Group Foreign Tenant",
            )
            db.add_all([own_tenant, foreign_tenant])
            await db.flush()
            specs = [
                ("admin", own_tenant.id, TENANT_ADMIN),
                ("owner", own_tenant.id, ANALYST),
                ("member", own_tenant.id, ANALYST),
                ("outsider", own_tenant.id, ANALYST),
                ("foreign-admin", foreign_tenant.id, TENANT_ADMIN),
                ("foreign-member", foreign_tenant.id, ANALYST),
            ]
            users = []
            for label, tenant_id, _role in specs:
                users.append(
                    User(
                        email=f"group-{label}-{suffix}@example.com",
                        hashed_password=PasswordHelper().hash(self.password),
                        is_active=True,
                        is_superuser=False,
                        is_verified=True,
                        tenant_id=tenant_id,
                    )
                )
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
            await db.execute(
                delete(UserGroup).where(UserGroup.tenant_id.in_(self.tenant_ids))
            )
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

    async def test_tenant_admin_and_group_owner_are_resource_scoped(self) -> None:
        endpoint = "/api/v1/admin/user-groups"
        name = f"shared-name-{uuid4()}"

        owner_create = await self.client.post(
            endpoint,
            json={"name": name},
            headers=await self._headers("owner"),
        )
        self.assertEqual(owner_create.status_code, 403, owner_create.text)

        own_admin_headers = await self._headers("admin")
        created = await self.client.post(
            endpoint,
            json={"name": name},
            headers=own_admin_headers,
        )
        self.assertEqual(created.status_code, 201, created.text)
        own_group_id = created.json()["id"]

        owner_added = await self.client.post(
            f"{endpoint}/{own_group_id}/members",
            json={"email": self.users["owner"][1], "role": "owner"},
            headers=own_admin_headers,
        )
        self.assertEqual(owner_added.status_code, 200, owner_added.text)

        owner_headers = await self._headers("owner")
        owner_update = await self.client.patch(
            f"{endpoint}/{own_group_id}",
            json={"description": "managed by group owner"},
            headers=owner_headers,
        )
        self.assertEqual(owner_update.status_code, 200, owner_update.text)

        owner_list = await self.client.get(endpoint, headers=owner_headers)
        self.assertEqual(owner_list.status_code, 200, owner_list.text)
        self.assertEqual([row["id"] for row in owner_list.json()], [own_group_id])

        outsider = await self.client.patch(
            f"{endpoint}/{own_group_id}",
            json={"description": "forbidden"},
            headers=await self._headers("outsider"),
        )
        self.assertEqual(outsider.status_code, 404, outsider.text)

        foreign_admin_headers = await self._headers("foreign-admin")
        foreign_lookup = await self.client.patch(
            f"{endpoint}/{own_group_id}",
            json={"description": "cross tenant"},
            headers=foreign_admin_headers,
        )
        self.assertEqual(foreign_lookup.status_code, 404, foreign_lookup.text)

        cross_tenant_member = await self.client.post(
            f"{endpoint}/{own_group_id}/members",
            json={"email": self.users["foreign-member"][1], "role": "member"},
            headers=own_admin_headers,
        )
        self.assertEqual(cross_tenant_member.status_code, 404, cross_tenant_member.text)

        foreign_same_name = await self.client.post(
            endpoint,
            json={"name": name},
            headers=foreign_admin_headers,
        )
        self.assertEqual(foreign_same_name.status_code, 201, foreign_same_name.text)

        async with AsyncSessionLocal() as db:
            db.add(
                UserGroupMembership(
                    group_id=UUID(own_group_id),
                    user_id=self.users["foreign-member"][0],
                )
            )
            with self.assertRaises(DBAPIError):
                await db.commit()
            await db.rollback()


if __name__ == "__main__":
    unittest.main()
