"""Live tenant-isolation contract for SCIM service principals."""

from __future__ import annotations

import os
import unittest
from uuid import UUID, uuid4

import httpx
from fastapi_users.password import PasswordHelper
from sqlalchemy import delete, select, text

from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.models import (
    RoleAssignment,
    ScimToken,
    Tenant,
    User,
    UserGroup,
)
from app.infrastructure.database.tenant_context import bind_principal, reset_principal
from app.shared.lib.permissions import ANALYST, TENANT_ADMIN
from tests.integration.support import integration_test


@integration_test
class ScimTenantIsolationIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        suffix = uuid4().hex[:12]
        self.password = f"A7!{uuid4()}z"
        self.base_url = os.getenv(
            "SCCAP_INTEGRATION_BASE_URL",
            "http://127.0.0.1:8000",
        ).rstrip("/")
        async with AsyncSessionLocal() as db:
            tenants = [
                Tenant(slug=f"scim-a-{suffix}", display_name="SCIM Tenant A"),
                Tenant(slug=f"scim-b-{suffix}", display_name="SCIM Tenant B"),
            ]
            db.add_all(tenants)
            await db.flush()
            users = [
                User(
                    email=f"scim-admin-a-{suffix}@example.com",
                    hashed_password=PasswordHelper().hash(self.password),
                    is_active=True,
                    is_superuser=False,
                    is_verified=True,
                    tenant_id=tenants[0].id,
                ),
                User(
                    email=f"scim-admin-b-{suffix}@example.com",
                    hashed_password=PasswordHelper().hash(self.password),
                    is_active=True,
                    is_superuser=False,
                    is_verified=True,
                    tenant_id=tenants[1].id,
                ),
                User(
                    email=f"scim-analyst-a-{suffix}@example.com",
                    hashed_password=PasswordHelper().hash(self.password),
                    is_active=True,
                    is_superuser=False,
                    is_verified=True,
                    tenant_id=tenants[0].id,
                ),
            ]
            db.add_all(users)
            await db.flush()
            db.add_all(
                [
                    RoleAssignment(
                        user_id=users[0].id,
                        tenant_id=tenants[0].id,
                        role_key=TENANT_ADMIN,
                    ),
                    RoleAssignment(
                        user_id=users[1].id,
                        tenant_id=tenants[1].id,
                        role_key=TENANT_ADMIN,
                    ),
                    RoleAssignment(
                        user_id=users[2].id,
                        tenant_id=tenants[0].id,
                        role_key=ANALYST,
                    ),
                ]
            )
            await db.commit()
            self.tenant_ids = [tenant.id for tenant in tenants]
            self.seed_user_ids = [user.id for user in users]
            self.emails = [user.email for user in users]
            self.suffix = suffix

        self.client = httpx.AsyncClient(base_url=self.base_url, timeout=15.0)

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        async with AsyncSessionLocal() as db:
            await db.execute(
                delete(ScimToken).where(ScimToken.tenant_id.in_(self.tenant_ids))
            )
            await db.execute(
                delete(UserGroup).where(UserGroup.tenant_id.in_(self.tenant_ids))
            )
            users = list(
                (
                    await db.scalars(
                        select(User.id).where(User.tenant_id.in_(self.tenant_ids))
                    )
                ).all()
            )
            await db.execute(
                delete(RoleAssignment).where(RoleAssignment.user_id.in_(users))
            )
            await db.execute(delete(User).where(User.id.in_(users)))
            await db.execute(delete(Tenant).where(Tenant.id.in_(self.tenant_ids)))
            await db.commit()
        await engine.dispose()

    async def _login(self, index: int) -> dict[str, str]:
        response = await self.client.post(
            "/api/v1/auth/login",
            data={"username": self.emails[index], "password": self.password},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    async def _issue_token(self, admin_index: int, name: str) -> tuple[str, str]:
        response = await self.client.post(
            "/api/v1/admin/scim/tokens",
            json={
                "name": name,
                "scopes": [
                    "users:read",
                    "users:write",
                    "groups:read",
                    "groups:write",
                ],
            },
            headers=await self._login(admin_index),
        )
        self.assertEqual(response.status_code, 201, response.text)
        body = response.json()
        return body["id"], body["plaintext_token"]

    @staticmethod
    def _scim_headers(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    async def test_tokens_users_and_groups_are_bound_to_one_tenant(self) -> None:
        denied = await self.client.post(
            "/api/v1/admin/scim/tokens",
            json={"name": "denied", "scopes": ["users:read"]},
            headers=await self._login(2),
        )
        self.assertEqual(denied.status_code, 403, denied.text)

        token_a_id, token_a = await self._issue_token(0, "tenant-a")
        token_b_id, token_b = await self._issue_token(1, "tenant-b")
        headers_a = self._scim_headers(token_a)
        headers_b = self._scim_headers(token_b)

        binding = bind_principal(
            tenant_id=self.tenant_ids[0],
            principal_kind="human",
            principal_id=str(self.seed_user_ids[0]),
        )
        try:
            async with AsyncSessionLocal() as db:
                await db.execute(text("SET LOCAL ROLE sccap_runtime"))
                visible_token_ids = set((await db.scalars(select(ScimToken.id))).all())
        finally:
            reset_principal(binding)
        self.assertIn(UUID(token_a_id), visible_token_ids)
        self.assertNotIn(UUID(token_b_id), visible_token_ids)

        email_a = f"scim-user-a-{self.suffix}@example.com"
        email_b = f"scim-user-b-{self.suffix}@example.com"
        created_a = await self.client.post(
            "/scim/v2/Users",
            json={"userName": email_a, "active": True},
            headers=headers_a,
        )
        created_b = await self.client.post(
            "/scim/v2/Users",
            json={"userName": email_b, "active": True},
            headers=headers_b,
        )
        self.assertEqual(created_a.status_code, 201, created_a.text)
        self.assertEqual(created_b.status_code, 201, created_b.text)
        user_a_id = created_a.json()["id"]
        user_b_id = created_b.json()["id"]

        foreign_user = await self.client.get(
            f"/scim/v2/Users/{user_b_id}", headers=headers_a
        )
        self.assertEqual(foreign_user.status_code, 404, foreign_user.text)
        listed_a = await self.client.get("/scim/v2/Users", headers=headers_a)
        self.assertEqual(listed_a.status_code, 200, listed_a.text)
        listed_names = {row["userName"] for row in listed_a.json()["Resources"]}
        self.assertIn(email_a, listed_names)
        self.assertNotIn(email_b, listed_names)

        group_name = f"shared-{self.suffix}"
        group_a = await self.client.post(
            "/scim/v2/Groups",
            json={
                "displayName": group_name,
                "members": [{"value": user_a_id}],
            },
            headers=headers_a,
        )
        group_b = await self.client.post(
            "/scim/v2/Groups",
            json={"displayName": group_name, "members": [{"value": user_b_id}]},
            headers=headers_b,
        )
        self.assertEqual(group_a.status_code, 201, group_a.text)
        self.assertEqual(group_b.status_code, 201, group_b.text)
        group_a_id = group_a.json()["id"]
        group_b_id = group_b.json()["id"]

        foreign_group = await self.client.get(
            f"/scim/v2/Groups/{group_b_id}", headers=headers_a
        )
        self.assertEqual(foreign_group.status_code, 404, foreign_group.text)
        add_foreign_member = await self.client.patch(
            f"/scim/v2/Groups/{group_a_id}",
            json={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [
                    {
                        "op": "add",
                        "path": "members",
                        "value": [{"value": user_b_id}],
                    }
                ],
            },
            headers=headers_a,
        )
        self.assertEqual(add_foreign_member.status_code, 200, add_foreign_member.text)
        self.assertEqual(
            {row["value"] for row in add_foreign_member.json()["members"]},
            {user_a_id},
        )

        foreign_revoke = await self.client.delete(
            f"/api/v1/admin/scim/tokens/{token_a_id}",
            headers=await self._login(1),
        )
        self.assertEqual(foreign_revoke.status_code, 404, foreign_revoke.text)

        async with AsyncSessionLocal() as db:
            provisioned = await db.scalar(select(User).where(User.id == int(user_a_id)))
            self.assertEqual(provisioned.tenant_id, self.tenant_ids[0])
            role = await db.scalar(
                select(RoleAssignment).where(
                    RoleAssignment.user_id == int(user_a_id),
                    RoleAssignment.tenant_id == self.tenant_ids[0],
                    RoleAssignment.role_key == ANALYST,
                )
            )
            self.assertIsNotNone(role)
            persisted_token = await db.scalar(
                select(ScimToken).where(ScimToken.id == UUID(token_a_id))
            )
            self.assertIsNotNone(persisted_token.last_used_at)
            persisted_group = await db.scalar(
                select(UserGroup).where(UserGroup.id == UUID(group_a_id))
            )
            self.assertEqual(persisted_group.created_by, self.seed_user_ids[0])

        revoked = await self.client.delete(
            f"/api/v1/admin/scim/tokens/{token_a_id}",
            headers=await self._login(0),
        )
        self.assertEqual(revoked.status_code, 204, revoked.text)
        stale_token = await self.client.get("/scim/v2/Users", headers=headers_a)
        self.assertEqual(stale_token.status_code, 401, stale_token.text)


if __name__ == "__main__":
    unittest.main()
