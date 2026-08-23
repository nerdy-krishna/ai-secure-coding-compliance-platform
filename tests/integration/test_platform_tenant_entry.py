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
                    is_superuser=False,
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
                delete(RoleAssignment).where(
                    RoleAssignment.user_id.in_(self.user_ids)
                )
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

    async def test_step_up_grant_selects_one_tenant_and_stales_immediately(self) -> None:
        entry_endpoint = "/api/v1/admin/tenants/entry"
        entry_reason = "Investigating a tenant security incident"
        admin_headers = await self._headers("admin")
        empty_reason = await self.client.post(
            entry_endpoint,
            headers=await self._headers("owner"),
            json={
                "tenant_id": str(self.target_tenant_id),
                "password": self.password,
                "reason": "          ",
            },
        )
        self.assertEqual(empty_reason.status_code, 422, empty_reason.text)
        non_platform = await self.client.post(
            entry_endpoint,
            headers=admin_headers,
            json={
                "tenant_id": str(self.target_tenant_id),
                "password": self.password,
                "reason": entry_reason,
            },
        )
        self.assertEqual(non_platform.status_code, 403, non_platform.text)

        owner_headers = await self._headers("owner")
        wrong_password = await self.client.post(
            entry_endpoint,
            headers=owner_headers,
            json={
                "tenant_id": str(self.target_tenant_id),
                "password": "wrong",
                "reason": entry_reason,
            },
        )
        self.assertEqual(wrong_password.status_code, 403, wrong_password.text)
        issued = await self.client.post(
            entry_endpoint,
            headers=owner_headers,
            json={
                "tenant_id": str(self.target_tenant_id),
                "password": self.password,
                "reason": entry_reason,
            },
        )
        self.assertEqual(issued.status_code, 200, issued.text)
        token = issued.json()["entry_token"]
        self.assertEqual(issued.json()["tenant_id"], str(self.target_tenant_id))
        self.assertEqual(issued.json()["expires_in"], 600)

        home_users = await self.client.get(
            "/api/v1/admin/users", headers=owner_headers
        )
        self.assertEqual(home_users.status_code, 200, home_users.text)
        home_ids = {row["id"] for row in home_users.json()}
        self.assertIn(self.users["home-member"][0], home_ids)
        self.assertNotIn(self.users["target-member"][0], home_ids)

        entered_headers = {**owner_headers, "X-SCCAP-Tenant-Entry": token}
        target_users = await self.client.get(
            "/api/v1/admin/users", headers=entered_headers
        )
        self.assertEqual(target_users.status_code, 200, target_users.text)
        target_ids = {row["id"] for row in target_users.json()}
        self.assertIn(self.users["target-member"][0], target_ids)
        self.assertNotIn(self.users["home-member"][0], target_ids)

        mismatched_principal = await self.client.get(
            "/api/v1/admin/users",
            headers={**admin_headers, "X-SCCAP-Tenant-Entry": token},
        )
        self.assertEqual(mismatched_principal.status_code, 403, mismatched_principal.text)
        tampered = await self.client.get(
            "/api/v1/admin/users",
            headers={**owner_headers, "X-SCCAP-Tenant-Entry": f"{token}x"},
        )
        self.assertEqual(tampered.status_code, 403, tampered.text)

        moved = await self.client.patch(
            f"/api/v1/admin/users/{self.users['target-member'][0]}/tenant",
            headers=entered_headers,
            json={"tenant_id": str(self.home_tenant_id)},
        )
        self.assertEqual(moved.status_code, 200, moved.text)
        self.assertEqual(moved.json()["tenant_id"], str(self.home_tenant_id))
        async with AsyncSessionLocal() as db:
            roles = set(
                (
                    await db.scalars(
                        select(RoleAssignment.role_key).where(
                            RoleAssignment.user_id
                            == self.users["target-member"][0]
                        )
                    )
                ).all()
            )
            self.assertEqual(roles, {ANALYST})
            target = await db.get(Tenant, self.target_tenant_id)
            target.separation_of_duties_mode = "critical"
            await db.commit()

        critical_move = await self.client.patch(
            f"/api/v1/admin/users/{self.users['target-critical'][0]}/tenant",
            headers=entered_headers,
            json={"tenant_id": str(self.home_tenant_id)},
        )
        self.assertEqual(critical_move.status_code, 409, critical_move.text)

        async with AsyncSessionLocal() as db:
            audit_row = await db.scalar(
                select(AuthorizationAuditEvent).where(
                    AuthorizationAuditEvent.principal_id
                    == str(self.users["owner"][0]),
                    AuthorizationAuditEvent.resource_type == "tenant_entry",
                    AuthorizationAuditEvent.outcome == "allowed",
                )
            )
            self.assertIsNotNone(audit_row)
            self.assertEqual(audit_row.tenant_id, self.target_tenant_id)
            self.assertNotIn(str(self.target_tenant_id), audit_row.target_fingerprint)
            reason_row = await db.scalar(
                select(AuthorizationAuditEvent).where(
                    AuthorizationAuditEvent.principal_id
                    == str(self.users["owner"][0]),
                    AuthorizationAuditEvent.resource_type == "tenant_entry_reason",
                    AuthorizationAuditEvent.outcome == "allowed",
                )
            )
            self.assertIsNotNone(reason_row)
            self.assertNotIn(entry_reason, reason_row.target_fingerprint)
            await db.execute(
                delete(RoleAssignment).where(
                    RoleAssignment.user_id == self.users["owner"][0],
                    RoleAssignment.role_key == PLATFORM_OWNER,
                )
            )
            await db.commit()

        stale_grant = await self.client.get(
            "/api/v1/admin/users", headers=entered_headers
        )
        self.assertEqual(stale_grant.status_code, 403, stale_grant.text)


if __name__ == "__main__":
    unittest.main()
