"""Live policy and durable distinct-actor action API contracts."""

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
    RoleAssignment,
    Tenant,
    User,
)
from app.shared.lib.permissions import ANALYST, AUDITOR, TENANT_ADMIN
from tests.integration.support import integration_test


@integration_test
class AuthorizationPolicyApiIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        suffix = uuid4().hex[:12]
        self.password = f"G7!{uuid4()}x"
        self.base_url = os.getenv(
            "SCCAP_INTEGRATION_BASE_URL", "http://127.0.0.1:8000"
        ).rstrip("/")
        async with AsyncSessionLocal() as db:
            tenant = Tenant(slug=f"policy-{suffix}", display_name="Policy Tenant")
            db.add(tenant)
            await db.flush()
            specs = [
                ("admin-a", TENANT_ADMIN),
                ("admin-b", TENANT_ADMIN),
                ("auditor", AUDITOR),
                ("analyst", ANALYST),
            ]
            users = [
                User(
                    email=f"policy-{label}-{suffix}@example.com",
                    hashed_password=PasswordHelper().hash(self.password),
                    is_active=True,
                    is_superuser=False,
                    is_verified=True,
                    tenant_id=tenant.id,
                )
                for label, _role in specs
            ]
            db.add_all(users)
            await db.flush()
            db.add_all(
                RoleAssignment(
                    user_id=user.id,
                    tenant_id=tenant.id,
                    role_key=role,
                )
                for user, (_label, role) in zip(users, specs)
            )
            await db.commit()
            self.tenant_id = tenant.id
            self.user_ids = [user.id for user in users]
            self.users = {
                label: (user.id, user.email)
                for user, (label, _role) in zip(users, specs)
            }
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
            await db.execute(delete(User).where(User.id.in_(self.user_ids)))
            await db.execute(delete(Tenant).where(Tenant.id == self.tenant_id))
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

    async def test_policy_relaxation_requires_distinct_durable_approval(self) -> None:
        policy_url = "/api/v1/admin/authorization/policy"
        actions_url = "/api/v1/admin/authorization/actions"
        admin_a = await self._headers("admin-a")
        admin_b = await self._headers("admin-b")

        analyst_read = await self.client.get(
            policy_url, headers=await self._headers("analyst")
        )
        self.assertEqual(analyst_read.status_code, 403, analyst_read.text)
        auditor_read = await self.client.get(
            policy_url, headers=await self._headers("auditor")
        )
        self.assertEqual(auditor_read.status_code, 200, auditor_read.text)
        self.assertEqual(auditor_read.json()["separation_of_duties_mode"], "off")

        tightened = await self.client.patch(
            policy_url,
            headers=admin_a,
            json={"separation_of_duties_mode": "critical"},
        )
        self.assertEqual(tightened.status_code, 200, tightened.text)
        direct_relax = await self.client.patch(
            policy_url,
            headers=admin_a,
            json={"separation_of_duties_mode": "off"},
        )
        self.assertEqual(direct_relax.status_code, 409, direct_relax.text)

        requested = await self.client.post(
            "/api/v1/admin/authorization/policy-change-requests",
            headers={**admin_a, "X-Idempotency-Key": f"policy-off-{uuid4()}"},
            json={"separation_of_duties_mode": "off"},
        )
        self.assertEqual(requested.status_code, 201, requested.text)
        request_id = requested.json()["id"]
        self.assertTrue(requested.json()["is_requester"])

        self_decision = await self.client.post(
            f"{actions_url}/{request_id}/decision",
            headers=admin_a,
            json={"approved": True, "reason": "self approval"},
        )
        self.assertEqual(self_decision.status_code, 403, self_decision.text)

        inbox = await self.client.get(
            actions_url, headers=admin_b, params={"status": "pending"}
        )
        self.assertEqual(inbox.status_code, 200, inbox.text)
        item = next(row for row in inbox.json() if row["id"] == request_id)
        self.assertTrue(item["can_decide"])
        approved = await self.client.post(
            f"{actions_url}/{request_id}/decision",
            headers=admin_b,
            json={"approved": True, "reason": "independent review complete"},
        )
        self.assertEqual(approved.status_code, 200, approved.text)
        self.assertEqual(approved.json()["status"], "approved")

        executed = await self.client.patch(
            policy_url,
            headers=admin_a,
            json={
                "separation_of_duties_mode": "off",
                "action_request_id": request_id,
            },
        )
        self.assertEqual(executed.status_code, 200, executed.text)
        self.assertEqual(executed.json()["separation_of_duties_mode"], "off")
        executed_inbox = await self.client.get(actions_url, headers=admin_a)
        executed_row = next(
            row for row in executed_inbox.json() if row["id"] == request_id
        )
        self.assertEqual(executed_row["status"], "executed")


if __name__ == "__main__":
    unittest.main()
