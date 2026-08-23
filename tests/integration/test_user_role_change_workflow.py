"""Live tenant role elevation and distinct-actor approval contracts."""

from __future__ import annotations

import os
import unittest
from uuid import uuid4

import httpx
from fastapi_users.password import PasswordHelper
from sqlalchemy import delete, select

from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.models import (
    AuthorizationActionRequest,
    AuthorizationAuditEvent,
    RoleAssignment,
    Tenant,
    User,
)
from app.shared.lib.permissions import ANALYST, SECURITY_APPROVER, TENANT_ADMIN
from tests.integration.support import integration_test


@integration_test
class UserRoleChangeWorkflowIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        suffix = uuid4().hex[:12]
        self.password = f"R8!{uuid4()}z"
        self.base_url = os.getenv(
            "SCCAP_INTEGRATION_BASE_URL", "http://127.0.0.1:8000"
        ).rstrip("/")
        async with AsyncSessionLocal() as db:
            tenant = Tenant(
                slug=f"roles-{suffix}",
                display_name="Role Workflow Tenant",
                separation_of_duties_mode="critical",
            )
            foreign_tenant = Tenant(
                slug=f"roles-foreign-{suffix}", display_name="Foreign Role Tenant"
            )
            db.add_all([tenant, foreign_tenant])
            await db.flush()
            specs = [
                ("admin-a", tenant.id, TENANT_ADMIN),
                ("admin-b", tenant.id, TENANT_ADMIN),
                ("target", tenant.id, ANALYST),
                ("foreign", foreign_tenant.id, ANALYST),
            ]
            users = [
                User(
                    email=f"roles-{label}-{suffix}@example.com",
                    hashed_password=PasswordHelper().hash(self.password),
                    is_active=True,
                    is_superuser=False,
                    is_verified=True,
                    tenant_id=user_tenant_id,
                )
                for label, user_tenant_id, _role in specs
            ]
            db.add_all(users)
            await db.flush()
            db.add_all(
                RoleAssignment(
                    user_id=user.id,
                    tenant_id=user_tenant_id,
                    role_key=role,
                )
                for user, (_label, user_tenant_id, role) in zip(users, specs)
            )
            await db.commit()
            self.tenant_id = tenant.id
            self.foreign_tenant_id = foreign_tenant.id
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
                delete(AuthorizationActionRequest).where(
                    AuthorizationActionRequest.tenant_id.in_(
                        [self.tenant_id, self.foreign_tenant_id]
                    )
                )
            )
            await db.execute(
                delete(RoleAssignment).where(RoleAssignment.user_id.in_(self.user_ids))
            )
            await db.execute(delete(User).where(User.id.in_(self.user_ids)))
            await db.execute(
                delete(Tenant).where(
                    Tenant.id.in_([self.tenant_id, self.foreign_tenant_id])
                )
            )
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

    async def _request_and_approve(
        self,
        *,
        requester_headers: dict[str, str],
        approver_headers: dict[str, str],
        target_user_id: int,
        role_keys: list[str],
    ) -> str:
        requested = await self.client.post(
            f"/api/v1/admin/users/{target_user_id}/role-change-requests",
            headers={
                **requester_headers,
                "X-Idempotency-Key": f"role-change-{uuid4()}",
            },
            json={"role_keys": role_keys},
        )
        self.assertEqual(requested.status_code, 201, requested.text)
        request_id = requested.json()["id"]
        self_decision = await self.client.post(
            f"/api/v1/admin/authorization/actions/{request_id}/decision",
            headers=requester_headers,
            json={"approved": True, "reason": "self approval is forbidden"},
        )
        self.assertEqual(self_decision.status_code, 403, self_decision.text)
        approved = await self.client.post(
            f"/api/v1/admin/authorization/actions/{request_id}/decision",
            headers=approver_headers,
            json={"approved": True, "reason": "independent role review complete"},
        )
        self.assertEqual(approved.status_code, 200, approved.text)
        return request_id

    async def test_critical_elevation_requires_exact_current_second_actor(self) -> None:
        admin_a = await self._headers("admin-a")
        admin_b = await self._headers("admin-b")
        target_id = self.users["target"][0]
        foreign_id = self.users["foreign"][0]
        roles_url = f"/api/v1/admin/users/{target_id}/roles"

        global_role = await self.client.patch(
            roles_url,
            headers=admin_a,
            json={"role_keys": ["platform_owner"]},
        )
        self.assertEqual(global_role.status_code, 422, global_role.text)

        foreign = await self.client.patch(
            f"/api/v1/admin/users/{foreign_id}/roles",
            headers=admin_a,
            json={"role_keys": [SECURITY_APPROVER]},
        )
        self.assertEqual(foreign.status_code, 404, foreign.text)

        direct = await self.client.patch(
            roles_url,
            headers=admin_a,
            json={"role_keys": [SECURITY_APPROVER]},
        )
        self.assertEqual(direct.status_code, 409, direct.text)

        request_id = await self._request_and_approve(
            requester_headers=admin_a,
            approver_headers=admin_b,
            target_user_id=target_id,
            role_keys=[SECURITY_APPROVER, TENANT_ADMIN],
        )
        tampered = await self.client.patch(
            roles_url,
            headers=admin_a,
            json={
                "role_keys": [TENANT_ADMIN],
                "action_request_id": request_id,
            },
        )
        self.assertEqual(tampered.status_code, 409, tampered.text)
        executed = await self.client.patch(
            roles_url,
            headers=admin_a,
            json={
                "role_keys": [SECURITY_APPROVER, TENANT_ADMIN],
                "action_request_id": request_id,
            },
        )
        self.assertEqual(executed.status_code, 200, executed.text)
        self.assertEqual(
            executed.json()["role_keys"], [SECURITY_APPROVER, TENANT_ADMIN]
        )

        stale_request_id = await self._request_and_approve(
            requester_headers=admin_a,
            approver_headers=admin_b,
            target_user_id=target_id,
            role_keys=[ANALYST, SECURITY_APPROVER, TENANT_ADMIN],
        )
        async with AsyncSessionLocal() as db:
            await db.execute(
                delete(RoleAssignment).where(
                    RoleAssignment.user_id == self.users["admin-b"][0],
                    RoleAssignment.tenant_id == self.tenant_id,
                )
            )
            await db.commit()
        stale_approver = await self.client.patch(
            roles_url,
            headers=admin_a,
            json={
                "role_keys": [ANALYST, SECURITY_APPROVER, TENANT_ADMIN],
                "action_request_id": stale_request_id,
            },
        )
        self.assertEqual(stale_approver.status_code, 409, stale_approver.text)

        direct_downgrade = await self.client.patch(
            roles_url,
            headers=admin_a,
            json={"role_keys": [SECURITY_APPROVER]},
        )
        self.assertEqual(direct_downgrade.status_code, 200, direct_downgrade.text)
        self.assertEqual(direct_downgrade.json()["role_keys"], [SECURITY_APPROVER])

        async with AsyncSessionLocal() as db:
            persisted = list(
                (
                    await db.scalars(
                        select(RoleAssignment.role_key).where(
                            RoleAssignment.user_id == target_id,
                            RoleAssignment.tenant_id == self.tenant_id,
                        )
                    )
                ).all()
            )
            self.assertEqual(persisted, [SECURITY_APPROVER])
            executed_audit = await db.scalar(
                select(AuthorizationAuditEvent).where(
                    AuthorizationAuditEvent.tenant_id == self.tenant_id,
                    AuthorizationAuditEvent.action_request_id == request_id,
                    AuthorizationAuditEvent.outcome == "executed",
                )
            )
            self.assertIsNotNone(executed_audit)
            self.assertNotIn(str(target_id), executed_audit.target_fingerprint)


if __name__ == "__main__":
    unittest.main()
