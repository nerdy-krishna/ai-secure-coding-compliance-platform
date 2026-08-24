"""Live distinct-actor contracts for destructive SSO and SCIM changes."""

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
    AuthAuditEvent,
    RoleAssignment,
    ScimToken,
    SsoProvider,
    Tenant,
    User,
)
from app.shared.lib.permissions import TENANT_ADMIN
from tests.integration.support import integration_test


@integration_test
class DestructiveIdentityWorkflowIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        suffix = uuid4().hex[:12]
        self.suffix = suffix
        self.password = f"D9!{uuid4()}w"
        self.base_url = os.getenv(
            "SCCAP_INTEGRATION_BASE_URL", "http://127.0.0.1:8000"
        ).rstrip("/")
        async with AsyncSessionLocal() as db:
            tenant = Tenant(
                slug=f"destructive-{suffix}",
                display_name="Destructive Workflow Tenant",
                separation_of_duties_mode="critical",
            )
            foreign_tenant = Tenant(
                slug=f"destructive-foreign-{suffix}",
                display_name="Foreign Destructive Tenant",
            )
            db.add_all([tenant, foreign_tenant])
            await db.flush()
            specs = [
                ("admin-a", tenant.id),
                ("admin-b", tenant.id),
                ("foreign", foreign_tenant.id),
            ]
            users = [
                User(
                    email=f"destructive-{label}-{suffix}@example.com",
                    hashed_password=PasswordHelper().hash(self.password),
                    is_active=True,
                    is_superuser=False,
                    is_verified=True,
                    tenant_id=user_tenant_id,
                )
                for label, user_tenant_id in specs
            ]
            db.add_all(users)
            await db.flush()
            db.add_all(
                RoleAssignment(
                    user_id=user.id,
                    tenant_id=user_tenant_id,
                    role_key=TENANT_ADMIN,
                )
                for user, (_label, user_tenant_id) in zip(users, specs)
            )
            await db.commit()
            self.tenant_id = tenant.id
            self.foreign_tenant_id = foreign_tenant.id
            self.user_ids = [user.id for user in users]
            self.users = {
                label: (user.id, user.email)
                for user, (label, _tenant_id) in zip(users, specs)
            }
        self.client = httpx.AsyncClient(base_url=self.base_url, timeout=15.0)

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        async with AsyncSessionLocal() as db:
            tenant_ids = [self.tenant_id, self.foreign_tenant_id]
            await db.execute(
                delete(AuthorizationActionRequest).where(
                    AuthorizationActionRequest.tenant_id.in_(tenant_ids)
                )
            )
            await db.execute(
                delete(SsoProvider).where(SsoProvider.tenant_id.in_(tenant_ids))
            )
            await db.execute(
                delete(ScimToken).where(ScimToken.tenant_id.in_(tenant_ids))
            )
            await db.execute(
                delete(RoleAssignment).where(RoleAssignment.user_id.in_(self.user_ids))
            )
            await db.execute(delete(User).where(User.id.in_(self.user_ids)))
            await db.execute(delete(Tenant).where(Tenant.id.in_(tenant_ids)))
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

    async def _create_provider(self, headers: dict[str, str], label: str) -> str:
        response = await self.client.post(
            "/api/v1/admin/sso/providers",
            headers=headers,
            json={
                "name": f"{label}-{self.suffix}",
                "display_name": f"{label} provider",
                "protocol": "oidc",
                "config": {
                    "issuer_url": "https://idp.example.com",
                    "client_id": "sccap",
                    "client_secret": "test-secret",
                    "scopes": ["openid", "email", "profile"],
                },
                "enabled": True,
                "jit_policy": "deny",
            },
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()["id"]

    async def _create_token(self, headers: dict[str, str], label: str) -> str:
        response = await self.client.post(
            "/api/v1/admin/scim/tokens",
            headers=headers,
            json={"name": label, "scopes": ["users:read", "users:write"]},
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()["id"]

    async def _request_and_approve(
        self,
        *,
        request_url: str,
        requester: dict[str, str],
        approver: dict[str, str],
    ) -> str:
        requested = await self.client.post(
            request_url,
            headers={
                **requester,
                "X-Idempotency-Key": f"destructive-{uuid4()}",
            },
        )
        self.assertEqual(requested.status_code, 201, requested.text)
        request_id = requested.json()["id"]
        self_decision = await self.client.post(
            f"/api/v1/admin/authorization/actions/{request_id}/decision",
            headers=requester,
            json={"approved": True, "reason": "self approval forbidden"},
        )
        self.assertEqual(self_decision.status_code, 403, self_decision.text)
        approved = await self.client.post(
            f"/api/v1/admin/authorization/actions/{request_id}/decision",
            headers=approver,
            json={"approved": True, "reason": "destructive change reviewed"},
        )
        self.assertEqual(approved.status_code, 200, approved.text)
        return request_id

    async def test_provider_delete_and_token_revoke_require_distinct_actor(
        self,
    ) -> None:
        admin_a = await self._headers("admin-a")
        admin_b = await self._headers("admin-b")
        foreign = await self._headers("foreign")
        provider_id = await self._create_provider(admin_a, "local")
        foreign_provider_id = await self._create_provider(foreign, "foreign")
        token_id = await self._create_token(admin_a, "local SCIM")
        foreign_token_id = await self._create_token(foreign, "foreign SCIM")

        for foreign_url in (
            f"/api/v1/admin/sso/providers/{foreign_provider_id}",
            f"/api/v1/admin/sso/providers/{foreign_provider_id}/deletion-requests",
            f"/api/v1/admin/scim/tokens/{foreign_token_id}",
            f"/api/v1/admin/scim/tokens/{foreign_token_id}/revocation-requests",
        ):
            response = (
                await self.client.delete(foreign_url, headers=admin_a)
                if "requests" not in foreign_url
                else await self.client.post(
                    foreign_url,
                    headers={
                        **admin_a,
                        "X-Idempotency-Key": f"foreign-{uuid4()}",
                    },
                )
            )
            self.assertEqual(response.status_code, 404, response.text)

        provider_url = f"/api/v1/admin/sso/providers/{provider_id}"
        direct_provider = await self.client.delete(provider_url, headers=admin_a)
        self.assertEqual(direct_provider.status_code, 409, direct_provider.text)
        provider_request_id = await self._request_and_approve(
            request_url=f"{provider_url}/deletion-requests",
            requester=admin_a,
            approver=admin_b,
        )

        token_url = f"/api/v1/admin/scim/tokens/{token_id}"
        direct_token = await self.client.delete(token_url, headers=admin_a)
        self.assertEqual(direct_token.status_code, 409, direct_token.text)
        wrong_action = await self.client.delete(
            token_url,
            headers=admin_a,
            params={"action_request_id": provider_request_id},
        )
        self.assertEqual(wrong_action.status_code, 404, wrong_action.text)
        token_request_id = await self._request_and_approve(
            request_url=f"{token_url}/revocation-requests",
            requester=admin_a,
            approver=admin_b,
        )

        provider_deleted = await self.client.delete(
            provider_url,
            headers=admin_a,
            params={"action_request_id": provider_request_id},
        )
        self.assertEqual(provider_deleted.status_code, 204, provider_deleted.text)
        token_revoked = await self.client.delete(
            token_url,
            headers=admin_a,
            params={"action_request_id": token_request_id},
        )
        self.assertEqual(token_revoked.status_code, 204, token_revoked.text)

        async with AsyncSessionLocal() as db:
            self.assertIsNone(await db.get(SsoProvider, provider_id))
            self.assertIsNone(await db.get(ScimToken, token_id))
            actions = list(
                (
                    await db.scalars(
                        select(AuthorizationActionRequest).where(
                            AuthorizationActionRequest.id.in_(
                                [provider_request_id, token_request_id]
                            )
                        )
                    )
                ).all()
            )
            self.assertEqual({row.status for row in actions}, {"executed"})
            audits = list(
                (
                    await db.scalars(
                        select(AuthorizationAuditEvent).where(
                            AuthorizationAuditEvent.action_request_id.in_(
                                [provider_request_id, token_request_id]
                            ),
                            AuthorizationAuditEvent.outcome == "executed",
                        )
                    )
                ).all()
            )
            self.assertEqual(len(audits), 2)
            self.assertTrue(all(audit.target_fingerprint for audit in audits))
            self.assertTrue(
                all(provider_id not in audit.target_fingerprint for audit in audits)
            )
            destructive_auth_audits = list(
                (
                    await db.scalars(
                        select(AuthAuditEvent).where(
                            AuthAuditEvent.tenant_id == self.tenant_id,
                            AuthAuditEvent.event.in_(
                                ["auth.provider.deleted", "scim.token.revoked"]
                            ),
                            AuthAuditEvent.outcome == "success",
                        )
                    )
                ).all()
            )
            self.assertEqual(len(destructive_auth_audits), 2)


if __name__ == "__main__":
    unittest.main()
