"""Public SCIM provisioning/deprovisioning browser-session contract."""

from __future__ import annotations

import os
import unittest
from uuid import uuid4

import httpx
from sqlalchemy import delete

from app.infrastructure.auth.scim.auth import hash_token
from app.infrastructure.auth.session import BrowserSessionService
from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.models import AuthSession, ScimToken, User
from tests.integration.support import integration_test


@integration_test
class ScimSessionLifecycleIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.base_url = os.getenv(
            "SCCAP_INTEGRATION_BASE_URL", "http://127.0.0.1:8000"
        ).rstrip("/")
        self.plaintext = "scim_" + uuid4().hex + uuid4().hex[:16]
        async with AsyncSessionLocal() as db:
            token = ScimToken(
                name=f"integration-scim-{uuid4()}",
                token_hash=hash_token(self.plaintext),
                scopes=["users:write"],
            )
            db.add(token)
            await db.commit()
            self.token_id = token.id
        self.client = httpx.AsyncClient(base_url=self.base_url, timeout=15.0)
        self.user_id: int | None = None

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        async with AsyncSessionLocal() as db:
            if self.user_id is not None:
                await db.execute(delete(User).where(User.id == self.user_id))
            await db.execute(delete(ScimToken).where(ScimToken.id == self.token_id))
            await db.commit()
        await engine.dispose()

    async def test_scim_create_then_string_false_deprovisions_and_revokes(self) -> None:
        headers = {"Authorization": f"Bearer {self.plaintext}"}
        email = f"scim-integration-{uuid4()}@example.com"
        created = await self.client.post(
            "/scim/v2/Users",
            headers=headers,
            json={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": email,
                "active": True,
            },
        )
        self.assertEqual(created.status_code, 201, created.text)
        self.user_id = int(created.json()["id"])

        async with AsyncSessionLocal() as db:
            user = await db.get(User, self.user_id)
            issued = await BrowserSessionService(db).create(
                user,
                auth_method="password",
            )
            await db.commit()
            session_id = issued.row.id

        deactivated = await self.client.patch(
            f"/scim/v2/Users/{self.user_id}",
            headers=headers,
            json={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [
                    {"op": "replace", "path": "active", "value": "false"}
                ],
            },
        )
        self.assertEqual(deactivated.status_code, 200, deactivated.text)
        self.assertFalse(deactivated.json()["active"])

        async with AsyncSessionLocal() as db:
            user = await db.get(User, self.user_id)
            session = await db.get(AuthSession, session_id)
            self.assertFalse(user.is_active)
            self.assertIsNotNone(session.revoked_at)
            self.assertEqual(session.revocation_reason, "scim_deactivated_user")


if __name__ == "__main__":
    unittest.main()
