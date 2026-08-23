"""Public HTTP integration contract for the password/refresh session."""

from __future__ import annotations

import os
import unittest
from uuid import uuid4

import httpx
from fastapi_users.password import PasswordHelper
from sqlalchemy import delete

from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.models import User
from tests.integration.support import integration_test


@integration_test
class PublicAuthSessionIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.base_url = os.getenv(
            "SCCAP_INTEGRATION_BASE_URL", "http://127.0.0.1:8000"
        ).rstrip("/")
        # Use a routable-looking reserved documentation domain because the
        # public UserRead schema deliberately rejects special-use TLDs such
        # as `.invalid`, even when a fixture inserts directly through SQL.
        self.email = f"integration-session-{uuid4()}@example.com"
        self.password = f"A7!{uuid4()}z"
        password_hash = PasswordHelper().hash(self.password)

        async with AsyncSessionLocal() as db:
            user = User(
                email=self.email,
                hashed_password=password_hash,
                is_active=True,
                is_superuser=False,
                is_verified=True,
            )
            db.add(user)
            await db.commit()
            self.user_id = user.id

        self.client = httpx.AsyncClient(base_url=self.base_url, timeout=15.0)

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        async with AsyncSessionLocal() as db:
            await db.execute(delete(User).where(User.id == self.user_id))
            await db.commit()
        await engine.dispose()

    async def test_password_login_refreshes_and_rotates_browser_session(self) -> None:
        login = await self.client.post(
            "/api/v1/auth/login",
            data={"username": self.email, "password": self.password},
        )
        self.assertEqual(login.status_code, 200, login.text)
        self.assertEqual(login.headers.get("cache-control"), "no-store")
        self.assertIn("access_token", login.json())

        initial_refresh = self.client.cookies.get("SecureCodePlatformRefresh")
        self.assertIsNotNone(initial_refresh)

        refresh = await self.client.post("/api/v1/auth/refresh")
        self.assertEqual(refresh.status_code, 200, refresh.text)
        self.assertEqual(refresh.headers.get("cache-control"), "no-store")
        refreshed_access = refresh.json()["access_token"]
        rotated_refresh = self.client.cookies.get("SecureCodePlatformRefresh")
        self.assertNotEqual(rotated_refresh, initial_refresh)

        me = await self.client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {refreshed_access}"},
        )
        self.assertEqual(me.status_code, 200, me.text)
        self.assertEqual(me.json()["email"], self.email)


if __name__ == "__main__":
    unittest.main()
