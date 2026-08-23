"""Public HTTP integration contract for the password/refresh session."""

from __future__ import annotations

import os
import unittest
from uuid import uuid4

import httpx
from fastapi_users.password import PasswordHelper
from sqlalchemy import delete, select

from app.infrastructure.auth.backend import get_custom_cookie_jwt_strategy
from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.models import AuthSession, User
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
        csrf_token = login.headers.get("x-csrf-token")
        self.assertIsNotNone(csrf_token)

        initial_refresh = self.client.cookies.get("SecureCodePlatformRefresh")
        self.assertIsNotNone(initial_refresh)
        session_cookie_name = (
            get_custom_cookie_jwt_strategy().browser_session_cookie_name
        )
        initial_session = self.client.cookies.get(session_cookie_name)
        self.assertIsNotNone(initial_session)

        rejected_refresh = await self.client.post("/api/v1/auth/refresh")
        self.assertEqual(rejected_refresh.status_code, 403, rejected_refresh.text)

        browser_headers = {
            "Origin": self.base_url,
            "X-CSRF-Token": csrf_token,
        }
        refresh = await self.client.post(
            "/api/v1/auth/refresh",
            headers=browser_headers,
        )
        self.assertEqual(refresh.status_code, 200, refresh.text)
        self.assertEqual(refresh.headers.get("cache-control"), "no-store")
        refreshed_access = refresh.json()["access_token"]
        rotated_refresh = self.client.cookies.get("SecureCodePlatformRefresh")
        self.assertNotEqual(rotated_refresh, initial_refresh)
        rotated_session = self.client.cookies.get(session_cookie_name)
        self.assertNotEqual(rotated_session, initial_session)

        async with AsyncSessionLocal() as db:
            session_row = await db.scalar(
                select(AuthSession).where(AuthSession.user_id == self.user_id)
            )
            self.assertIsNotNone(session_row)
            self.assertEqual(session_row.credential_generation, 1)
            self.assertIsNone(session_row.revoked_at)

        me = await self.client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {refreshed_access}"},
        )
        self.assertEqual(me.status_code, 200, me.text)
        self.assertEqual(me.json()["email"], self.email)

        cookie_me = await self.client.get("/api/v1/auth/session/me")
        self.assertEqual(cookie_me.status_code, 200, cookie_me.text)
        self.assertEqual(cookie_me.json()["email"], self.email)

        preferences = await self.client.get("/api/v1/account/preferences")
        self.assertEqual(preferences.status_code, 200, preferences.text)
        rejected_update = await self.client.put(
            "/api/v1/account/preferences",
            json={"theme": "dark"},
        )
        self.assertEqual(rejected_update.status_code, 403, rejected_update.text)
        accepted_update = await self.client.put(
            "/api/v1/account/preferences",
            json={"theme": "dark"},
            headers=browser_headers,
        )
        self.assertEqual(accepted_update.status_code, 200, accepted_update.text)

        csrf_bootstrap = await self.client.get("/api/v1/auth/session/csrf")
        self.assertEqual(csrf_bootstrap.status_code, 200, csrf_bootstrap.text)
        self.assertEqual(
            csrf_bootstrap.headers.get("x-csrf-token"),
            csrf_bootstrap.json()["csrf_token"],
        )

        # A copied prior-generation browser credential is a validly MACed
        # replay, not random tampering. The family is revoked immediately.
        self.client.cookies.set(session_cookie_name, initial_session)
        replay = await self.client.post(
            "/api/v1/auth/refresh",
            headers=browser_headers,
        )
        self.assertEqual(replay.status_code, 401, replay.text)
        async with AsyncSessionLocal() as db:
            replayed_row = await db.scalar(
                select(AuthSession).where(AuthSession.user_id == self.user_id)
            )
            self.assertEqual(replayed_row.revocation_reason, "credential_reuse")


if __name__ == "__main__":
    unittest.main()
