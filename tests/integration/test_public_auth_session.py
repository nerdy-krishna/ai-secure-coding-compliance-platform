"""Public HTTP integration contract for the password/refresh session."""

from __future__ import annotations

import os
import unittest
from uuid import uuid4

import httpx
from fastapi_users.password import PasswordHelper
from sqlalchemy import delete, select

from app.infrastructure.auth.backend import get_custom_cookie_jwt_strategy
from app.infrastructure.auth.session import (
    BrowserSessionService,
    decode_session_credential,
)
from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.models import (
    AuthSession,
    RoleAssignment,
    Tenant,
    User,
)
from app.shared.lib.permissions import TENANT_ADMIN
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
            foreign_tenant = Tenant(
                slug=f"integration-session-{uuid4()}",
                display_name="Session Integration Foreign Tenant",
            )
            db.add(foreign_tenant)
            await db.flush()
            user = User(
                email=self.email,
                hashed_password=password_hash,
                is_active=True,
                is_superuser=True,
                is_verified=True,
            )
            same_tenant_user = User(
                email=f"integration-session-peer-{uuid4()}@example.com",
                hashed_password=password_hash,
                is_active=True,
                is_superuser=False,
                is_verified=True,
            )
            foreign_user = User(
                email=f"integration-session-foreign-{uuid4()}@example.com",
                hashed_password=password_hash,
                is_active=True,
                is_superuser=False,
                is_verified=True,
                tenant_id=foreign_tenant.id,
            )
            db.add_all([user, same_tenant_user, foreign_user])
            await db.flush()
            db.add(
                RoleAssignment(
                    user_id=user.id,
                    tenant_id=user.tenant_id,
                    role_key=TENANT_ADMIN,
                )
            )
            same_session = await BrowserSessionService(db).create(
                same_tenant_user,
                auth_method="password",
            )
            foreign_session = await BrowserSessionService(db).create(
                foreign_user,
                auth_method="password",
            )
            await db.commit()
            self.user_id = user.id
            self.same_tenant_user_id = same_tenant_user.id
            self.same_tenant_session_id = same_session.row.id
            self.foreign_user_id = foreign_user.id
            self.foreign_session_id = foreign_session.row.id
            self.foreign_tenant_id = foreign_tenant.id

        self.client = httpx.AsyncClient(base_url=self.base_url, timeout=15.0)

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        async with AsyncSessionLocal() as db:
            await db.execute(
                delete(User).where(
                    User.id.in_(
                        [
                            self.user_id,
                            self.same_tenant_user_id,
                            self.foreign_user_id,
                        ]
                    )
                )
            )
            await db.execute(delete(Tenant).where(Tenant.id == self.foreign_tenant_id))
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
        initial_session_id = decode_session_credential(initial_session).session_id

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
                select(AuthSession).where(AuthSession.id == initial_session_id)
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

        # A second device appears in inventory and can be individually revoked.
        async with httpx.AsyncClient(base_url=self.base_url, timeout=15.0) as second:
            second_login = await second.post(
                "/api/v1/auth/login",
                data={"username": self.email, "password": self.password},
            )
            self.assertEqual(second_login.status_code, 200, second_login.text)
            sessions = await self.client.get("/api/v1/auth/sessions")
            self.assertEqual(sessions.status_code, 200, sessions.text)
            session_items = sessions.json()
            self.assertEqual(sum(item["current"] for item in session_items), 1)
            second_id = next(
                item["id"] for item in session_items if not item["current"]
            )

            revoke_second = await self.client.delete(
                f"/api/v1/auth/sessions/{second_id}",
                headers=browser_headers,
            )
            self.assertEqual(revoke_second.status_code, 204, revoke_second.text)
            second_me = await second.get("/api/v1/auth/session/me")
            self.assertEqual(second_me.status_code, 401, second_me.text)

        async with httpx.AsyncClient(base_url=self.base_url, timeout=15.0) as second:
            second_login = await second.post(
                "/api/v1/auth/login",
                data={"username": self.email, "password": self.password},
            )
            self.assertEqual(second_login.status_code, 200, second_login.text)
            revoke_others = await self.client.post(
                "/api/v1/auth/sessions/revoke-others",
                headers=browser_headers,
            )
            self.assertEqual(revoke_others.status_code, 200, revoke_others.text)
            self.assertGreaterEqual(revoke_others.json()["revoked"], 1)
            second_me = await second.get("/api/v1/auth/session/me")
            self.assertEqual(second_me.status_code, 401, second_me.text)

        # Self-service IDs cannot be used to revoke another user's session.
        cross_user = await self.client.delete(
            f"/api/v1/auth/sessions/{self.same_tenant_session_id}",
            headers=browser_headers,
        )
        self.assertEqual(cross_user.status_code, 404, cross_user.text)

        # Current superusers are tenant-confined until issue 17 adds a distinct
        # cross-tenant system-admin permission.
        same_tenant_inventory = await self.client.get(
            f"/api/v1/admin/users/{self.same_tenant_user_id}/sessions"
        )
        self.assertEqual(
            same_tenant_inventory.status_code, 200, same_tenant_inventory.text
        )
        cross_tenant_inventory = await self.client.get(
            f"/api/v1/admin/users/{self.foreign_user_id}/sessions"
        )
        self.assertEqual(
            cross_tenant_inventory.status_code, 404, cross_tenant_inventory.text
        )
        cross_tenant_revoke = await self.client.delete(
            f"/api/v1/admin/users/{self.foreign_user_id}/sessions/{self.foreign_session_id}",
            headers=browser_headers,
        )
        self.assertEqual(cross_tenant_revoke.status_code, 404, cross_tenant_revoke.text)

        admin_revoke = await self.client.delete(
            f"/api/v1/admin/users/{self.same_tenant_user_id}/sessions/"
            f"{self.same_tenant_session_id}",
            headers=browser_headers,
        )
        self.assertEqual(admin_revoke.status_code, 204, admin_revoke.text)

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
                select(AuthSession).where(AuthSession.id == initial_session_id)
            )
            self.assertEqual(replayed_row.revocation_reason, "credential_reuse")

    async def test_current_logout_revokes_server_row_and_clears_cookie(self) -> None:
        login = await self.client.post(
            "/api/v1/auth/login",
            data={"username": self.email, "password": self.password},
        )
        self.assertEqual(login.status_code, 200, login.text)
        csrf_token = login.headers["x-csrf-token"]
        strategy = get_custom_cookie_jwt_strategy()
        credential = self.client.cookies.get(strategy.browser_session_cookie_name)
        session_id = decode_session_credential(credential).session_id

        logout = await self.client.post(
            "/api/v1/auth/session/logout",
            headers={"Origin": self.base_url, "X-CSRF-Token": csrf_token},
        )
        self.assertEqual(logout.status_code, 204, logout.text)
        self.assertIsNone(self.client.cookies.get(strategy.browser_session_cookie_name))
        self.assertIsNone(self.client.cookies.get("SecureCodePlatformRefresh"))
        rejected = await self.client.get("/api/v1/auth/session/me")
        self.assertEqual(rejected.status_code, 401, rejected.text)

        async with AsyncSessionLocal() as db:
            row = await db.get(AuthSession, session_id)
            self.assertEqual(row.revocation_reason, "user_logout")


if __name__ == "__main__":
    unittest.main()
