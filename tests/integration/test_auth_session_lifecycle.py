"""Real-PostgreSQL contracts for browser-session rotation and expiry."""

from __future__ import annotations

import asyncio
import unittest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi_users.password import PasswordHelper
from sqlalchemy import delete

from app.infrastructure.auth.session import (
    BrowserSessionService,
    InvalidSessionCredential,
    SessionExpired,
    SessionLimitExceeded,
    SessionPolicy,
    SessionReuseDetected,
    provider_session_digest,
)
from app.infrastructure.auth.sso.repository import SsoProviderRepository
from app.infrastructure.auth.db import get_user_db
from app.infrastructure.auth.manager import UserManager
from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.models import AuthSession, SsoProvider, Tenant, User
from app.infrastructure.database.repositories.auth_session_repo import (
    AuthSessionRepository,
)
from tests.integration.support import integration_test


@integration_test
class AuthSessionLifecycleIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.email = f"integration-browser-session-{uuid4()}@example.com"
        async with AsyncSessionLocal() as db:
            user = User(
                email=self.email,
                hashed_password=PasswordHelper().hash(f"A7!{uuid4()}z"),
                is_active=True,
                is_superuser=False,
                is_verified=True,
            )
            db.add(user)
            await db.commit()
            self.user_id = user.id

    async def asyncTearDown(self) -> None:
        async with AsyncSessionLocal() as db:
            await db.execute(delete(User).where(User.id == self.user_id))
            await db.commit()
        await engine.dispose()

    async def _issue(
        self,
        *,
        policy: SessionPolicy | None = None,
        now: datetime | None = None,
    ):
        async with AsyncSessionLocal() as db:
            user = await db.get(User, self.user_id)
            self.assertIsNotNone(user)
            issued = await BrowserSessionService(db, policy=policy).create(
                user,
                auth_method="password",
                now=now or datetime(2026, 8, 23, tzinfo=timezone.utc),
            )
            await db.commit()
            return issued.row.id, issued.credential

    async def test_valid_tampering_does_not_revoke_the_session(self) -> None:
        session_id, credential = await self._issue()
        parts = credential.split(".")
        parts[1] = uuid4().hex

        async with AsyncSessionLocal() as db:
            with self.assertRaises(InvalidSessionCredential):
                await BrowserSessionService(db).authenticate(".".join(parts))
            row = await db.get(AuthSession, session_id)
            self.assertIsNone(row.revoked_at)

    async def test_rotation_then_prior_generation_reuse_revokes_family(self) -> None:
        session_id, credential = await self._issue()
        rotated_at = datetime(2026, 8, 23, 0, 5, tzinfo=timezone.utc)

        async with AsyncSessionLocal() as db:
            rotated = await BrowserSessionService(db).rotate(credential, now=rotated_at)
            await db.commit()
        self.assertNotEqual(rotated.credential, credential)
        self.assertEqual(rotated.row.credential_generation, 1)

        async with AsyncSessionLocal() as db:
            with self.assertRaises(SessionReuseDetected):
                await BrowserSessionService(db).rotate(
                    credential,
                    now=rotated_at + timedelta(seconds=1),
                )
            await db.commit()

        async with AsyncSessionLocal() as db:
            row = await db.get(AuthSession, session_id)
            self.assertIsNotNone(row.revoked_at)
            self.assertEqual(row.revocation_reason, "credential_reuse")

    async def test_concurrent_rotation_has_one_winner_and_detects_reuse(self) -> None:
        session_id, credential = await self._issue()
        rotate_at = datetime(2026, 8, 23, 0, 5, tzinfo=timezone.utc)

        async def rotate_once() -> str:
            async with AsyncSessionLocal() as db:
                try:
                    await BrowserSessionService(db).rotate(credential, now=rotate_at)
                except SessionReuseDetected:
                    await db.commit()
                    return "reuse"
                await db.commit()
                return "rotated"

        outcomes = await asyncio.gather(rotate_once(), rotate_once())
        self.assertCountEqual(outcomes, ["rotated", "reuse"])

        async with AsyncSessionLocal() as db:
            row = await db.get(AuthSession, session_id)
            self.assertIsNotNone(row.revoked_at)
            self.assertEqual(row.revocation_reason, "credential_reuse")

    async def test_idle_activity_extends_only_to_absolute_deadline(self) -> None:
        policy = SessionPolicy(
            idle_seconds=60,
            absolute_seconds=120,
            touch_interval_seconds=10,
        )
        session_id, credential = await self._issue(policy=policy)
        issued_at = datetime(2026, 8, 23, tzinfo=timezone.utc)

        async with AsyncSessionLocal() as db:
            row = await BrowserSessionService(db, policy=policy).authenticate(
                credential,
                now=issued_at + timedelta(seconds=30),
            )
            await db.commit()
            self.assertEqual(row.idle_expires_at, issued_at + timedelta(seconds=90))
            self.assertEqual(
                row.absolute_expires_at, issued_at + timedelta(seconds=120)
            )

        async with AsyncSessionLocal() as db:
            with self.assertRaises(SessionExpired):
                await BrowserSessionService(db, policy=policy).authenticate(
                    credential,
                    now=issued_at + timedelta(seconds=121),
                )
            await db.commit()

        async with AsyncSessionLocal() as db:
            row = await db.get(AuthSession, session_id)
            self.assertEqual(row.revocation_reason, "absolute_timeout")

    async def test_revoke_all_is_idempotent_and_does_not_touch_other_users(
        self,
    ) -> None:
        await self._issue()
        await self._issue()
        other_email = f"integration-browser-session-other-{uuid4()}@example.com"
        async with AsyncSessionLocal() as db:
            other = User(
                email=other_email,
                hashed_password=PasswordHelper().hash(f"A7!{uuid4()}z"),
                is_active=True,
                is_superuser=False,
                is_verified=True,
            )
            db.add(other)
            await db.flush()
            unrelated = await BrowserSessionService(db).create(
                other,
                auth_method="password",
            )
            other_id = other.id
            await db.commit()

        try:
            async with AsyncSessionLocal() as db:
                repo = AuthSessionRepository(db)
                first = await repo.revoke_all_for_user(
                    self.user_id,
                    reason="test_revoke_all",
                )
                second = await repo.revoke_all_for_user(
                    self.user_id,
                    reason="test_revoke_all",
                )
                await db.commit()
            self.assertEqual(first, 2)
            self.assertEqual(second, 0)

            async with AsyncSessionLocal() as db:
                row = await BrowserSessionService(db).authenticate(unrelated.credential)
                self.assertEqual(row.user_id, other_id)
        finally:
            async with AsyncSessionLocal() as db:
                await db.execute(delete(User).where(User.id == other_id))
                await db.commit()

    async def test_confirmed_password_reset_revokes_every_browser_session(
        self,
    ) -> None:
        first_id, _ = await self._issue()
        second_id, _ = await self._issue()

        async with AsyncSessionLocal() as db:
            user = await db.get(User, self.user_id)
            user_db_gen = get_user_db(db)
            user_db = await user_db_gen.__anext__()
            try:
                await UserManager(user_db).on_after_reset_password(user)
            finally:
                await user_db_gen.aclose()

        async with AsyncSessionLocal() as db:
            first = await db.get(AuthSession, first_id)
            second = await db.get(AuthSession, second_id)
            self.assertEqual(first.revocation_reason, "password_reset")
            self.assertEqual(second.revocation_reason, "password_reset")

    async def test_provider_logout_revokes_only_the_matching_remote_session(
        self,
    ) -> None:
        async with AsyncSessionLocal() as db:
            provider = await SsoProviderRepository(db).create(
                name=f"integration-oidc-{uuid4().hex[:12]}",
                display_name="Integration OIDC",
                protocol="oidc",
                config_plain={
                    "issuer_url": "https://idp.example.test",
                    "client_id": "integration-client",
                    "client_secret": "integration-secret",
                },
            )
            user = await db.get(User, self.user_id)
            matching = await BrowserSessionService(db).create(
                user,
                auth_method="oidc",
                provider_id=provider.id,
                provider_session_id="remote-session-a",
            )
            unrelated = await BrowserSessionService(db).create(
                user,
                auth_method="oidc",
                provider_id=provider.id,
                provider_session_id="remote-session-b",
            )
            provider_id = provider.id
            await db.commit()

        try:
            async with AsyncSessionLocal() as db:
                revoked = await AuthSessionRepository(db).revoke_for_provider_session(
                    provider_id,
                    provider_session_digest("remote-session-a") or "",
                    reason="oidc_backchannel_logout",
                )
                await db.commit()
            self.assertEqual(revoked, 1)

            async with AsyncSessionLocal() as db:
                matching_row = await db.get(AuthSession, matching.row.id)
                unrelated_row = await db.get(AuthSession, unrelated.row.id)
                self.assertEqual(
                    matching_row.revocation_reason,
                    "oidc_backchannel_logout",
                )
                self.assertIsNone(unrelated_row.revoked_at)
        finally:
            async with AsyncSessionLocal() as db:
                provider = await db.get(SsoProvider, provider_id)
                if provider is not None:
                    await db.delete(provider)
                await db.commit()

    async def test_concurrency_limit_denies_new_session_by_default(self) -> None:
        async with AsyncSessionLocal() as db:
            tenant = Tenant(
                slug=f"session-limit-{uuid4()}",
                display_name="Session Limit",
                session_concurrency_limit=1,
                session_concurrency_mode="deny_new",
            )
            db.add(tenant)
            await db.flush()
            user = await db.get(User, self.user_id)
            user.tenant_id = tenant.id
            tenant_id = tenant.id
            await db.commit()
        try:
            login_at = datetime.now(timezone.utc)
            first_id, _ = await self._issue(now=login_at)
            with self.assertRaises(SessionLimitExceeded):
                await self._issue(now=login_at + timedelta(seconds=1))
            async with AsyncSessionLocal() as db:
                first = await db.get(AuthSession, first_id)
                self.assertIsNone(first.revoked_at)
        finally:
            async with AsyncSessionLocal() as db:
                user = await db.get(User, self.user_id)
                user.tenant_id = None
                await db.execute(delete(Tenant).where(Tenant.id == tenant_id))
                await db.commit()

    async def test_concurrency_limit_can_explicitly_revoke_oldest(self) -> None:
        async with AsyncSessionLocal() as db:
            tenant = Tenant(
                slug=f"session-oldest-{uuid4()}",
                display_name="Session Oldest",
                session_concurrency_limit=1,
                session_concurrency_mode="revoke_oldest",
            )
            db.add(tenant)
            await db.flush()
            user = await db.get(User, self.user_id)
            user.tenant_id = tenant.id
            tenant_id = tenant.id
            await db.commit()
        try:
            login_at = datetime.now(timezone.utc)
            first_id, _ = await self._issue(now=login_at)
            second_id, _ = await self._issue(now=login_at + timedelta(seconds=1))
            async with AsyncSessionLocal() as db:
                first = await db.get(AuthSession, first_id)
                second = await db.get(AuthSession, second_id)
                self.assertEqual(
                    first.revocation_reason,
                    "concurrency_revoke_oldest",
                )
                self.assertIsNone(second.revoked_at)
        finally:
            async with AsyncSessionLocal() as db:
                user = await db.get(User, self.user_id)
                user.tenant_id = None
                await db.execute(delete(Tenant).where(Tenant.id == tenant_id))
                await db.commit()

    async def test_concurrent_login_limit_has_exactly_one_winner(self) -> None:
        async with AsyncSessionLocal() as db:
            tenant = Tenant(
                slug=f"session-race-{uuid4()}",
                display_name="Session Race",
                session_concurrency_limit=1,
                session_concurrency_mode="deny_new",
            )
            db.add(tenant)
            await db.flush()
            user = await db.get(User, self.user_id)
            user.tenant_id = tenant.id
            tenant_id = tenant.id
            await db.commit()

        async def login_once() -> str:
            async with AsyncSessionLocal() as db:
                user = await db.get(User, self.user_id)
                try:
                    await BrowserSessionService(db).create(
                        user,
                        auth_method="password",
                    )
                except SessionLimitExceeded:
                    await db.rollback()
                    return "denied"
                await db.commit()
                return "created"

        try:
            outcomes = await asyncio.gather(login_once(), login_once())
            self.assertCountEqual(outcomes, ["created", "denied"])
            async with AsyncSessionLocal() as db:
                active = await AuthSessionRepository(db).list_for_user(self.user_id)
                self.assertEqual(len(active), 1)
        finally:
            async with AsyncSessionLocal() as db:
                user = await db.get(User, self.user_id)
                user.tenant_id = None
                await db.execute(delete(Tenant).where(Tenant.id == tenant_id))
                await db.commit()


if __name__ == "__main__":
    unittest.main()
