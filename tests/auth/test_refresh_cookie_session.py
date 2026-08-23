"""Regression tests for the browser session issued by password login."""

from __future__ import annotations

import unittest
from http.cookies import SimpleCookie
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import jwt
from fastapi import Response

from app.infrastructure.auth.backend import (
    auth_backend,
    get_custom_cookie_jwt_strategy,
)


class PasswordSessionTests(unittest.IsolatedAsyncioTestCase):
    async def test_password_login_issues_typed_http_only_refresh_cookie(self) -> None:
        strategy = get_custom_cookie_jwt_strategy()
        user = SimpleNamespace(id=42)

        with patch.object(
            strategy,
            "issue_stateful_browser_session",
            new=AsyncMock(),
        ) as issue_stateful:
            response = await auth_backend.login(strategy, user)
        issue_stateful.assert_awaited_once()

        cookie = SimpleCookie()
        cookie.load(response.headers.get("set-cookie", ""))
        self.assertIn(strategy.cookie_name, cookie)
        morsel = cookie[strategy.cookie_name]
        self.assertTrue(morsel["httponly"])
        self.assertEqual(morsel["path"], "/")
        self.assertEqual(bool(morsel["secure"]), strategy.cookie_secure)

        payload = jwt.decode(
            morsel.value,
            strategy.decode_key,
            algorithms=[strategy.algorithm],
            audience="fastapi-users:auth",
        )
        self.assertEqual(payload["sub"], "42")
        self.assertEqual(payload["typ"], "refresh")
        self.assertIsInstance(payload["original_iat"], int)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.headers["pragma"], "no-cache")

    async def test_stateful_browser_cookie_uses_host_prefix_only_when_secure(
        self,
    ) -> None:
        strategy = get_custom_cookie_jwt_strategy()
        response = Response()

        await strategy.write_browser_session(response, "opaque-credential")

        cookie = SimpleCookie()
        for value in response.headers.getlist("set-cookie"):
            cookie.load(value)
        self.assertIn(strategy.browser_session_cookie_name, cookie)
        morsel = cookie[strategy.browser_session_cookie_name]
        self.assertTrue(morsel["httponly"])
        self.assertEqual(morsel["path"], "/")
        self.assertEqual(bool(morsel["secure"]), strategy.cookie_secure)
        if strategy.cookie_secure:
            self.assertTrue(strategy.browser_session_cookie_name.startswith("__Host-"))
        else:
            self.assertFalse(strategy.browser_session_cookie_name.startswith("__Host-"))

    async def test_logout_expires_refresh_cookie(self) -> None:
        strategy = get_custom_cookie_jwt_strategy()
        user = SimpleNamespace(id=42)

        response = await auth_backend.logout(strategy, user, "access-token")

        cookie = SimpleCookie()
        cookie.load(response.headers.get("set-cookie", ""))
        self.assertIn(strategy.cookie_name, cookie)
        self.assertEqual(cookie[strategy.cookie_name]["max-age"], "0")
        self.assertEqual(
            response.headers["clear-site-data"], '"cache", "cookies", "storage"'
        )
        self.assertEqual(response.headers["cache-control"], "no-store")


if __name__ == "__main__":
    unittest.main()
