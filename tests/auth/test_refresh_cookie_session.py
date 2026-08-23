"""Regression tests for the browser session issued by password login."""

from __future__ import annotations

import unittest
from http.cookies import SimpleCookie
from types import SimpleNamespace

import jwt

from app.infrastructure.auth.backend import (
    auth_backend,
    get_custom_cookie_jwt_strategy,
)


class PasswordSessionTests(unittest.IsolatedAsyncioTestCase):
    async def test_password_login_issues_typed_http_only_refresh_cookie(self) -> None:
        strategy = get_custom_cookie_jwt_strategy()
        user = SimpleNamespace(id=42)

        response = await auth_backend.login(strategy, user)

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
