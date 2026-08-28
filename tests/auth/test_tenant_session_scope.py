from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

from app.api.v1.dependencies import get_current_user_tenant_id
from app.infrastructure.database.tenant_context import DEFAULT_TENANT_ID
from app.shared.lib.permissions import PLATFORM_OWNER


class TenantSessionScopeTests(unittest.IsolatedAsyncioTestCase):
    async def _resolve(self, *, active_tenant_id=None):
        home_tenant_id = uuid4()
        user = SimpleNamespace(id=17, tenant_id=home_tenant_id)
        request = SimpleNamespace(
            headers={},
            cookies={},
            state=SimpleNamespace(active_tenant_id=active_tenant_id),
        )
        repo = SimpleNamespace(
            role_keys_for_user=AsyncMock(return_value={PLATFORM_OWNER}),
            db=SimpleNamespace(
                scalar=AsyncMock(return_value=active_tenant_id or DEFAULT_TENANT_ID),
                execute=AsyncMock(),
            ),
        )
        dependency = get_current_user_tenant_id(request, user, repo)
        try:
            return await anext(dependency)
        finally:
            await dependency.aclose()

    async def test_platform_owner_defaults_to_default_tenant(self) -> None:
        self.assertEqual(await self._resolve(), DEFAULT_TENANT_ID)

    async def test_platform_owner_reuses_session_selected_tenant(self) -> None:
        selected_tenant_id = uuid4()
        self.assertEqual(
            await self._resolve(active_tenant_id=selected_tenant_id),
            selected_tenant_id,
        )
