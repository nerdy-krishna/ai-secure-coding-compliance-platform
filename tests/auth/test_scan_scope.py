"""Unit contracts for permission-aware scan owner scope."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

from app.shared.lib.scan_scope import visible_user_ids


class ScanScopeTests(unittest.IsolatedAsyncioTestCase):
    async def test_resource_scope_contains_caller_and_sorted_group_peers(self) -> None:
        user = SimpleNamespace(id=7, is_superuser=True)
        repo = SimpleNamespace(get_peer_user_ids=AsyncMock(return_value={12, 9}))
        tenant_id = uuid4()

        visible = await visible_user_ids(user, repo, tenant_id=tenant_id)

        self.assertEqual(visible, [7, 9, 12])
        repo.get_peer_user_ids.assert_awaited_once_with(7, tenant_id=tenant_id)

    async def test_tenant_wide_permission_skips_only_owner_filter(self) -> None:
        user = SimpleNamespace(id=7, is_superuser=False)
        repo = SimpleNamespace(get_peer_user_ids=AsyncMock())

        visible = await visible_user_ids(
            user,
            repo,
            tenant_id=uuid4(),
            tenant_wide=True,
        )

        self.assertIsNone(visible)
        repo.get_peer_user_ids.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
