"""Regression tests for list/detail visibility parity on shared scans."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from uuid import uuid4

from app.shared.lib.scan_visibility import can_view_scan


class ScanDetailVisibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tenant_id = uuid4()
        self.other_tenant_id = uuid4()
        self.user = SimpleNamespace(id=10, is_superuser=False)

    def test_group_peer_can_read_detail_inside_tenant(self) -> None:
        scan = SimpleNamespace(user_id=20, tenant_id=self.tenant_id)
        self.assertTrue(
            can_view_scan(
                scan,
                self.user,
                visible_user_ids=[10, 20],
                tenant_id=self.tenant_id,
            )
        )

    def test_cross_tenant_peer_is_denied_even_if_owner_id_is_visible(self) -> None:
        scan = SimpleNamespace(user_id=20, tenant_id=self.other_tenant_id)
        self.assertFalse(
            can_view_scan(
                scan,
                self.user,
                visible_user_ids=[10, 20],
                tenant_id=self.tenant_id,
            )
        )

    def test_missing_explicit_scope_defaults_to_owner_only(self) -> None:
        peer_scan = SimpleNamespace(user_id=20, tenant_id=self.tenant_id)
        own_scan = SimpleNamespace(user_id=10, tenant_id=self.tenant_id)
        self.assertFalse(can_view_scan(peer_scan, self.user))
        self.assertTrue(can_view_scan(own_scan, self.user))

    def test_platform_owner_has_no_cross_tenant_bypass(self) -> None:
        admin = SimpleNamespace(id=1, is_superuser=True)
        scan = SimpleNamespace(user_id=20, tenant_id=self.other_tenant_id)
        self.assertFalse(can_view_scan(scan, admin, tenant_id=self.tenant_id))

    def test_tenant_wide_scope_reads_any_owner_only_in_selected_tenant(self) -> None:
        same_tenant = SimpleNamespace(user_id=20, tenant_id=self.tenant_id)
        other_tenant = SimpleNamespace(user_id=20, tenant_id=self.other_tenant_id)
        self.assertTrue(can_view_scan(same_tenant, self.user, tenant_id=self.tenant_id))
        self.assertFalse(can_view_scan(other_tenant, self.user, tenant_id=self.tenant_id))


if __name__ == "__main__":
    unittest.main()
