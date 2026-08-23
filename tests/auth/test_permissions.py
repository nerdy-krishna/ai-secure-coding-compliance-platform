import unittest

from app.shared.lib.permissions import (
    ALL_PERMISSION_KEYS,
    ANALYST,
    AUDITOR,
    DEVELOPER,
    IDENTITY_MANAGE,
    PLATFORM_OWNER,
    SCAN_APPROVE,
    SCAN_APPROVE_SELF,
    SECURITY_APPROVER,
    TENANT_ADMIN,
    permissions_for_roles,
)


class PermissionMatrixTests(unittest.TestCase):
    def test_platform_owner_has_every_builtin_permission(self) -> None:
        self.assertEqual(permissions_for_roles([PLATFORM_OWNER]), ALL_PERMISSION_KEYS)

    def test_scan_approval_and_identity_duties_are_separated(self) -> None:
        tenant_admin = permissions_for_roles([TENANT_ADMIN])
        security_approver = permissions_for_roles([SECURITY_APPROVER])
        developer = permissions_for_roles([DEVELOPER])

        self.assertIn(IDENTITY_MANAGE, tenant_admin)
        self.assertNotIn(SCAN_APPROVE, tenant_admin)
        self.assertIn(SCAN_APPROVE, security_approver)
        self.assertNotIn(IDENTITY_MANAGE, security_approver)
        self.assertIn(SCAN_APPROVE_SELF, developer)
        self.assertNotIn(SCAN_APPROVE, developer)

    def test_multiple_roles_union_and_unknown_roles_fail_closed(self) -> None:
        combined = permissions_for_roles([ANALYST, AUDITOR, "future_unknown_role"])
        self.assertGreater(len(combined), 0)
        self.assertEqual(
            combined,
            permissions_for_roles([ANALYST]) | permissions_for_roles([AUDITOR]),
        )
        self.assertEqual(permissions_for_roles(["future_unknown_role"]), frozenset())
