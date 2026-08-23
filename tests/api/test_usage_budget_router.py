from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1.dependencies import (
    get_current_permissions,
    get_current_user_tenant_id,
)
from app.api.v1.routers.admin_usage_budgets import _budget_repo, router
from app.shared.lib.permissions import AUDIT_READ


class UsageBudgetRouterAuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tenant_id = uuid4()
        self.repo = SimpleNamespace(list_policies=AsyncMock(return_value=[]))
        self.app = FastAPI()
        self.app.include_router(router, prefix="/api/v1")
        self.app.dependency_overrides[get_current_user_tenant_id] = (
            lambda: self.tenant_id
        )
        self.app.dependency_overrides[_budget_repo] = lambda: self.repo
        self.client = TestClient(self.app)

    def tearDown(self) -> None:
        self.client.close()

    def test_auditor_can_read_active_tenant_policies(self) -> None:
        self.app.dependency_overrides[get_current_permissions] = lambda: frozenset(
            {AUDIT_READ}
        )

        response = self.client.get("/api/v1/admin/usage-budgets/policies")

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), [])
        self.repo.list_policies.assert_awaited_once_with(
            tenant_id=self.tenant_id, include_disabled=False
        )

    def test_principal_without_audit_permission_cannot_read_budgets(self) -> None:
        self.app.dependency_overrides[get_current_permissions] = lambda: frozenset()

        response = self.client.get("/api/v1/admin/usage-budgets/policies")

        self.assertEqual(response.status_code, 403, response.text)
        self.repo.list_policies.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
