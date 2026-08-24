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
from app.api.v1.routers.admin_provider_reconciliation import _repo, router
from app.shared.lib.permissions import AUDIT_READ


class ProviderReconciliationRouterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tenant_id = uuid4()
        self.repo = SimpleNamespace(
            list_connectors=AsyncMock(return_value=[]),
            summary=AsyncMock(return_value=None),
        )
        self.app = FastAPI()
        self.app.include_router(router, prefix="/api/v1")
        self.app.dependency_overrides[get_current_user_tenant_id] = lambda: self.tenant_id
        self.app.dependency_overrides[_repo] = lambda: self.repo
        self.client = TestClient(self.app)

    def tearDown(self) -> None:
        self.client.close()

    def test_auditor_reads_unconfigured_summary(self) -> None:
        self.app.dependency_overrides[get_current_permissions] = lambda: frozenset({AUDIT_READ})
        response = self.client.get("/api/v1/admin/usage-reconciliation/summary")
        self.assertEqual(200, response.status_code, response.text)
        self.assertEqual("not_configured", response.json()["status"])
        self.assertNotIn("credentials", response.text)

    def test_principal_without_audit_read_is_denied(self) -> None:
        self.app.dependency_overrides[get_current_permissions] = lambda: frozenset()
        response = self.client.get("/api/v1/admin/usage-reconciliation/summary")
        self.assertEqual(403, response.status_code, response.text)
        self.repo.summary.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
