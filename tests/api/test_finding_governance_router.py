from __future__ import annotations

import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1.dependencies import (
    get_current_permissions,
    get_current_user_tenant_id,
    get_visible_user_ids,
)
from app.api.v1.routers.finding_governance import router, service
from app.api.v1.schemas.finding_governance import FindingLineageListResponse
from app.infrastructure.auth.core import current_active_user


class FindingGovernanceRouterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tenant_id = uuid4()
        self.user = SimpleNamespace(id=9, tenant_id=self.tenant_id)
        self.scan_id = uuid4()
        self.svc = SimpleNamespace(
            lineage=AsyncMock(
                return_value=FindingLineageListResponse(
                    scan_id=self.scan_id,
                    counts={"new": 1, "fixed": 0, "unchanged": 0, "reintroduced": 0},
                    items=[],
                )
            ),
            grant_waiver=AsyncMock(),
        )
        app = FastAPI()
        app.include_router(router, prefix="/api/v1")
        app.dependency_overrides[get_current_user_tenant_id] = lambda: self.tenant_id
        app.dependency_overrides[get_visible_user_ids] = lambda: [9]
        app.dependency_overrides[current_active_user] = lambda: self.user
        app.dependency_overrides[get_current_permissions] = lambda: frozenset()
        app.dependency_overrides[service] = lambda: self.svc
        self.app = app
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()

    def test_read_passes_visibility_scope(self) -> None:
        response = self.client.get(
            f"/api/v1/finding-governance/scans/{self.scan_id}/findings"
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.svc.lineage.assert_awaited_once_with(
            self.scan_id,
            tenant_id=self.tenant_id,
            visible_user_ids=[9],
        )

    def test_direct_waiver_requires_approver_permission(self) -> None:
        response = self.client.post(
            f"/api/v1/finding-governance/scans/{self.scan_id}/findings/12/waivers",
            json={
                "scope": "finding",
                "reason": "Temporary accepted exception",
                "expires_at": datetime(2027, 1, 1, tzinfo=timezone.utc).isoformat(),
            },
        )
        self.assertEqual(response.status_code, 403, response.text)
        self.svc.grant_waiver.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
