from __future__ import annotations

import unittest
from datetime import datetime, timezone
from decimal import Decimal
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
from app.api.v1.routers.usage_center import _service, router
from app.api.v1.schemas.usage_center import UsageTotals
from app.infrastructure.auth.core import current_active_user


class UsageCenterRouterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tenant_id = uuid4()
        self.user = SimpleNamespace(id=7, tenant_id=self.tenant_id)
        self.visibility = SimpleNamespace(
            scope="self",
            visible_user_ids=(7,),
            visible_group_ids=(),
            tenant_wide=False,
        )
        self.repo = SimpleNamespace(list_events=AsyncMock(return_value=[]))
        self.service = SimpleNamespace(
            resolve_visibility=AsyncMock(return_value=self.visibility),
            authorize_query=lambda query, visibility: query,
            summary=AsyncMock(
                return_value=UsageTotals(
                    actual_cost=Decimal("0.123456789012"), unknown_events=1
                )
            ),
            preview_policy=AsyncMock(),
            repo=self.repo,
        )
        self.app = FastAPI()
        self.app.include_router(router, prefix="/api/v1")
        self.app.dependency_overrides[get_current_user_tenant_id] = (
            lambda: self.tenant_id
        )
        self.app.dependency_overrides[current_active_user] = lambda: self.user
        self.app.dependency_overrides[get_current_permissions] = lambda: frozenset()
        self.app.dependency_overrides[get_visible_user_ids] = lambda: [7, 8]
        self.app.dependency_overrides[_service] = lambda: self.service
        self.client = TestClient(self.app)

    def tearDown(self) -> None:
        self.client.close()

    def test_summary_is_authenticated_scoped_and_decimal_exact(self) -> None:
        response = self.client.get(
            "/api/v1/usage/summary",
            params={
                "from_at": "2026-01-01T00:00:00Z",
                "to_at": "2026-01-31T00:00:00Z",
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["scope"], "self")
        self.assertEqual(response.json()["totals"]["actual_cost"], "0.123456789012")
        self.service.resolve_visibility.assert_awaited_once()
        self.service.summary.assert_awaited_once()

    def test_range_is_bounded_to_production_retention_window(self) -> None:
        response = self.client.get(
            "/api/v1/usage/summary",
            params={
                "from_at": "2024-01-01T00:00:00Z",
                "to_at": "2026-01-31T00:00:00Z",
            },
        )
        self.assertEqual(response.status_code, 422)
        self.service.summary.assert_not_awaited()

    def test_export_uses_narrow_contract_without_prompt_or_response(self) -> None:
        event = SimpleNamespace(
            id=uuid4(),
            created_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            operation_kind="chat",
            operation_id=str(uuid4()),
            scan_id=None,
            stage="advisor",
            agent_name="chat_agent",
            user_id=7,
            provider="openai",
            requested_model="gpt-test",
            request_count=1,
            input_tokens=10,
            output_tokens=4,
            total_tokens=14,
            cache_read_tokens=2,
            cache_write_tokens=0,
            reasoning_tokens=0,
            usage_source="provider",
            quality_state="normalized",
            cost_status="unknown",
            currency=None,
            total_cost=None,
            prompt_context="must-not-export",
            raw_response="must-not-export",
        )
        self.repo.list_events.return_value = [event]
        response = self.client.get("/api/v1/usage/export?format=json")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotIn("prompt_context", response.text)
        self.assertNotIn("raw_response", response.text)
        self.assertEqual(response.json()[0]["cost_status"], "unknown")

    def test_policy_preview_requires_policy_management_permission(self) -> None:
        payload = {
            "policy": {
                "scope": "tenant",
                "window": "month",
                "caps": {"usd": "25.000000000000"},
                "reason": "Preview production allowance",
            }
        }
        denied = self.client.post("/api/v1/usage/policy-preview", json=payload)
        self.assertEqual(denied.status_code, 403, denied.text)
        self.service.preview_policy.assert_not_awaited()

        policy_id = uuid4()
        self.app.dependency_overrides[get_current_permissions] = lambda: frozenset(
            {"tenant.policy.manage"}
        )
        self.service.preview_policy.return_value = {
            "candidate_scope": "tenant",
            "matching_policy_ids": [policy_id],
            "precedence": ["user", "group", "tenant"],
            "effective_caps": {"usd": "25.000000000000"},
            "strictest_policy_ids": {"usd": policy_id},
            "warnings": [],
        }
        allowed = self.client.post("/api/v1/usage/policy-preview", json=payload)
        self.assertEqual(allowed.status_code, 200, allowed.text)
        self.assertEqual(allowed.json()["candidate_scope"], "tenant")


if __name__ == "__main__":
    unittest.main()
