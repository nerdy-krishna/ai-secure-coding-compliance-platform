from __future__ import annotations

import unittest
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

from app.core.services.usage_budget_service import (
    BUDGET_HARD_LIMIT_EXCEEDED,
    BUDGET_PRICE_UNKNOWN,
    BudgetExceededError,
    UsageBudgetService,
)
from app.infrastructure.database.repositories.llm_usage_repo import LLMUsageContext
from app.infrastructure.database.repositories.usage_budget_repo import (
    BudgetAttribution,
    BudgetDenial,
    BudgetReservationDecision,
)


def _context() -> LLMUsageContext:
    operation_id = uuid4()
    return LLMUsageContext(
        operation_kind="chat",
        operation_id=str(operation_id),
        chat_session_id=operation_id,
        stage="chat_response",
        agent_name="chat",
        idempotency_key=f"chat:{operation_id}",
        actor_user_id=42,
    )


class UsageBudgetServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.repo = SimpleNamespace(
            resolve_attribution=AsyncMock(
                return_value=BudgetAttribution(uuid4(), 42, (), None)
            ),
            list_active_policies=AsyncMock(return_value=[]),
            reserve=AsyncMock(),
            settle=AsyncMock(),
            release=AsyncMock(return_value=True),
            mark_accounting_unknown=AsyncMock(return_value=True),
            ensure_default_scan_policy=AsyncMock(),
            record_denial=AsyncMock(),
        )
        self.service = UsageBudgetService(self.repo)

    async def test_no_applicable_policy_is_a_noop(self) -> None:
        result = await self.service.reserve_logical_call(
            _context(), uuid4(), {"input_tokens": 10}, None
        )

        self.assertIsNone(result)
        self.repo.reserve.assert_not_awaited()

    async def test_unknown_price_fails_closed_for_monetary_policy(self) -> None:
        policy_id = uuid4()
        self.repo.list_active_policies.return_value = [
            SimpleNamespace(
                id=policy_id,
                cap_usd=Decimal("5"),
                unknown_price_action="deny",
                scope_kind="tenant",
                window_kind="month",
            )
        ]

        with self.assertRaises(BudgetExceededError) as raised:
            await self.service.reserve_logical_call(
                _context(), uuid4(), {"input_tokens": 10}, None
            )

        self.assertEqual(raised.exception.code, BUDGET_PRICE_UNKNOWN)
        self.assertEqual(raised.exception.snapshot.policy_id, policy_id)
        self.repo.reserve.assert_not_awaited()
        self.repo.record_denial.assert_awaited_once()

    async def test_repository_denial_becomes_stable_error(self) -> None:
        policy_id = uuid4()
        self.repo.list_active_policies.return_value = [
            SimpleNamespace(
                id=policy_id,
                cap_usd=None,
                unknown_price_action="deny",
                scope_kind="group",
                window_kind="day",
            )
        ]
        self.repo.reserve.return_value = BudgetReservationDecision(
            allowed=False,
            denial=BudgetDenial(
                policy_id=policy_id,
                scope_kind="group",
                window_kind="day",
                dimension="total_tokens",
                remaining=100,
                requested=120,
                reset_at=None,
            ),
        )

        with self.assertRaises(BudgetExceededError) as raised:
            await self.service.reserve_logical_call(
                _context(),
                uuid4(),
                {"upper_bound_input_tokens": 80, "upper_bound_output_tokens": 40},
                object(),
            )

        self.assertEqual(raised.exception.code, BUDGET_HARD_LIMIT_EXCEEDED)
        self.assertEqual(raised.exception.snapshot.requested, 120)
        request = self.repo.reserve.await_args.args[0]
        self.assertEqual(request.estimate.total_tokens, 120)
        self.assertEqual(request.estimate.uncached_input_tokens, 80)

    async def test_provider_call_without_ledger_event_never_releases_hold(self) -> None:
        reservation_id = uuid4()

        await self.service.settle_logical_call(
            reservation_id, None, provider_called=True
        )

        self.repo.mark_accounting_unknown.assert_awaited_once()
        self.repo.release.assert_not_awaited()

    async def test_failure_before_provider_releases_hold(self) -> None:
        reservation_id = uuid4()

        await self.service.settle_logical_call(
            reservation_id, None, provider_called=False
        )

        self.repo.release.assert_awaited_once_with(
            reservation_id, "provider_not_called", commit=True
        )
        self.repo.mark_accounting_unknown.assert_not_awaited()

    async def test_scan_gate_uses_attempt_identity_and_non_request_windows(self) -> None:
        scan_id = uuid4()
        attempt_id = uuid4()
        reservation_id = uuid4()
        tenant_id = uuid4()
        self.repo.resolve_attribution.return_value = BudgetAttribution(
            tenant_id, 42, (), attempt_id
        )
        self.repo.list_active_policies.return_value = [
            SimpleNamespace(
                id=uuid4(),
                cap_usd=Decimal("100"),
                unknown_price_action="deny",
                scope_kind="tenant",
                window_kind="scan",
            )
        ]
        self.repo.reserve.return_value = BudgetReservationDecision(
            allowed=True,
            reservation=SimpleNamespace(id=reservation_id),
        )

        result = await self.service.reserve_scan_gate(
            scan_id,
            "cost_approval",
            {
                "upper_bound_input_tokens": 100,
                "upper_bound_output_tokens": 20,
                "upper_bound_estimated_cost": "1.25",
            },
            actor_user_id=42,
        )

        self.assertEqual(result, reservation_id)
        self.repo.ensure_default_scan_policy.assert_awaited_once_with(
            tenant_id=tenant_id,
            created_by_user_id=42,
            commit=False,
        )
        request = self.repo.reserve.await_args.args[0]
        self.assertIn(str(attempt_id), request.idempotency_key)
        self.assertEqual(request.stage, "analysis")
        self.assertEqual(request.llm_config_id, None)
        self.assertEqual(request.window_kinds, ("scan", "day", "month"))
        self.assertEqual(request.estimate.usd, Decimal("1.25"))
        self.assertEqual(self.repo.reserve.await_args.kwargs, {"commit": False})


if __name__ == "__main__":
    unittest.main()
