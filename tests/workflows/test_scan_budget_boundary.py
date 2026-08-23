"""Focused contracts for scan-side budget denial propagation."""

from __future__ import annotations

import unittest
import uuid
from decimal import Decimal
from unittest.mock import AsyncMock, patch

from app.core.services.usage_budget_service import (
    BudgetExceededError,
    BudgetFailureSnapshot,
)
from app.infrastructure.agents.file_profiler import FileProfiler
from app.infrastructure.workflows.budget import (
    ScanBudgetExhausted,
    raise_first_budget_denial,
    scan_gate_estimate,
)
from app.infrastructure.workflows.cancellation import cancellation_aware


def _denial() -> BudgetExceededError:
    return BudgetExceededError(
        snapshot=BudgetFailureSnapshot(
            policy_id=uuid.uuid4(),
            scope="tenant",
            dimension="usd",
            window="scan",
            remaining=Decimal("0.10"),
            requested=Decimal("0.25"),
        )
    )


class ScanBudgetValueTests(unittest.TestCase):
    def test_gate_estimate_uses_conservative_dimensions(self) -> None:
        estimate = scan_gate_estimate(
            {
                "upper_bound_input_tokens": 100,
                "upper_bound_output_tokens": 40,
                "upper_bound_estimated_cost": "1.25000000",
                "upper_bound_request_count": 3,
            }
        )

        self.assertEqual(estimate.input_tokens, 100)
        self.assertEqual(estimate.output_tokens, 40)
        self.assertEqual(estimate.total_tokens, 140)
        self.assertEqual(estimate.uncached_input_tokens, 100)
        self.assertEqual(estimate.billable_tokens, 140)
        self.assertEqual(estimate.usd, Decimal("1.25000000"))
        self.assertEqual(estimate.provider_requests, 3)

    def test_parallel_result_denial_is_not_degraded_to_an_ordinary_error(self) -> None:
        denial = _denial()

        with self.assertRaises(BudgetExceededError) as raised:
            raise_first_budget_denial([RuntimeError("provider unavailable"), denial])

        self.assertIs(raised.exception, denial)


class ScanBudgetAsyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_file_profiler_re_raises_budget_denial(self) -> None:
        denial = _denial()
        client = AsyncMock()
        client.generate_structured_output.side_effect = denial
        profiler = FileProfiler(
            client,
            scan_id=uuid.uuid4(),
            llm_config_id=uuid.uuid4(),
        )

        with self.assertRaises(BudgetExceededError) as raised:
            await profiler.profile_file("src/main.py", "print('ok')", {})

        self.assertIs(raised.exception, denial)

    async def test_graph_boundary_persists_then_raises_terminal_control_signal(
        self,
    ) -> None:
        denial = _denial()

        async def node(_state):
            raise denial

        wrapped = cancellation_aware(node, stage_name="billable_node")
        with (
            patch(
                "app.infrastructure.workflows.cancellation.is_scan_cancelled",
                new=AsyncMock(return_value=False),
            ),
            patch(
                "app.infrastructure.workflows.cancellation.mark_scan_budget_exhausted",
                new=AsyncMock(return_value=True),
            ) as persist,
        ):
            with self.assertRaises(ScanBudgetExhausted):
                await wrapped({"scan_id": uuid.uuid4()})

        persist.assert_awaited_once()
        self.assertIs(persist.await_args.args[1], denial)


if __name__ == "__main__":
    unittest.main()
