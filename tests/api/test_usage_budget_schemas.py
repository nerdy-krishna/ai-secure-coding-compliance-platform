from __future__ import annotations

import unittest
from decimal import Decimal
from uuid import uuid4

from pydantic import ValidationError

from app.api.v1.schemas.usage_budgets import BudgetCaps, UsageBudgetPolicyCreate


class UsageBudgetSchemaTests(unittest.TestCase):
    def test_policy_defaults_to_utc_calendar_warning_thresholds(self) -> None:
        policy = UsageBudgetPolicyCreate(
            scope="tenant",
            window="month",
            caps=BudgetCaps(usd=Decimal("125.50")),
            reason="Monthly tenant allowance",
        )

        self.assertEqual(policy.soft_thresholds, (80, 95))
        self.assertEqual(policy.unknown_price_action, "deny")

    def test_scope_target_must_match_scope_kind(self) -> None:
        with self.assertRaises(ValidationError):
            UsageBudgetPolicyCreate(
                scope="group",
                window="day",
                caps=BudgetCaps(total_tokens=10_000),
                reason="Bound one tenant group",
            )

        with self.assertRaises(ValidationError):
            UsageBudgetPolicyCreate(
                scope="tenant",
                group_id=uuid4(),
                window="day",
                caps=BudgetCaps(total_tokens=10_000),
                reason="Invalid tenant target",
            )

    def test_token_only_unknown_price_requires_finite_token_cap(self) -> None:
        with self.assertRaises(ValidationError):
            UsageBudgetPolicyCreate(
                scope="user",
                user_id=42,
                window="request",
                caps=BudgetCaps(usd=Decimal("1.00")),
                unknown_price_action="token_only",
                reason="Permit unknown token pricing",
            )

        policy = UsageBudgetPolicyCreate(
            scope="user",
            user_id=42,
            window="request",
            caps=BudgetCaps(total_tokens=5_000, usd=Decimal("1.00")),
            unknown_price_action="token_only",
            reason="Permit bounded token fallback",
        )
        self.assertEqual(policy.unknown_price_action, "token_only")

    def test_thresholds_are_strictly_increasing_percentages(self) -> None:
        for thresholds in ((95, 80), (80, 80), (0, 95), (80, 100)):
            with self.subTest(thresholds=thresholds), self.assertRaises(
                ValidationError
            ):
                UsageBudgetPolicyCreate(
                    scope="tenant",
                    window="day",
                    caps=BudgetCaps(input_tokens=10_000),
                    soft_thresholds=thresholds,
                    reason="Invalid warning thresholds",
                )


if __name__ == "__main__":
    unittest.main()
