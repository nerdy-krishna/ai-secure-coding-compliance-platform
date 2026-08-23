from __future__ import annotations

import unittest
from datetime import datetime, timezone
from decimal import Decimal
from uuid import uuid4

from app.infrastructure.database.repositories.usage_budget_repo import (
    BudgetAmounts,
    utc_window,
)


class BudgetAmountsTests(unittest.TestCase):
    def test_rejects_negative_capacity(self) -> None:
        with self.assertRaisesRegex(ValueError, "input_tokens"):
            BudgetAmounts(input_tokens=-1)

    def test_preserves_fixed_precision_money(self) -> None:
        amount = BudgetAmounts(usd=Decimal("0.123456789012"))
        self.assertEqual(amount.as_model_values("held")["held_usd"], amount.usd)


class UTCBudgetWindowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.at = datetime(2026, 12, 31, 23, 59, tzinfo=timezone.utc)
        self.expiry = datetime(2027, 1, 2, tzinfo=timezone.utc)

    def test_day_window_is_half_open_utc_calendar_day(self) -> None:
        key, start, end = utc_window(
            "day",
            at=self.at,
            request_key="request-1",
            scan_attempt_id=None,
            expires_at=self.expiry,
        )
        self.assertEqual(key, "day:2026-12-31")
        self.assertEqual(start, datetime(2026, 12, 31, tzinfo=timezone.utc))
        self.assertEqual(end, datetime(2027, 1, 1, tzinfo=timezone.utc))

    def test_month_window_crosses_year_without_rollover(self) -> None:
        key, start, end = utc_window(
            "month",
            at=self.at,
            request_key="request-1",
            scan_attempt_id=None,
            expires_at=self.expiry,
        )
        self.assertEqual(key, "month:2026-12")
        self.assertEqual(start, datetime(2026, 12, 1, tzinfo=timezone.utc))
        self.assertEqual(end, datetime(2027, 1, 1, tzinfo=timezone.utc))

    def test_scan_window_requires_attempt_identity(self) -> None:
        with self.assertRaisesRegex(ValueError, "scan attempt"):
            utc_window(
                "scan",
                at=self.at,
                request_key="request-1",
                scan_attempt_id=None,
                expires_at=self.expiry,
            )
        attempt_id = uuid4()
        key, _, _ = utc_window(
            "scan",
            at=self.at,
            request_key="request-1",
            scan_attempt_id=attempt_id,
            expires_at=self.expiry,
        )
        self.assertEqual(key, f"scan:{attempt_id}")


if __name__ == "__main__":
    unittest.main()
