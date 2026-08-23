"""Request-level prices use Decimal snapshots and explicit unknown states."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from decimal import Decimal

from pydantic_ai.usage import RequestUsage
from pydantic import ValidationError

from app.api.v1.models import LLMPriceOverrideCreate
from app.shared.lib.llm_usage import (
    BILLABLE_CATEGORIES,
    PriceSnapshot,
    Rate,
    normalize_request_usage,
    price_normalized_usage,
)


EFFECTIVE_AT = datetime(2026, 8, 1, tzinfo=timezone.utc)


class UsagePricingTests(unittest.TestCase):
    def test_prices_cache_and_reasoning_categories_before_aggregation(self) -> None:
        normalized = normalize_request_usage(
            "openai",
            RequestUsage(
                input_tokens=1_000,
                cache_read_tokens=400,
                output_tokens=300,
                details={"reasoning_tokens": 100},
            ),
        )
        snapshot = PriceSnapshot(
            source="catalog:test-v1",
            effective_at=EFFECTIVE_AT,
            currency="USD",
            rates={
                "uncached_input": Rate(Decimal("2.00"), "million_tokens"),
                "cache_read_input": Rate(Decimal("0.50"), "million_tokens"),
                "non_reasoning_output": Rate(Decimal("8.00"), "million_tokens"),
                "reasoning_output": Rate(Decimal("8.00"), "million_tokens"),
            },
        )

        priced = price_normalized_usage(normalized, snapshot)

        self.assertEqual(priced.cost_status, "exact")
        self.assertEqual(priced.total_amount, Decimal("0.003800000000"))
        self.assertEqual(
            {item.category for item in priced.line_items},
            {
                "uncached_input",
                "cache_read_input",
                "non_reasoning_output",
                "reasoning_output",
            },
        )
        self.assertTrue(
            all(isinstance(item.amount, Decimal) for item in priced.line_items)
        )

    def test_unknown_model_pricing_is_null_not_zero(self) -> None:
        normalized = normalize_request_usage(
            "openai", RequestUsage(input_tokens=100, output_tokens=20)
        )

        priced = price_normalized_usage(normalized, None)

        self.assertEqual(priced.cost_status, "unknown")
        self.assertIsNone(priced.total_amount)
        self.assertEqual(priced.line_items, ())

    def test_incomplete_override_cannot_mix_with_another_source(self) -> None:
        normalized = normalize_request_usage(
            "anthropic",
            RequestUsage(
                input_tokens=1_000,
                cache_write_tokens=200,
                output_tokens=100,
            ),
        )
        partial_override = PriceSnapshot(
            source="admin:config-1:v2",
            effective_at=EFFECTIVE_AT,
            currency="USD",
            rates={
                "uncached_input": Rate(Decimal("3"), "million_tokens"),
                "non_reasoning_output": Rate(Decimal("15"), "million_tokens"),
            },
        )

        priced = price_normalized_usage(normalized, partial_override)

        self.assertEqual(priced.cost_status, "unknown")
        self.assertIsNone(priced.total_amount)
        self.assertIn("cache_write_input", priced.missing_categories)

    def test_admin_override_contract_requires_every_billable_category(self) -> None:
        token_rate = {
            "amount": "1.25",
            "unit": "million_tokens",
            "modifier": "1",
        }
        rates = {category: token_rate for category in BILLABLE_CATEGORIES}
        rates["provider_request"] = {
            "amount": "0.25",
            "unit": "thousand_requests",
            "modifier": "1",
        }
        complete = LLMPriceOverrideCreate(
            rates=rates,
            currency="USD",
            source="enterprise-contract-2026",
        )

        self.assertEqual(set(complete.rates), BILLABLE_CATEGORIES)
        with self.assertRaises(ValidationError):
            LLMPriceOverrideCreate(
                rates={"uncached_input": token_rate},
                currency="USD",
                source="partial-contract",
            )
