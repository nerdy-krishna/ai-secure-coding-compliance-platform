"""Pydantic AI run capture retains request-level retry metadata."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from decimal import Decimal
from types import SimpleNamespace
from uuid import uuid4

from pydantic_ai.messages import ModelResponse
from pydantic_ai.usage import RequestUsage

from app.infrastructure.llm_usage_capture import build_request_writes
from app.infrastructure.database.repositories.llm_usage_repo import (
    build_usage_idempotency_key,
)


class _RunResult:
    def __init__(self, responses: list[ModelResponse]):
        self._responses = responses

    def new_messages(self) -> list[ModelResponse]:
        return self._responses


class UsageCaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = SimpleNamespace(
            id=uuid4(),
            provider="openai",
            model_name="requested-model",
            input_cost_per_million=Decimal("2"),
            output_cost_per_million=Decimal("8"),
            updated_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
        )

    @staticmethod
    def _response(
        response_id: str, usage: RequestUsage, *, service_tier: str = "default"
    ) -> ModelResponse:
        return ModelResponse(
            parts=[],
            usage=usage,
            model_name="resolved-model-2026-08-01",
            provider_name="openai",
            provider_response_id=response_id,
            provider_details={
                "api_flavor": "responses",
                "service_tier": service_tier,
                "batch": False,
                "region": "us",
            },
            timestamp=datetime(2026, 8, 23, tzinfo=timezone.utc),
        )

    def test_structured_output_retry_responses_are_priced_individually(self) -> None:
        run = _RunResult(
            [
                self._response(
                    "response-1", RequestUsage(input_tokens=100, output_tokens=20)
                ),
                self._response(
                    "response-2", RequestUsage(input_tokens=120, output_tokens=30)
                ),
            ]
        )

        writes = build_request_writes(run, self.config)

        self.assertEqual([write.request_index for write in writes], [1, 2])
        self.assertEqual(
            [write.provider_response_id for write in writes],
            ["response-1", "response-2"],
        )
        self.assertTrue(all(write.priced.cost_status == "exact" for write in writes))
        self.assertTrue(
            all(write.resolved_model == "resolved-model-2026-08-01" for write in writes)
        )
        self.assertTrue(all(write.api_flavor == "responses" for write in writes))

    def test_legacy_two_rate_override_cannot_misprice_cache(self) -> None:
        run = _RunResult(
            [
                self._response(
                    "response-cache",
                    RequestUsage(
                        input_tokens=100,
                        cache_read_tokens=40,
                        output_tokens=20,
                    ),
                )
            ]
        )

        (write,) = build_request_writes(run, self.config)

        self.assertEqual(write.priced.cost_status, "unknown")
        self.assertIsNone(write.priced.total_amount)
        self.assertIn("cache_read_input", write.priced.missing_categories)

    def test_idempotency_key_is_stable_bounded_and_hides_unit_data(self) -> None:
        secret_path = "/tenant/acme/private/customer-source.py"
        kwargs = {
            "operation_kind": "scan",
            "operation_id": uuid4(),
            "stage": "analysis",
            "agent_name": "SecurityAgent",
            "unit_key": secret_path,
            "llm_config_id": self.config.id,
        }

        first = build_usage_idempotency_key(**kwargs)
        second = build_usage_idempotency_key(**kwargs)

        self.assertEqual(first, second)
        self.assertLessEqual(len(first), 512)
        self.assertNotIn(secret_path, first)
