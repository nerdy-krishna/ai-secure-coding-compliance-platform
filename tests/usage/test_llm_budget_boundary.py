"""Budget admission contracts at the sole production model-call boundary."""

from __future__ import annotations

import unittest
import uuid
from collections.abc import Awaitable, Callable
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from pydantic import BaseModel

from app.core.services.usage_budget_service import (
    BudgetExceededError,
    BudgetFailureSnapshot,
)
from app.infrastructure.database.repositories.llm_usage_repo import LLMUsageContext
from app.infrastructure.llm_client import LLMClient


class _Answer(BaseModel):
    value: str


class _Usage:
    input_tokens = 12
    output_tokens = 3
    cache_write_tokens = 0
    cache_read_tokens = 0
    tool_calls = 0


class _RunResult:
    output = _Answer(value="ok")

    @staticmethod
    def usage() -> _Usage:
        return _Usage()

    @staticmethod
    def new_messages() -> list[object]:
        return []


class _FakeAgent:
    def __init__(self, result: object | None = None, error: Exception | None = None):
        self.result = result
        self.error = error
        self.run = AsyncMock(side_effect=self._run)

    async def _run(self, _prompt: str) -> object:
        if self.error is not None:
            raise self.error
        return self.result


def _config() -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        provider="openai",
        model_name="gpt-test",
        decrypted_api_key="test-key",
        input_cost_per_million=1,
        output_cost_per_million=2,
        requests_per_minute=None,
        tokens_per_minute=None,
        max_prompt_tokens=None,
    )


def _context() -> LLMUsageContext:
    operation_id = uuid.uuid4()
    return LLMUsageContext(
        operation_kind="chat",
        operation_id=str(operation_id),
        stage="advisor_response",
        agent_name="test",
        idempotency_key=f"chat:{operation_id}:advisor_response:test",
        actor_user_id=1,
    )


async def _direct_circuit_call(
    *, fn: Callable[[], Awaitable[object]], **_kwargs: object
) -> object:
    return await fn()


async def _single_attempt(
    fn: Callable[[], Awaitable[object]], **_kwargs: object
) -> object:
    return await fn()


class LLMBudgetBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_budget_denial_prevents_provider_call(self) -> None:
        fake_agent = _FakeAgent(result=_RunResult())
        denial = BudgetExceededError(
            snapshot=BudgetFailureSnapshot(
                policy_id=uuid.uuid4(),
                scope="tenant",
                dimension="total_tokens",
                window="day",
                remaining=2,
                requested=20,
            )
        )
        client = LLMClient(_config())

        with (
            patch.object(LLMClient, "_build_model", return_value=object()),
            patch("app.infrastructure.llm_client.Agent", return_value=fake_agent),
            patch(
                "app.infrastructure.llm_client.circuit_breaker_call",
                new=_direct_circuit_call,
            ),
            patch(
                "app.infrastructure.llm_client.retry_with_backoff",
                new=_single_attempt,
            ),
            patch(
                "app.infrastructure.llm_client.cost_estimation.count_tokens",
                new=AsyncMock(return_value=10),
            ),
            patch(
                "app.infrastructure.llm_client.load_active_price_override",
                new=AsyncMock(return_value=None),
            ),
            patch(
                "app.infrastructure.llm_client._reserve_usage_budget",
                new=AsyncMock(side_effect=denial),
            ),
            patch(
                "app.infrastructure.llm_client._finalize_usage_budget",
                new=AsyncMock(),
            ) as finalize,
            patch("app.infrastructure.llm_client.get_langfuse", return_value=None),
        ):
            with self.assertRaises(BudgetExceededError):
                await client.generate_structured_output(
                    "hello", _Answer, usage_context=_context()
                )

        fake_agent.run.assert_not_awaited()
        finalize.assert_not_awaited()

    async def test_success_settles_canonical_usage_event(self) -> None:
        fake_agent = _FakeAgent(result=_RunResult())
        client = LLMClient(_config())
        reservation_id = uuid.uuid4()
        usage_event_id = uuid.uuid4()

        with (
            patch.object(LLMClient, "_build_model", return_value=object()),
            patch("app.infrastructure.llm_client.Agent", return_value=fake_agent),
            patch(
                "app.infrastructure.llm_client.circuit_breaker_call",
                new=_direct_circuit_call,
            ),
            patch(
                "app.infrastructure.llm_client.retry_with_backoff",
                new=_single_attempt,
            ),
            patch(
                "app.infrastructure.llm_client.cost_estimation.count_tokens",
                new=AsyncMock(return_value=10),
            ),
            patch(
                "app.infrastructure.llm_client.load_active_price_override",
                new=AsyncMock(return_value=None),
            ),
            patch(
                "app.infrastructure.llm_client._reserve_usage_budget",
                new=AsyncMock(return_value=reservation_id),
            ),
            patch(
                "app.infrastructure.llm_client.record_run_usage",
                new=AsyncMock(return_value=(usage_event_id, None, True)),
            ),
            patch(
                "app.infrastructure.llm_client._finalize_usage_budget",
                new=AsyncMock(),
            ) as finalize,
            patch("app.infrastructure.llm_client.get_langfuse", return_value=None),
        ):
            result = await client.generate_structured_output(
                "hello", _Answer, usage_context=_context()
            )

        self.assertEqual(result.usage_event_id, usage_event_id)
        finalize.assert_awaited_once_with(
            reservation_id=reservation_id,
            usage_event_id=usage_event_id,
            provider_called=True,
        )

    async def test_failed_provider_call_conserves_unknown_spend(self) -> None:
        fake_agent = _FakeAgent(error=RuntimeError("offline"))
        client = LLMClient(_config())
        reservation_id = uuid.uuid4()

        with (
            patch.object(LLMClient, "_build_model", return_value=object()),
            patch("app.infrastructure.llm_client.Agent", return_value=fake_agent),
            patch(
                "app.infrastructure.llm_client.circuit_breaker_call",
                new=_direct_circuit_call,
            ),
            patch(
                "app.infrastructure.llm_client.retry_with_backoff",
                new=_single_attempt,
            ),
            patch(
                "app.infrastructure.llm_client.cost_estimation.count_tokens",
                new=AsyncMock(return_value=10),
            ),
            patch(
                "app.infrastructure.llm_client.load_active_price_override",
                new=AsyncMock(return_value=None),
            ),
            patch(
                "app.infrastructure.llm_client._reserve_usage_budget",
                new=AsyncMock(return_value=reservation_id),
            ),
            patch(
                "app.infrastructure.llm_client._finalize_usage_budget",
                new=AsyncMock(),
            ) as finalize,
            patch("app.infrastructure.llm_client.get_langfuse", return_value=None),
        ):
            result = await client.generate_structured_output(
                "hello", _Answer, usage_context=_context()
            )

        self.assertIsNotNone(result.error)
        finalize.assert_awaited_once_with(
            reservation_id=reservation_id,
            usage_event_id=None,
            provider_called=True,
        )


if __name__ == "__main__":
    unittest.main()
