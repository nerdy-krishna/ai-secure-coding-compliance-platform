"""Fail-open contract test for the LLMClient × Langfuse integration (G5).

If the Langfuse SDK raises (network blip, auth error, span emit fault)
the LLM call MUST still return a populated `AgentLLMResult`. Anything
else would make every scan dependent on Langfuse availability — the
opposite of "observability shouldn't take prod down."
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest


pytestmark = pytest.mark.asyncio


class _BoomSpanCtx:
    """Pretend Langfuse client whose `start_as_current_span` raises on
    `__enter__`. Mirrors a network failure during span open."""

    def __init__(self, *_a: Any, **_k: Any) -> None:
        pass

    def __enter__(self) -> Any:
        raise RuntimeError("simulated langfuse span open failure")

    def __exit__(self, *_a: Any, **_k: Any) -> None:
        pass


class _BoomClient:
    def start_as_current_span(self, *_a: Any, **_k: Any) -> _BoomSpanCtx:
        return _BoomSpanCtx()


class _StubUsage:
    def __init__(self) -> None:
        self.input_tokens = 100
        self.output_tokens = 20
        self.cache_read_tokens = 0
        self.cache_write_tokens = 0


class _StubRunResult:
    def __init__(self, output: Any) -> None:
        self.output = output

    def usage(self) -> _StubUsage:
        return _StubUsage()


class _StubAgent:
    def __init__(self, *_a: Any, **_k: Any) -> None:
        pass

    async def run(self, _prompt: str) -> _StubRunResult:
        from pydantic import BaseModel

        class _Out(BaseModel):
            ok: bool

        return _StubRunResult(_Out(ok=True))


@pytest.fixture
def _llm_config() -> Any:
    """Build a minimal DB_LLMConfiguration substitute."""
    from app.infrastructure.database.models import LLMConfiguration

    cfg = LLMConfiguration(
        id=uuid.uuid4(),
        name="test",
        provider="openai",
        model_name="gpt-4o-mini",
        encrypted_api_key="dummy",
        input_cost_per_million=0,
        output_cost_per_million=0,
    )
    cfg.decrypted_api_key = "fake-key"
    return cfg


async def test_llm_client_survives_langfuse_span_failure(
    monkeypatch: pytest.MonkeyPatch, _llm_config: Any
) -> None:
    """G5 — LLMClient.generate_structured_output returns a populated
    result even when the Langfuse span raises on enter."""
    from pydantic import BaseModel

    from app.infrastructure import llm_client as llm_mod

    monkeypatch.setattr(llm_mod, "get_langfuse", lambda: _BoomClient())

    # Stub Pydantic AI Agent + provider model factory so no real LLM call
    # is attempted.
    monkeypatch.setattr(llm_mod, "Agent", _StubAgent)
    monkeypatch.setattr(
        llm_mod.LLMClient,
        "_build_model",
        lambda self: object(),
    )
    monkeypatch.setattr(llm_mod, "get_rate_limiter_for_config", lambda _c, _p: None)

    class _Resp(BaseModel):
        ok: bool

    client = llm_mod.LLMClient(_llm_config)
    result = await client.generate_structured_output(
        prompt="test prompt", response_model=_Resp
    )

    # Despite the Langfuse boom, the LLM call still produced output.
    assert result.error is None
    assert result.parsed_output is not None
    assert result.parsed_output.ok is True
    assert result.prompt_tokens == 100
    assert result.completion_tokens == 20
