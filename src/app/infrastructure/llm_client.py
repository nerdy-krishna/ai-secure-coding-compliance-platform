# src/app/infrastructure/llm_client.py
#
# Node-level LLM client. Structured output goes through Pydantic AI (1.86)
# for validation-with-retry, typed output, and unified usage accounting
# across OpenAI / Anthropic / Google. This replaced a LangChain
# `with_structured_output` path in Phase I.3; LangChain is no longer
# imported here.
#
# Responsibilities that remain identical to the previous implementation:
# - honour the per-provider rate limiter (token-based budget).
# - run cost math against LiteLLM via the cost_estimation module.
# - preserve Anthropic prompt caching (cache_read / cache_write) by
#   marking the system prompt as cacheable on Anthropic models.
# - return an AgentLLMResult NamedTuple so existing call sites don't
#   change.

import logging
import time
import uuid
from typing import Any, NamedTuple, Optional, Type, TypeVar

from pydantic import BaseModel
from pydantic_ai import Agent, PromptedOutput
from pydantic_ai.settings import ModelSettings
from pydantic_ai.models.anthropic import AnthropicModel
from pydantic_ai.models.google import GoogleModel
from pydantic_ai.models.openai import OpenAIModel
from pydantic_ai.providers.anthropic import AnthropicProvider
from pydantic_ai.providers.google import GoogleProvider
from pydantic_ai.providers.openai import OpenAIProvider

from app.infrastructure.database import AsyncSessionLocal as async_session_factory
from app.infrastructure.database.models import LLMConfiguration as DB_LLMConfiguration
from app.infrastructure.database.repositories.llm_config_repo import LLMConfigRepository
from app.infrastructure.llm_client_rate_limiter import get_rate_limiter_for_config
from app.infrastructure.observability import get_langfuse, mask
from app.shared.lib import cost_estimation
from app.shared.lib.circuit_breaker import call as circuit_breaker_call
from app.shared.lib.retry_jitter import _default_is_retryable, retry_with_backoff

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


class AgentLLMResult(NamedTuple):
    raw_output: str
    parsed_output: Optional[BaseModel]
    error: Optional[str]
    cost: Optional[float]
    prompt_tokens: Optional[int]
    completion_tokens: Optional[int]
    total_tokens: Optional[int]
    latency_ms: Optional[int]
    cache_creation_tokens: int = 0
    cache_read_tokens: int = 0


# How many auto-retries Pydantic AI gets to recover a Pydantic-validation
# failure on the LLM output before we surface an error. Two is enough to
# absorb one bad sample; more burns cost without improving success rates
# meaningfully against current models.
_OUTPUT_RETRIES = 2

# Models discovered at runtime to reject tool-based (function-calling)
# structured output — DeepSeek's reasoner is the known case: it 400s
# with "does not support this tool_choice". Keyed "provider:model".
# Once a model lands here, later calls skip straight to prompt-based
# structured output instead of paying a failed tool call first.
_PROMPTED_OUTPUT_MODELS: set[str] = set()


def _is_tool_choice_unsupported(err: Exception) -> bool:
    """True when an LLM error means the model can't do tool-based
    structured output and we should fall back to prompt-based output."""
    s = str(err).lower()
    return (
        "tool_choice" in s
        or "does not support tool" in s
        or "function calling" in s
        or "tool calling" in s
    )


def _is_temperature_unsupported(err: Exception) -> bool:
    """True when an LLM error indicates the model rejected the
    `temperature` parameter — some reasoner models do. The call is
    retried once without temperature so the scan still completes (#78)."""
    return "temperature" in str(err).lower()


class LLMClient:
    """A client for a specific LLM configuration.

    Instantiated per call site; instances are not intended to be shared
    across concurrent callers (the Pydantic AI Agent construction is
    cheap, and keeping it per-call lets us set system_prompt with
    cache_control correctly for Anthropic).

    V15.4.1: __slots__ + freeze-after-init converts the docstring
    concurrency warning into a runtime guarantee — post-construction
    attribute writes raise AttributeError, preventing accidental state
    mutation if the instance is ever cached or shared.
    """

    # V15.4.1: restrict attributes and prevent post-init mutation.
    __slots__ = (
        "provider_name",
        "db_llm_config",
        "decrypted_api_key",
        "temperature",
        "_frozen",
    )

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_frozen", False):
            raise AttributeError(
                f"LLMClient is immutable after construction; cannot set '{name}'."
            )
        super().__setattr__(name, value)

    def __init__(
        self,
        llm_config: DB_LLMConfiguration,
        temperature: Optional[float] = None,
    ):
        self.db_llm_config = llm_config
        self.provider_name = llm_config.provider.lower()
        decrypted_api_key = getattr(llm_config, "decrypted_api_key", None)
        if not decrypted_api_key:
            raise ValueError(
                f"API key for LLM config {llm_config.id} is missing or not decrypted."
            )
        self.decrypted_api_key = decrypted_api_key
        # Per-stage LLM temperature (#78). None ⇒ provider default.
        self.temperature = temperature
        self._frozen = True  # V15.4.1: freeze instance; no further attribute writes.
        logger.info(
            "LLMClient initialized for provider=%s model=%s temperature=%s",
            self.provider_name,
            llm_config.model_name,
            temperature,
        )

    # ------------------------------------------------------------------
    # Model construction — one factory per provider. Pydantic AI picks
    # the native structured-output strategy (tool-calling on OpenAI /
    # Anthropic, responseMimeType+schema on Google) based on the model.
    # ------------------------------------------------------------------

    # DeepSeek and xAI both ship OpenAI-compatible Chat Completions APIs;
    # Pydantic AI talks to them through the OpenAI client with a custom
    # base_url. See https://api-docs.deepseek.com and https://docs.x.ai.
    _OPENAI_COMPATIBLE_BASE_URLS = {
        "deepseek": "https://api.deepseek.com/v1",
        "xai": "https://api.x.ai/v1",
    }

    def _build_model(self) -> Any:
        model_name = self.db_llm_config.model_name
        if self.provider_name == "openai":
            return OpenAIModel(
                model_name,
                provider=OpenAIProvider(api_key=self.decrypted_api_key),
            )
        if self.provider_name == "anthropic":
            return AnthropicModel(
                model_name,
                provider=AnthropicProvider(api_key=self.decrypted_api_key),
            )
        if self.provider_name == "google":
            return GoogleModel(
                model_name,
                provider=GoogleProvider(api_key=self.decrypted_api_key),
            )
        base_url = self._OPENAI_COMPATIBLE_BASE_URLS.get(self.provider_name)
        if base_url is not None:
            return OpenAIModel(
                model_name,
                provider=OpenAIProvider(
                    api_key=self.decrypted_api_key, base_url=base_url
                ),
            )
        raise ValueError(f"Unsupported LLM provider: {self.provider_name}")

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def generate_structured_output(
        self,
        prompt: str,
        response_model: Type[T],
        system_prompt: Optional[str] = None,
    ) -> AgentLLMResult:
        """Run `prompt` through the configured LLM and validate the
        response against `response_model`. Pydantic AI automatically
        retries the LLM (up to `_OUTPUT_RETRIES`) if the first response
        fails Pydantic validation.

        Returns an `AgentLLMResult` even on failure — callers branch on
        `result.parsed_output` / `result.error`.
        """
        logger.info(
            "Entering LLM structured output generation.",
            extra={
                "model_name": self.db_llm_config.model_name,
                "provider": self.provider_name,
                "response_model": response_model.__name__,
                "cacheable_prefix": bool(system_prompt),
            },
        )

        full_prompt_for_counting = (
            f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
        )

        # Pre-count tokens for the rate limiter's token budget. Cheap,
        # local call via LiteLLM (no network round-trip under
        # LITELLM_LOCAL_MODEL_COST_MAP=True).
        rate_limiter = get_rate_limiter_for_config(
            self.db_llm_config, self.provider_name
        )
        prompt_tokens_for_budget: Optional[int] = None
        if rate_limiter:
            prompt_tokens_for_budget = await cost_estimation.count_tokens(
                full_prompt_for_counting, self.db_llm_config
            )
            max_prompt_tokens = getattr(self.db_llm_config, "max_prompt_tokens", None)
            if max_prompt_tokens and prompt_tokens_for_budget > int(max_prompt_tokens):
                return AgentLLMResult(
                    parsed_output=None,
                    raw_output="",
                    error=(
                        f"Prompt token estimate {prompt_tokens_for_budget} exceeds "
                        f"configured max_prompt_tokens {max_prompt_tokens}."
                    ),
                    cost=0.0,
                    prompt_tokens=prompt_tokens_for_budget,
                    completion_tokens=0,
                    total_tokens=prompt_tokens_for_budget,
                    latency_ms=0,
                )

        model = self._build_model()
        model_key = f"{self.provider_name}:{self.db_llm_config.model_name}"
        circuit_key = str(getattr(self.db_llm_config, "id", model_key))

        def _make_agent(prompted: bool, temperature: Optional[float]) -> Agent:
            """Build the Pydantic AI agent.

            `system_prompt=` is the stable cache prefix — on Anthropic
            Pydantic AI serialises it with cache_control. `prompted`
            switches structured output from the default tool-based
            strategy to `PromptedOutput`, which needs no `tool_choice`
            and works on models (e.g. DeepSeek's reasoner) that reject
            function calling. `temperature` (#78) is applied via
            model settings when set; ``None`` leaves the provider
            default.
            """
            kwargs: dict[str, Any] = {
                "output_type": (
                    PromptedOutput(response_model) if prompted else response_model
                ),
                "retries": _OUTPUT_RETRIES,
            }
            if system_prompt:
                kwargs["system_prompt"] = system_prompt
            if temperature is not None:
                kwargs["model_settings"] = ModelSettings(temperature=temperature)
            return Agent(model, **kwargs)

        use_prompted = model_key in _PROMPTED_OUTPUT_MODELS
        agent: Agent = _make_agent(prompted=use_prompted, temperature=self.temperature)

        # V14.2.4 / V16.2.5 / V13.4.2: mask prompt payload before logging to
        # prevent PII/secrets reaching Loki when DEBUG is enabled at runtime.
        logger.debug(
            "LLM PROMPT [%s/%s]:\n%s\n---END PROMPT---",
            self.provider_name,
            self.db_llm_config.model_name,
            mask(full_prompt_for_counting),
        )

        start_time = time.perf_counter()
        parsed_output_value: Optional[T] = None
        error_message: Optional[str] = None
        prompt_tokens: int = 0
        completion_tokens: int = 0
        cache_write_tokens: int = 0
        cache_read_tokens: int = 0

        # Langfuse cost reporting is owned by THIS span (recorded onto
        # `cost_details` after the call). Cost source of truth remains
        # `cost_estimation.calculate_actual_cost`. Do NOT enable
        # `litellm.success_callback=["langfuse"]` — that would emit a
        # second cost record per call and diverge from Scan.actual_cost.
        # Threat-model gate G6.
        langfuse_client = get_langfuse()
        span_ctx = (
            langfuse_client.start_as_current_span(
                name=f"llm.{self.provider_name}.{self.db_llm_config.model_name}",
                input=mask(full_prompt_for_counting),
            )
            if langfuse_client is not None
            else None
        )
        span = None
        if span_ctx is not None:
            try:
                span = span_ctx.__enter__()
            except Exception as e:
                logger.warning("Langfuse span open failed: %s", e)
                span_ctx = None

        def _capture(rr: Any) -> None:
            """Pull the parsed output + usage off a Pydantic AI run."""
            nonlocal parsed_output_value, prompt_tokens, completion_tokens
            nonlocal cache_write_tokens, cache_read_tokens
            parsed_output_value = rr.output  # type: ignore[assignment]
            usage = rr.usage()
            prompt_tokens = int(usage.input_tokens or 0)
            completion_tokens = int(usage.output_tokens or 0)
            cache_write_tokens = int(getattr(usage, "cache_write_tokens", 0) or 0)
            cache_read_tokens = int(getattr(usage, "cache_read_tokens", 0) or 0)

        # Acquire rate-limit budget before the API call.  This may sleep
        # if the token bucket is empty — normal, expected behaviour,
        # not a failure.  Keep it outside the retry/circuit-breaker
        # envelope so rate-limiter waits don't count as errors.
        if rate_limiter:
            await rate_limiter.acquire(tokens=prompt_tokens_for_budget or 1)

        async def _invoke_llm(run_agent: Agent) -> None:
            """Single LLM invocation with model-quirk fallback.

            If the model rejects tool-based output or temperature, rebuild
            the agent and retry exactly once.  Transient errors (429, 5xx)
            are NOT caught here — they propagate to the retry wrapper.
            """
            nonlocal use_prompted
            try:
                _capture(await run_agent.run(prompt))
            except Exception as e:
                tool_issue = not use_prompted and _is_tool_choice_unsupported(e)
                temp_issue = self.temperature is not None and (
                    _is_temperature_unsupported(e)
                )
                if not tool_issue and not temp_issue:
                    raise
                logger.warning(
                    "Model %s rejected %s (%s); retrying with fallback.",
                    model_key,
                    " and ".join(
                        x
                        for x, on in (
                            ("tool-based output", tool_issue),
                            ("temperature", temp_issue),
                        )
                        if on
                    ),
                    e,
                )
                if tool_issue:
                    _PROMPTED_OUTPUT_MODELS.add(model_key)
                    use_prompted = True
                _capture(
                    await _make_agent(
                        prompted=use_prompted,
                        temperature=None if temp_issue else self.temperature,
                    ).run(prompt)
                )

        try:
            await circuit_breaker_call(
                key=circuit_key,
                fn=lambda: retry_with_backoff(
                    lambda: _invoke_llm(agent)
                ),
                is_retryable=_default_is_retryable,
            )
        except Exception as e:
            logger.error(
                "LLM call failed (provider=%s, model=%s): %s",
                self.provider_name,
                self.db_llm_config.model_name,
                e,
                exc_info=True,
            )
            error_message = str(e)

        end_time = time.perf_counter()
        latency_ms = int((end_time - start_time) * 1000)

        # Fill in the blanks if the provider didn't report usage. LiteLLM
        # gives us local tokenization; fall back to what we counted for
        # the rate limiter, then a len/4 last resort.
        if not prompt_tokens:
            prompt_tokens = prompt_tokens_for_budget or (
                len(full_prompt_for_counting) // 4
            )
        if not completion_tokens and parsed_output_value is not None:
            try:
                completion_tokens = len(parsed_output_value.model_dump_json()) // 4
            except Exception:  # pragma: no cover — defensive
                completion_tokens = 0

        if parsed_output_value is None and not error_message:
            error_message = (
                "LLM returned no parseable structured output. "
                f"Check that model name '{self.db_llm_config.model_name}' "
                f"is valid for provider '{self.provider_name}'."
            )
            logger.error(error_message)

        if parsed_output_value is not None:
            # V14.2.4 / V16.2.5 / V13.4.2: mask response payload before logging;
            # V16.2.5 forbids logging unredacted LLM payloads.
            logger.debug(
                "LLM RESPONSE [%s/%s]:\n%s\n---END RESPONSE---",
                self.provider_name,
                self.db_llm_config.model_name,
                mask(parsed_output_value.model_dump_json()),
            )

        cost = cost_estimation.calculate_actual_cost(
            config=self.db_llm_config,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )

        # Stamp output / usage / cost onto the Langfuse span and close
        # it. All Langfuse interactions wrapped in try/except so a flush
        # error never bubbles into the LLM call path (G5 fail-open).
        if span is not None and span_ctx is not None:
            try:
                span.update(
                    output=(
                        mask(parsed_output_value.model_dump_json())
                        if parsed_output_value is not None
                        else mask(error_message or "")
                    ),
                    model=self.db_llm_config.model_name,
                    usage_details={
                        "input": prompt_tokens,
                        "output": completion_tokens,
                        "cache_read_input": cache_read_tokens,
                        "cache_creation_input": cache_write_tokens,
                    },
                    cost_details={"total": cost} if cost is not None else None,
                )
            except Exception as e:
                logger.warning("Langfuse span.update failed: %s", e)
            try:
                span_ctx.__exit__(None, None, None)
            except Exception as e:
                logger.warning("Langfuse span exit failed: %s", e)

        return AgentLLMResult(
            raw_output="[Structured output — raw text not directly available]",
            parsed_output=parsed_output_value,
            error=error_message,
            cost=cost,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
            latency_ms=latency_ms,
            cache_creation_tokens=cache_write_tokens,
            cache_read_tokens=cache_read_tokens,
        )


async def get_llm_client(
    llm_config_id: uuid.UUID,
    temperature: Optional[float] = None,
) -> Optional[LLMClient]:
    """Factory that resolves the DB config, decrypts its API key, and
    returns an LLMClient ready to run. The repo attaches the decrypted
    key to the ORM instance as a dynamic attribute — LLMClient reads it
    from there. `temperature` (#78) is the per-stage LLM temperature;
    ``None`` leaves the provider default."""
    logger.info(
        "Attempting to get LLM client for config ID.",
        extra={"llm_config_id": str(llm_config_id)},
    )
    async with async_session_factory() as db:
        repo = LLMConfigRepository(db)
        config = await repo.get_by_id_with_decrypted_key(llm_config_id)
    if config is None:
        logger.error("LLM config %s not found.", llm_config_id)
        return None
    if not getattr(config, "decrypted_api_key", None):
        logger.error("Failed to decrypt API key for LLM config %s.", llm_config_id)
        return None

    logger.info(
        "Successfully retrieved LLM config and returning new LLMClient instance."
    )
    return LLMClient(config, temperature=temperature)
