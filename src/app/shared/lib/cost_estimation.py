# src/app/shared/lib/cost_estimation.py
"""Token counting and cost estimation, routed through LiteLLM.

LiteLLM ships per-provider tokenizers (tiktoken for OpenAI, the official
Anthropic tokenizer, sentencepiece for Gemini, etc.) plus a community
maintained pricing table (`model_prices_and_context_window`). We use both
as the source of truth and honour the admin override stored on the
`LLMConfiguration` row when it's set to a non-zero value.

The `LITELLM_LOCAL_MODEL_COST_MAP=True` env var (set in the api/worker
containers) pins LiteLLM to the bundled price map, eliminating runtime
network calls on every cost lookup.

Call signatures are unchanged so existing callers don't need to move.
"""

import logging
from typing import Any, Dict, Optional

import litellm

from app.config.config import settings
from app.infrastructure.database import models as db_models

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Model naming
# ---------------------------------------------------------------------------
#
# LiteLLM keys its price/tokenizer maps by canonical model names that are
# usually the same as the provider's model string (e.g. "gpt-4o",
# "claude-sonnet-4-5", "gemini-2.5-flash"). For Anthropic, though, some
# names appear only under the vendor-prefixed key ("anthropic/claude-..."),
# and the Gemini line is usually under "gemini/<model>" in LiteLLM's map.
# We try both shapes and fall back to the raw name LangChain uses so an
# unknown preview model name still works via tiktoken's fallback encoding.

# NOTE (eval-gap): DeepSeek and xAI Grok prompts are not yet exercised by
# the Promptfoo eval suite or the deferred OWASP LLM/Agentic redteam pack.
# Operators routing scans through them accept the model-alignment risk —
# see .agent/features.md.
_PROVIDER_PREFIX = {
    "openai": "openai",
    "anthropic": "anthropic",
    "google": "gemini",
    "deepseek": "deepseek",
    "xai": "xai",
}


def _candidate_model_keys(config: db_models.LLMConfiguration) -> list[str]:
    raw = config.model_name
    prefix = _PROVIDER_PREFIX.get(config.provider.lower())
    keys = [raw]
    if prefix and not raw.startswith(f"{prefix}/"):
        keys.append(f"{prefix}/{raw}")
    return keys


def _first_working_model_key(
    config: db_models.LLMConfiguration,
) -> str:
    """Return the first model key LiteLLM recognises in its price map.

    Falls back to the raw model name if nothing matches; tiktoken's
    default cl100k_base encoding still produces a usable token count
    under that path.
    """
    for key in _candidate_model_keys(config):
        try:
            # `model_cost` is the in-memory map. Cheap lookup; no network.
            if key in litellm.model_cost:
                return key
        except Exception:  # pragma: no cover — defensive
            pass
    return config.model_name


def _admin_override(
    config: db_models.LLMConfiguration,
) -> Optional[tuple[float, float]]:
    """Return (input_per_token, output_per_token) when the admin set a
    non-zero price on the config; otherwise None (→ LiteLLM map)."""
    try:
        in_per_m = float(config.input_cost_per_million or 0)
        out_per_m = float(config.output_cost_per_million or 0)
    except (TypeError, ValueError):
        return None
    if in_per_m <= 0 and out_per_m <= 0:
        return None
    if (in_per_m > 0) ^ (out_per_m > 0):
        logger.warning(
            "LLMConfiguration %s has partial cost override (in=%s out=%s); "
            "falling back to LiteLLM map",
            config.id,
            in_per_m,
            out_per_m,
        )
        return None
    return (in_per_m / 1_000_000, out_per_m / 1_000_000)


# ---------------------------------------------------------------------------
# Token counting
# ---------------------------------------------------------------------------


async def count_tokens(
    text: str,
    config: db_models.LLMConfiguration,
    api_key: Optional[str] = None,
) -> int:
    """Return the token count LiteLLM associates with (model, text).

    `api_key` is accepted for signature compatibility with the previous
    implementation but ignored — LiteLLM does all counting locally.
    """
    if not text:
        return 0
    if not isinstance(text, str):
        raise TypeError("count_tokens: text must be str")
    if len(text) > 4_000_000:
        text = text[:4_000_000]
    del api_key  # unused; kept for backwards-compatible call sites

    model = _first_working_model_key(config)
    try:
        return int(litellm.token_counter(model=model, text=text))
    except Exception as e:
        logger.warning(
            "LiteLLM token_counter failed for model=%s (provider=%s): %s. "
            "Falling back to len/4.",
            model,
            config.provider,
            e,
        )
        return max(0, len(text) // 4)


# ---------------------------------------------------------------------------
# Cost math
# ---------------------------------------------------------------------------


def _compute_cost(
    config: db_models.LLMConfiguration,
    prompt_tokens: int,
    completion_tokens: int,
) -> tuple[float, float]:
    """(input_cost, output_cost) in USD. Admin override > LiteLLM map."""
    override = _admin_override(config)
    if override is not None:
        in_rate, out_rate = override
        return prompt_tokens * in_rate, completion_tokens * out_rate

    model = _first_working_model_key(config)
    try:
        prompt_cost, completion_cost = litellm.cost_per_token(
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )
        return float(prompt_cost), float(completion_cost)
    except Exception as e:
        logger.warning(
            "LiteLLM cost_per_token failed for model=%s (provider=%s): %s. "
            "Returning zero cost (safe default).",
            model,
            config.provider,
            e,
        )
        return 0.0, 0.0


def estimate_cost_for_prompt(
    config: db_models.LLMConfiguration,
    input_tokens: int,
    output_token_percentage: float = 0.25,
) -> Dict[str, float]:
    """Pre-call cost estimate. Output tokens are predicted at 25% of input
    by default (same heuristic as before); admin can tune by passing a
    different ratio when calling."""
    if not isinstance(input_tokens, int) or input_tokens < 0:
        raise ValueError("input_tokens must be a non-negative int")
    if not (0.0 <= output_token_percentage <= 4.0):
        raise ValueError("output_token_percentage out of range")
    predicted_output_tokens = max(0, int(input_tokens * output_token_percentage))
    input_cost, predicted_output_cost = _compute_cost(
        config, input_tokens, predicted_output_tokens
    )

    total_estimated_cost = input_cost + predicted_output_cost
    logger.debug(
        "Cost estimate for %s: input_tokens=%d predicted_output=%d total=$%.6f",
        config.model_name,
        input_tokens,
        predicted_output_tokens,
        total_estimated_cost,
    )
    MAX_PER_SCAN_USD = getattr(settings, "MAX_PER_SCAN_ESTIMATED_COST_USD", 100.0)
    if total_estimated_cost > MAX_PER_SCAN_USD:
        raise ValueError(
            f"Estimated cost ${total_estimated_cost:.2f} exceeds per-scan ceiling ${MAX_PER_SCAN_USD}"
        )
    return {
        "input_cost": input_cost,
        "predicted_output_cost": predicted_output_cost,
        "total_estimated_cost": total_estimated_cost,
        "predicted_output_tokens": float(predicted_output_tokens),
        "total_input_tokens": float(input_tokens),
    }


def estimate_cost_two_slot(
    *,
    reasoning_config: db_models.LLMConfiguration,
    reasoning_input_tokens: int,
    utility_config: db_models.LLMConfiguration,
    utility_input_tokens: int,
    secondary_reasoning_config: Optional[db_models.LLMConfiguration] = None,
    secondary_reasoning_input_tokens: int = 0,
    output_token_percentage: float = 0.25,
) -> Dict[str, Any]:
    """Pre-call cost estimate across the LLM slots of a scan (#69, #93).

    Each slot's input tokens are priced at *that slot's* configured
    rate; the slot totals are summed. When the same config sits in
    multiple slots the result equals a single-config estimate over the
    combined token count. The per-scan ceiling is applied to the
    combined total, not to any slot alone.

    When ``secondary_reasoning_config`` is supplied (#93 — the opt-in
    second reasoning LLM), the analysis pass is priced a second time at
    that config's rate and added to the total; the breakdown gains a
    ``reasoning_secondary`` slot. When it is ``None`` the result is
    byte-identical to the pre-#93 two-slot estimate.

    The returned dict carries the same top-level keys as
    `estimate_cost_for_prompt` (so existing `cost_details` consumers
    keep working) plus a `slots` breakdown for transparency.
    """
    slot_inputs = [
        ("reasoning", reasoning_input_tokens),
        ("utility", utility_input_tokens),
    ]
    if secondary_reasoning_config is not None:
        slot_inputs.append(("secondary_reasoning", secondary_reasoning_input_tokens))
    for label, toks in slot_inputs:
        if not isinstance(toks, int) or toks < 0:
            raise ValueError(f"{label}_input_tokens must be a non-negative int")
    if not (0.0 <= output_token_percentage <= 4.0):
        raise ValueError("output_token_percentage out of range")

    def _slot(
        config: db_models.LLMConfiguration, input_tokens: int
    ) -> Dict[str, float]:
        predicted_output = max(0, int(input_tokens * output_token_percentage))
        in_cost, out_cost = _compute_cost(config, input_tokens, predicted_output)
        return {
            "input_tokens": float(input_tokens),
            "predicted_output_tokens": float(predicted_output),
            "input_cost": in_cost,
            "predicted_output_cost": out_cost,
            "total_estimated_cost": in_cost + out_cost,
        }

    reasoning = _slot(reasoning_config, reasoning_input_tokens)
    utility = _slot(utility_config, utility_input_tokens)
    slots: Dict[str, Dict[str, float]] = {
        "reasoning": reasoning,
        "utility": utility,
    }
    priced = [reasoning, utility]
    if secondary_reasoning_config is not None:
        reasoning_secondary = _slot(
            secondary_reasoning_config, secondary_reasoning_input_tokens
        )
        slots["reasoning_secondary"] = reasoning_secondary
        priced.append(reasoning_secondary)

    total = sum(s["total_estimated_cost"] for s in priced)

    MAX_PER_SCAN_USD = getattr(settings, "MAX_PER_SCAN_ESTIMATED_COST_USD", 100.0)
    if total > MAX_PER_SCAN_USD:
        raise ValueError(
            f"Estimated cost ${total:.2f} exceeds per-scan ceiling ${MAX_PER_SCAN_USD}"
        )
    logger.debug(
        "Two-slot cost estimate: reasoning=$%.6f utility=$%.6f "
        "secondary=$%.6f total=$%.6f",
        reasoning["total_estimated_cost"],
        utility["total_estimated_cost"],
        slots.get("reasoning_secondary", {}).get("total_estimated_cost", 0.0),
        total,
    )
    return {
        "input_cost": sum(s["input_cost"] for s in priced),
        "predicted_output_cost": sum(s["predicted_output_cost"] for s in priced),
        "total_estimated_cost": total,
        "predicted_output_tokens": sum(s["predicted_output_tokens"] for s in priced),
        "total_input_tokens": sum(s["input_tokens"] for s in priced),
        "slots": slots,
    }


def calculate_actual_cost(
    config: db_models.LLMConfiguration,
    prompt_tokens: int,
    completion_tokens: int,
) -> float:
    """Post-call exact cost from the provider-reported token counts."""
    input_cost, output_cost = _compute_cost(config, prompt_tokens, completion_tokens)
    total = input_cost + output_cost
    logger.info(
        "Actual cost for %s (%d in, %d out): $%.6f",
        config.model_name,
        prompt_tokens,
        completion_tokens,
        total,
    )
    return total
