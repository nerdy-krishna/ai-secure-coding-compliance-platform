# tests/test_cost_estimation.py
#
# Sanity checks on the LiteLLM-backed cost_estimation module. These
# won't catch subtle pricing bugs but they will catch:
#   - LiteLLM bumps that break our model-name resolver
#   - Regression where the admin override stops taking precedence
#   - count_tokens returning zero on known-good text

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from app.shared.lib import cost_estimation


def _config(provider: str, model: str, in_per_m: float = 0, out_per_m: float = 0):
    """Build a light duck-typed LLMConfiguration stand-in."""
    return SimpleNamespace(
        provider=provider,
        model_name=model,
        input_cost_per_million=in_per_m,
        output_cost_per_million=out_per_m,
        tokenizer_encoding=None,
    )


SAMPLE_TEXT = "The quick brown fox jumps over the lazy dog."


@pytest.mark.parametrize(
    "provider,model,min_tokens,max_tokens",
    [
        ("openai", "gpt-4o", 8, 14),
        ("anthropic", "claude-sonnet-4-5", 8, 18),
        ("google", "gemini-2.5-flash", 6, 16),
    ],
)
def test_count_tokens_in_plausible_range(provider, model, min_tokens, max_tokens):
    """LiteLLM should return a sensible token count for a short English
    sentence across all three providers. Tight range to catch regressions
    where the tokenizer falls back to `len/4` silently."""
    cfg = _config(provider, model)
    tokens = asyncio.run(cost_estimation.count_tokens(SAMPLE_TEXT, cfg))
    assert (
        min_tokens <= tokens <= max_tokens
    ), f"{provider}/{model}: got {tokens} tokens; expected {min_tokens}..{max_tokens}"


def test_calculate_actual_cost_uses_litellm_map_when_override_absent():
    # gpt-4o is list-priced at $2.50 in / $10.00 out per 1M at the time
    # of writing. A 1k/500 call should land near $0.0075.
    cfg = _config("openai", "gpt-4o", in_per_m=0, out_per_m=0)
    cost = cost_estimation.calculate_actual_cost(cfg, 1_000, 500)
    assert cost > 0, "LiteLLM map returned zero cost for a known-priced model"
    # Allow ±10% drift so we don't fail the test on a future LiteLLM
    # pricing update.
    assert 0.005 <= cost <= 0.020


def test_admin_override_takes_precedence():
    # Override rates = $1000 per 1M input, $2000 per 1M output. 1k/500 →
    # $1.00 in + $1.00 out = $2.00.
    cfg = _config("openai", "gpt-4o", in_per_m=1_000, out_per_m=2_000)
    cost = cost_estimation.calculate_actual_cost(cfg, 1_000, 500)
    assert cost == pytest.approx(2.00, rel=1e-6)


@pytest.mark.parametrize(
    "provider,model",
    [
        ("deepseek", "deepseek-chat"),
        ("xai", "grok-2-latest"),
    ],
)
def test_first_working_model_key_resolves_new_providers(provider, model):
    """`_PROVIDER_PREFIX` extension for DeepSeek + xAI must resolve to a
    key LiteLLM recognises in its bundled `model_cost` map. If LiteLLM
    ever renames either prefix, this test catches the drift before
    cost estimation falls back to `len/4`.
    """
    import litellm

    cfg = _config(provider, model)
    key = cost_estimation._first_working_model_key(cfg)
    assert key in litellm.model_cost, (
        f"{provider}/{model}: resolver returned {key!r} which is not in "
        f"litellm.model_cost — `_PROVIDER_PREFIX` and LiteLLM's bundled "
        f"map have drifted apart."
    )


def test_estimate_for_prompt_uses_predicted_output_ratio():
    cfg = _config("openai", "gpt-4o")
    est = cost_estimation.estimate_cost_for_prompt(cfg, 1_000)
    # Default predicted ratio is 0.25 → 250 output tokens.
    assert est["predicted_output_tokens"] == 250
    assert est["total_input_tokens"] == 1_000
    assert (
        est["total_estimated_cost"] == est["input_cost"] + est["predicted_output_cost"]
    )


# ---------------------------------------------------------------------------
# Two-slot (utility + reasoning) cost estimation — #69
# ---------------------------------------------------------------------------


def test_two_slot_estimate_sums_each_slot_at_its_own_price():
    """Each slot is priced at its own configured rate; the result is the
    sum. Override rates make the arithmetic exact and LiteLLM-independent."""
    reasoning = _config("openai", "gpt-4o", in_per_m=1_000, out_per_m=2_000)
    utility = _config("openai", "gpt-4o-mini", in_per_m=100, out_per_m=200)
    est = cost_estimation.estimate_cost_two_slot(
        reasoning_config=reasoning,
        reasoning_input_tokens=1_000,
        utility_config=utility,
        utility_input_tokens=2_000,
    )
    # reasoning: 1000 in @ $1000/1M = $1.00 + 250 out @ $2000/1M = $0.50
    # utility:   2000 in @ $100/1M  = $0.20 + 500 out @ $200/1M  = $0.10
    assert est["slots"]["reasoning"]["total_estimated_cost"] == pytest.approx(1.50)
    assert est["slots"]["utility"]["total_estimated_cost"] == pytest.approx(0.30)
    assert est["total_estimated_cost"] == pytest.approx(1.80)
    assert est["total_input_tokens"] == 3_000


def test_two_slot_estimate_with_same_config_in_both_slots():
    """Same config in both slots equals a single estimate over the
    combined token count."""
    cfg = _config("openai", "gpt-4o", in_per_m=1_000, out_per_m=2_000)
    two_slot = cost_estimation.estimate_cost_two_slot(
        reasoning_config=cfg,
        reasoning_input_tokens=600,
        utility_config=cfg,
        utility_input_tokens=400,
    )
    single = cost_estimation.estimate_cost_for_prompt(cfg, 1_000)
    assert two_slot["total_estimated_cost"] == pytest.approx(
        single["total_estimated_cost"]
    )


def test_two_slot_estimate_rejects_negative_tokens():
    cfg = _config("openai", "gpt-4o")
    with pytest.raises(ValueError):
        cost_estimation.estimate_cost_two_slot(
            reasoning_config=cfg,
            reasoning_input_tokens=100,
            utility_config=cfg,
            utility_input_tokens=-1,
        )


# ---------------------------------------------------------------------------
# Dual reasoning LLM cost estimation — #93 / PRD #91
# ---------------------------------------------------------------------------


def test_secondary_reasoning_prices_the_analysis_pass_twice():
    """With a second reasoning LLM the analysis pass is priced again at
    that config's rate and added to the total; a `reasoning_secondary`
    slot appears in the breakdown."""
    reasoning = _config("openai", "gpt-4o", in_per_m=1_000, out_per_m=2_000)
    utility = _config("openai", "gpt-4o-mini", in_per_m=100, out_per_m=200)
    secondary = _config(
        "anthropic", "claude-sonnet-4-6", in_per_m=3_000, out_per_m=6_000
    )
    est = cost_estimation.estimate_cost_two_slot(
        reasoning_config=reasoning,
        reasoning_input_tokens=1_000,
        utility_config=utility,
        utility_input_tokens=0,
        secondary_reasoning_config=secondary,
        secondary_reasoning_input_tokens=1_000,
    )
    # reasoning:  1000 in @ $1000/1M = $1.00 + 250 out @ $2000/1M = $0.50
    # secondary:  1000 in @ $3000/1M = $3.00 + 250 out @ $6000/1M = $1.50
    assert est["slots"]["reasoning"]["total_estimated_cost"] == pytest.approx(1.50)
    assert est["slots"]["reasoning_secondary"][
        "total_estimated_cost"
    ] == pytest.approx(4.50)
    assert est["total_estimated_cost"] == pytest.approx(6.00)
    assert est["total_input_tokens"] == 2_000


def test_no_secondary_config_leaves_estimate_unchanged():
    """When no second reasoning LLM is passed the result is the pre-#93
    two-slot estimate — no `reasoning_secondary` slot."""
    reasoning = _config("openai", "gpt-4o", in_per_m=1_000, out_per_m=2_000)
    utility = _config("openai", "gpt-4o-mini", in_per_m=100, out_per_m=200)
    est = cost_estimation.estimate_cost_two_slot(
        reasoning_config=reasoning,
        reasoning_input_tokens=1_000,
        utility_config=utility,
        utility_input_tokens=2_000,
    )
    assert "reasoning_secondary" not in est["slots"]
    assert est["total_estimated_cost"] == pytest.approx(1.80)


def test_secondary_same_config_same_basis_doubles_the_analysis_cost():
    """The dual-LLM analysis runs the same agents over the same tokens
    on both configs — same config + same basis ⇒ exactly double."""
    cfg = _config("openai", "gpt-4o", in_per_m=1_000, out_per_m=2_000)
    est = cost_estimation.estimate_cost_two_slot(
        reasoning_config=cfg,
        reasoning_input_tokens=1_000,
        utility_config=cfg,
        utility_input_tokens=0,
        secondary_reasoning_config=cfg,
        secondary_reasoning_input_tokens=1_000,
    )
    primary = est["slots"]["reasoning"]["total_estimated_cost"]
    secondary = est["slots"]["reasoning_secondary"]["total_estimated_cost"]
    assert secondary == pytest.approx(primary)
    assert est["total_estimated_cost"] == pytest.approx(2 * primary)


def test_secondary_reasoning_rejects_negative_tokens():
    cfg = _config("openai", "gpt-4o")
    with pytest.raises(ValueError):
        cost_estimation.estimate_cost_two_slot(
            reasoning_config=cfg,
            reasoning_input_tokens=100,
            utility_config=cfg,
            utility_input_tokens=0,
            secondary_reasoning_config=cfg,
            secondary_reasoning_input_tokens=-5,
        )
