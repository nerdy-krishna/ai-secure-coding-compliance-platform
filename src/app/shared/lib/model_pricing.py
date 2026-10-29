"""Model price resolution shared by estimates, usage capture and setup.

Three resolvers disagree about which model names exist:

* ``litellm.model_cost`` — the price map bundled with the pinned LiteLLM
  (pinned to the local copy via ``LITELLM_LOCAL_MODEL_COST_MAP``);
* ``genai_prices`` (via Pydantic AI's ``response.cost()``) — used when
  recording *actual* usage;
* the admin override stored on ``LLMConfiguration``.

A model the application accepts but neither catalogue knows (e.g.
``deepseek-flash``) used to produce ``$0.0000`` for every estimate and every
completed scan, silently. This module gives one answer to "what does this model
cost", so the three call sites cannot drift:

1. admin override, when both rates are set;
2. the catalogue entry for the model (raw name and provider-prefixed form);
3. the catalogue entry for an explicit price alias (models priced identically
   to another catalogue entry);
4. otherwise ``None`` — callers must surface "pricing unavailable" rather than
   inventing a number.

Aliases are deliberately few and documented: a wrong alias silently misprices
every scan, which is worse than an honest "unknown".
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional

import litellm

logger = logging.getLogger(__name__)

#: Provider → LiteLLM model-key prefix. Mirrors ``cost_estimation``.
_PROVIDER_PREFIX = {
    "openai": "openai",
    "anthropic": "anthropic",
    "google": "gemini",
    "deepseek": "deepseek",
    "xai": "xai",
}

#: Model → catalogue name that is priced identically.
#:
#: ``deepseek-flash`` is DeepSeek's low-latency tier and is billed at the
#: ``deepseek-chat`` rate; the pinned price map predates the alias, so without
#: this entry the model resolves to no price at all. Add entries only when the
#: provider's published price for the two names is the same.
_PRICE_ALIASES: dict[str, str] = {
    "deepseek-flash": "deepseek-chat",
    "deepseek-v4-flash": "deepseek-chat",
}


@dataclass(frozen=True)
class ModelPrices:
    """Resolved per-token prices for one configured model."""

    input_per_token: float
    output_per_token: float
    #: ``admin_override`` | ``catalog`` | ``alias``
    source: str
    #: Catalogue key that produced the price (for display/diagnostics).
    matched_model: Optional[str] = None
    #: Set when ``source == "alias"``: the configured name that was aliased.
    aliased_from: Optional[str] = None

    def per_million(self) -> tuple[float, float]:
        """(input, output) USD per million tokens — the admin-facing unit."""
        return (self.input_per_token * 1_000_000, self.output_per_token * 1_000_000)

    def as_dict(self) -> dict[str, Any]:
        return {
            "input_per_token": self.input_per_token,
            "output_per_token": self.output_per_token,
            "source": self.source,
            "matched_model": self.matched_model,
            "aliased_from": self.aliased_from,
        }


def _model_name(config: Any) -> str:
    return str(getattr(config, "model_name", "") or "").strip()


def _provider(config: Any) -> str:
    return str(getattr(config, "provider", "") or "").strip().lower()


def catalogue_candidates(model_name: str, provider: str) -> list[str]:
    """Catalogue keys to try for a configured model, in priority order."""
    keys = [model_name]
    prefix = _PROVIDER_PREFIX.get(provider)
    if prefix and not model_name.startswith(f"{prefix}/"):
        keys.append(f"{prefix}/{model_name}")
    canonical = _PRICE_ALIASES.get(model_name.lower())
    if canonical and canonical not in keys:
        keys.append(canonical)
        if prefix and not canonical.startswith(f"{prefix}/"):
            keys.append(f"{prefix}/{canonical}")
    return keys


def canonical_model_name(config: Any) -> str:
    """Configured model name, mapped through the price aliases."""
    name = _model_name(config)
    return _PRICE_ALIASES.get(name.lower(), name)


def _catalogue_prices(key: str) -> Optional[tuple[float, float]]:
    try:
        entry = litellm.model_cost.get(key)
    except Exception:  # pragma: no cover - defensive
        return None
    if not entry:
        return None
    input_rate = entry.get("input_cost_per_token")
    output_rate = entry.get("output_cost_per_token")
    try:
        input_rate = float(input_rate)
        output_rate = float(output_rate)
    except (TypeError, ValueError):
        return None
    if input_rate <= 0 and output_rate <= 0:
        return None
    return input_rate, output_rate


def _admin_override(config: Any) -> Optional[tuple[float, float]]:
    try:
        input_per_m = float(getattr(config, "input_cost_per_million", 0) or 0)
        output_per_m = float(getattr(config, "output_cost_per_million", 0) or 0)
    except (TypeError, ValueError):
        return None
    if input_per_m > 0 and output_per_m > 0:
        return (input_per_m / 1_000_000, output_per_m / 1_000_000)
    if (input_per_m > 0) ^ (output_per_m > 0):
        logger.warning(
            "llm_config.partial_cost_override",
            extra={"config_id": str(getattr(config, "id", ""))},
        )
    return None


def resolve_model_prices(config: Any) -> Optional[ModelPrices]:
    """Return the prices to bill this model at, or ``None`` when unknown."""
    override = _admin_override(config)
    if override is not None:
        return ModelPrices(
            input_per_token=override[0],
            output_per_token=override[1],
            source="admin_override",
            matched_model=None,
        )

    model_name = _model_name(config)
    provider = _provider(config)
    alias_target = _PRICE_ALIASES.get(model_name.lower())
    for key in catalogue_candidates(model_name, provider):
        prices = _catalogue_prices(key)
        if prices is None:
            continue
        is_alias = alias_target is not None and (
            key == alias_target or key.endswith(f"/{alias_target}")
        )
        return ModelPrices(
            input_per_token=prices[0],
            output_per_token=prices[1],
            source="alias" if is_alias else "catalog",
            matched_model=key,
            aliased_from=model_name if is_alias else None,
        )
    return None


def describe_pricing(config: Any) -> str:
    """Operator-facing one-liner, used by setup and logs."""
    prices = resolve_model_prices(config)
    model = _model_name(config)
    if prices is None:
        return f"no catalogue price for model '{model}' — set rates in Admin → LLM configuration"
    in_per_m, out_per_m = prices.per_million()
    if prices.source == "admin_override":
        return f"pricing from admin override (${in_per_m:.4g}/${out_per_m:.4g} per M tokens)"
    if prices.source == "alias":
        return (
            f"pricing aliased '{prices.aliased_from}' → '{prices.matched_model}' "
            f"(${in_per_m:.4g}/${out_per_m:.4g} per M tokens)"
        )
    return f"pricing from catalogue '{prices.matched_model}' (${in_per_m:.4g}/${out_per_m:.4g} per M tokens)"


__all__ = [
    "ModelPrices",
    "catalogue_candidates",
    "canonical_model_name",
    "describe_pricing",
    "resolve_model_prices",
]
