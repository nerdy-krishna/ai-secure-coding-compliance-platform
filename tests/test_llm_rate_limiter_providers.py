"""Per-provider LLM rate limiters.

Regression guard for the DeepSeek/xAI rollout: every provider the LLM
client can build a model for must have a rate limiter, or
`get_rate_limiter_for_provider` fails the whole scan. This pins that
invariant and the conservative-fallback behaviour.
"""

from __future__ import annotations

import typing

import pytest

from app.api.v1.models import LLMConfigurationBase
from app.infrastructure import llm_client_rate_limiter as rl


def test_provider_settings_covers_every_schema_provider():
    """Every `provider` the LLMConfiguration schema accepts must have
    rate-limit settings — otherwise its scans hit the fallback path."""
    literal = LLMConfigurationBase.model_fields["provider"].annotation
    schema_providers = set(typing.get_args(literal))
    configured = set(rl._provider_settings())
    missing = schema_providers - configured
    assert not missing, f"providers without rate-limit settings: {missing}"


@pytest.mark.parametrize(
    "provider", ["openai", "anthropic", "google", "deepseek", "xai"]
)
def test_every_supported_provider_has_a_rate_limiter(provider):
    rl.initialize_rate_limiters()  # idempotent
    limiter = rl.get_rate_limiter_for_provider(provider)
    assert limiter is not None


def test_provider_lookup_is_case_insensitive():
    rl.initialize_rate_limiters()
    assert rl.get_rate_limiter_for_provider(
        "DeepSeek"
    ) is rl.get_rate_limiter_for_provider("deepseek")


def test_unknown_provider_falls_back_instead_of_failing():
    """A provider with no explicit limiter is rate-limited conservatively
    rather than raising — a config gap must not fail every scan."""
    rl.initialize_rate_limiters()
    try:
        limiter = rl.get_rate_limiter_for_provider("some-future-provider")
        assert limiter is not None
        # The fallback limiter is cached so the warning fires once.
        assert rl.get_rate_limiter_for_provider("some-future-provider") is limiter
    finally:
        rl.provider_rate_limiters.pop("some-future-provider", None)
