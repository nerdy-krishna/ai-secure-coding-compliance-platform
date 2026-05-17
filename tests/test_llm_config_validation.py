"""Provider/model coherence validation for LLM configs.

`_validate_cfg` runs on every create and update. Beyond the provider
allowlist it now catches a provider/model *mismatch* — e.g. a DeepSeek
model saved under `provider="anthropic"`, which otherwise builds an
Anthropic client and 401s every agent call deep into a scan.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.infrastructure.database.repositories.llm_config_repo import (
    _provider_for_model,
    _validate_cfg,
)


def _cfg(provider: str, model_name: str) -> SimpleNamespace:
    return SimpleNamespace(
        name="test-config",
        provider=provider,
        model_name=model_name,
        input_cost_per_million=0.0,
        output_cost_per_million=0.0,
    )


@pytest.mark.parametrize(
    "model_name,expected",
    [
        ("deepseek-v4-flash", "deepseek"),
        ("deepseek-chat", "deepseek"),
        ("claude-opus-4-7", "anthropic"),
        ("gpt-4o", "openai"),
        ("o3-mini", "openai"),
        ("gemini-3.1-pro-preview", "google"),
        ("grok-2-latest", "xai"),
        ("some-private-endpoint-model", None),
        ("", None),
    ],
)
def test_provider_for_model_infers_from_signature(model_name, expected):
    assert _provider_for_model(model_name) == expected


def test_validate_rejects_provider_model_mismatch():
    """The exact bug class: a DeepSeek model under provider=anthropic."""
    with pytest.raises(ValueError, match="looks like a deepseek model"):
        _validate_cfg(_cfg("anthropic", "deepseek-v4-flash"))


def test_validate_rejects_anthropic_model_under_openai():
    with pytest.raises(ValueError, match="looks like an? anthropic model"):
        _validate_cfg(_cfg("openai", "claude-sonnet-4-6"))


@pytest.mark.parametrize(
    "provider,model_name",
    [
        ("deepseek", "deepseek-v4-flash"),
        ("deepseek", "deepseek-chat"),
        ("anthropic", "claude-opus-4-7"),
        ("openai", "gpt-4o"),
        ("google", "gemini-3.1-pro-preview"),
        ("xai", "grok-2-latest"),
    ],
)
def test_validate_accepts_matching_provider_and_model(provider, model_name):
    _validate_cfg(_cfg(provider, model_name))  # must not raise


def test_validate_allows_unrecognised_model_name():
    """A model name with no known signature is left alone — a new or
    privately-hosted model must not be falsely rejected."""
    _validate_cfg(_cfg("openai", "my-companys-private-model"))


def test_validate_still_rejects_unsupported_provider():
    with pytest.raises(ValueError, match="Unsupported provider"):
        _validate_cfg(_cfg("bogus-vendor", "gpt-4o"))


def test_validate_rejects_empty_model_name():
    with pytest.raises(ValueError, match="model_name"):
        _validate_cfg(_cfg("openai", ""))
