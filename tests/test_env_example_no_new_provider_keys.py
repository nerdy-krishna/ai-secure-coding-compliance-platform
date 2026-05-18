"""Regression: `.env.example` must not carry plaintext provider API-key placeholders.

CLAUDE.md H.0.2 forbids `OPENAI_API_KEY` / `GOOGLE_API_KEY` placeholders
in `.env.example` — the same rule applies to any new provider added to
the supported set. Keys are configured at runtime through the admin UI
and stored Fernet-encrypted in `llm_configurations.encrypted_api_key`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

ENV_EXAMPLE = Path(__file__).resolve().parents[1] / ".env.example"


def test_env_example_omits_new_provider_keys():
    # `.env.example` lives at the repo root but is not copied into the
    # Docker image, so this filesystem check can only run where the repo
    # is checked out (host / CI). Skip cleanly in the container rather
    # than fail on a missing file.
    if not ENV_EXAMPLE.is_file():
        pytest.skip(".env.example not present in this environment")
    body = ENV_EXAMPLE.read_text(encoding="utf-8")
    assert "DEEPSEEK_API_KEY" not in body, (
        "DEEPSEEK_API_KEY placeholder must not be added to .env.example "
        "(CLAUDE.md H.0.2). Keys go through the admin UI."
    )
    assert "XAI_API_KEY" not in body, (
        "XAI_API_KEY placeholder must not be added to .env.example "
        "(CLAUDE.md H.0.2). Keys go through the admin UI."
    )
