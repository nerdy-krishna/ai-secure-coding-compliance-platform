"""Tool-choice fallback detection for structured output.

Some models — DeepSeek's reasoner is the known case — reject
tool-based (function-calling) structured output. `generate_structured_output`
falls back to prompt-based output when `_is_tool_choice_unsupported`
recognises the error.
"""

from __future__ import annotations

import pytest

from app.infrastructure.llm_client import _is_tool_choice_unsupported


@pytest.mark.parametrize(
    "message",
    [
        # The exact DeepSeek-reasoner 400 body.
        "status_code: 400, model_name: deepseek-v4-pro, body: "
        "{'message': 'deepseek-reasoner does not support this tool_choice'}",
        "This model does not support function calling.",
        "tool calling is not available for this model",
        "Error: does not support tool use",
    ],
)
def test_recognises_tool_unsupported_errors(message):
    assert _is_tool_choice_unsupported(Exception(message)) is True


@pytest.mark.parametrize(
    "message",
    [
        "Error code: 401 - invalid x-api-key",
        "rate limit exceeded, retry after 60s",
        "Connection reset by peer",
        "schema validation failed after 2 retries",
        "status_code: 500, internal server error",
    ],
)
def test_ignores_unrelated_errors(message):
    assert _is_tool_choice_unsupported(Exception(message)) is False
