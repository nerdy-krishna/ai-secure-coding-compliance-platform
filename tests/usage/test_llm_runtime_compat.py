from __future__ import annotations

import unittest
from types import SimpleNamespace

from app.infrastructure.llm_client import _prefers_prompted_output
from app.infrastructure.llm_usage_capture import _run_usage


class LLMRuntimeCompatibilityTests(unittest.TestCase):
    def test_deepseek_uses_prompted_structured_output_on_first_request(self) -> None:
        self.assertTrue(_prefers_prompted_output("deepseek", "deepseek-v4-pro"))
        self.assertTrue(_prefers_prompted_output("deepseek", "deepseek-reasoner"))
        self.assertFalse(_prefers_prompted_output("openai", "gpt-5"))

    def test_usage_accessor_supports_property_and_legacy_method(self) -> None:
        usage = SimpleNamespace(input_tokens=3, output_tokens=2, tool_calls=0)
        self.assertIs(_run_usage(SimpleNamespace(usage=usage)), usage)
        self.assertIs(_run_usage(SimpleNamespace(usage=lambda: usage)), usage)


if __name__ == "__main__":
    unittest.main()
