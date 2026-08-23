"""Repository contracts that prevent un-attributed model calls."""

from __future__ import annotations

import ast
import inspect
import unittest
from pathlib import Path

from app.infrastructure.llm_client import LLMClient


ROOT = Path(__file__).resolve().parents[2]


class UsageCallsiteContractTests(unittest.TestCase):
    def test_usage_context_is_required_and_keyword_only(self) -> None:
        parameter = inspect.signature(LLMClient.generate_structured_output).parameters[
            "usage_context"
        ]

        self.assertEqual(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIs(parameter.default, inspect.Parameter.empty)

    def test_every_production_call_supplies_usage_context(self) -> None:
        missing: list[str] = []
        for path in sorted((ROOT / "src" / "app").rglob("*.py")):
            if path.name == "llm_client.py":
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                function = node.func
                if not (
                    isinstance(function, ast.Attribute)
                    and function.attr == "generate_structured_output"
                ):
                    continue
                if not any(keyword.arg == "usage_context" for keyword in node.keywords):
                    missing.append(f"{path.relative_to(ROOT)}:{node.lineno}")

        self.assertEqual(missing, [], f"un-attributed LLM calls: {missing}")


if __name__ == "__main__":
    unittest.main()
