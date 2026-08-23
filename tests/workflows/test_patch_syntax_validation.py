import unittest
from unittest.mock import patch

from app.infrastructure.workflows.nodes.consolidate import (
    _verify_syntax_with_treesitter,
)


class PatchSyntaxValidationTests(unittest.TestCase):
    def test_missing_tree_sitter_is_explicit_tool_missing(self):
        with patch(
            "app.infrastructure.workflows.nodes.consolidate.HAS_TREE_SITTER",
            False,
        ):
            result = _verify_syntax_with_treesitter("const value = 1;\n", "src/app.js")
        self.assertEqual(result.status, "tool_missing")
        self.assertTrue(result.blocking)

    def test_unknown_language_is_explicit_skipped(self):
        with patch(
            "app.infrastructure.workflows.nodes.consolidate.HAS_TREE_SITTER",
            True,
        ):
            result = _verify_syntax_with_treesitter("key: value\n", "config.yaml")
        self.assertEqual(result.status, "skipped")
        self.assertTrue(result.blocking)

    def test_jsx_and_tsx_select_their_allowlisted_parsers(self):
        for filename, language in (
            ("src/App.jsx", "javascript"),
            ("src/App.tsx", "tsx"),
        ):
            with (
                self.subTest(filename=filename),
                patch(
                    "app.infrastructure.workflows.nodes.consolidate.HAS_TREE_SITTER",
                    True,
                ),
                patch(
                    "app.infrastructure.workflows.nodes.consolidate.ts_get_parser"
                ) as parser_factory,
            ):
                parser_factory.return_value.parse.return_value.root_node.has_error = (
                    False
                )
                result = _verify_syntax_with_treesitter(
                    "export default null;\n", filename
                )
            parser_factory.assert_called_once_with(language)
            self.assertEqual(result.status, "passed")

    def test_parser_exception_is_infrastructure_error(self):
        with (
            patch(
                "app.infrastructure.workflows.nodes.consolidate.HAS_TREE_SITTER",
                True,
            ),
            patch(
                "app.infrastructure.workflows.nodes.consolidate.ts_get_parser",
                side_effect=RuntimeError("broken parser"),
            ),
        ):
            result = _verify_syntax_with_treesitter("value = 1\n", "src/app.py")
        self.assertEqual(result.status, "infrastructure_error")
        self.assertTrue(result.blocking)


if __name__ == "__main__":
    unittest.main()
