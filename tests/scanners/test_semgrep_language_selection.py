import unittest

from app.infrastructure.scanners.semgrep_rules import derive_semgrep_languages


class SemgrepLanguageSelectionTests(unittest.TestCase):
    def test_derives_supported_languages_without_duplicates(self) -> None:
        self.assertEqual(
            derive_semgrep_languages(
                ["src/a.py", "src/b.py", "ui/main.tsx", "README.md"]
            ),
            ["python", "typescript"],
        )

    def test_returns_languages_in_stable_order(self) -> None:
        paths = ["z/main.go", "a/main.java", "web/app.js"]
        self.assertEqual(derive_semgrep_languages(paths), ["go", "java", "javascript"])


if __name__ == "__main__":
    unittest.main()
