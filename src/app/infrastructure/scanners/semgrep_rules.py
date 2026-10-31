"""Shared Semgrep rule-selection helpers."""

from __future__ import annotations

from collections.abc import Iterable

from app.shared.lib.language_registry import language_for


#: Registry language → Semgrep's own language identifier. Only languages Semgrep
#: actually parses are listed; anything else is dropped rather than passed to the
#: rule selector, which would return no rules and silently skip the scanner.
_SEMGREP_LANGUAGES: dict[str, str] = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "typescript",
    "java": "java",
    "kotlin": "kotlin",
    "scala": "scala",
    "go": "go",
    "ruby": "ruby",
    "php": "php",
    "csharp": "csharp",
    "fsharp": "fsharp",
    "visualbasic": "generic",
    "c": "c",
    "cpp": "cpp",
    "rust": "rust",
    "swift": "swift",
    "dart": "dart",
    "lua": "lua",
    "perl": "generic",
    "elixir": "elixir",
    "erlang": "generic",
    "haskell": "generic",
    "clojure": "clojure",
    "groovy": "generic",
    "solidity": "solidity",
    "terraform": "hcl",
    "dockerfile": "dockerfile",
    "sql": "generic",
    "json": "json",
    "yaml": "yaml",
    "html": "html",
}


def semgrep_language_for(path: str) -> str | None:
    """Semgrep language identifier for a path, or None when it cannot parse it."""
    return _SEMGREP_LANGUAGES.get(language_for(path) or "")


def derive_semgrep_languages(file_paths: Iterable[str]) -> list[str]:
    """Return stable, deduplicated Semgrep language names for paths.

    Derived from the shared language registry, so a Kotlin or Rust repository derives
    its languages instead of looking like a tree with nothing Semgrep can read.
    """
    languages = {
        language
        for path in file_paths
        if (language := semgrep_language_for(path)) is not None
    }
    return sorted(languages)
