"""Shared Semgrep rule-selection helpers."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import PurePosixPath


_EXT_TO_SEMGREP_LANG: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".h": "c",
    ".hpp": "cpp",
}


def derive_semgrep_languages(file_paths: Iterable[str]) -> list[str]:
    """Return stable, deduplicated Semgrep language names for paths."""
    languages = {
        language
        for path in file_paths
        if (language := _EXT_TO_SEMGREP_LANG.get(PurePosixPath(path).suffix.lower()))
    }
    return sorted(languages)
