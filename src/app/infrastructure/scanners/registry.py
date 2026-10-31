"""Per-file scanner routing + minified-bundle detection.

Mirrors the extension-based routing used by the LLM agents (see
`shared/lib/agent_routing.resolve_agents_for_file`). Bandit is
Python-only; Semgrep is eligible for the supported multi-language
subset and applies the scan's database-selected rules; Gitleaks scans
any text-shaped file for secret patterns.

Minified bundles (`*.min.js`, `*.bundle.js`, `*.min.css`) carry a
lower per-file byte cap to dodge Semgrep's documented multi-minute
parse pathology on large minified inputs.
"""

from __future__ import annotations

from typing import List


#: Extension/filename → language → scanner capability all live in one table now.
#: The per-scanner allow-lists that used to be here diverged: Semgrep was limited to
#: 15 extensions while the rule database covered many more languages, so Kotlin, Rust,
#: shell and SQL files never reached a scanner that could read them.
from app.shared.lib.language_registry import language_for, scanners_for  # noqa: E402

MINIFIED_BYTE_LIMIT = 10 * 1024 * 1024

_MINIFIED_SUFFIXES = (".min.js", ".bundle.js", ".min.css")


def is_minified(rel_path: str) -> bool:
    """Heuristic: does the path look like a minified web bundle?"""
    lowered = rel_path.lower()
    return any(lowered.endswith(suffix) for suffix in _MINIFIED_SUFFIXES)


def scanners_for_file(rel_path: str) -> List[str]:
    """Return the scanners that can read ``rel_path``.

    Capability only — whether a file *should* be scanned is a role decision made by
    `file_classification` (vendor bundles are readable by Semgrep but not worth its
    time). Name-based languages (`Dockerfile`, `Makefile`, `requirements.txt`) are
    resolved too, which the extension-only version could not do.
    """
    return scanners_for(rel_path)


def language_for_file(rel_path: str) -> str | None:
    """Language of ``rel_path`` per the shared registry."""
    return language_for(rel_path)
