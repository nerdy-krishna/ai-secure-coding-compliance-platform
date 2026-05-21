"""CI grep-check that operator-only scripts under ``app/scripts/``
are NOT imported by any production code path (router, service, repo,
MCP tool).

Per N10 (sast-prescan-followups threat model): the backfill script
mutates historical ``findings`` rows; if it were callable from a
router or MCP tool, it would grant write-all on the table. The
hardening posture is ``app/scripts/`` lives outside the import graph
of anything that handles HTTP / MCP traffic.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


_REPO_ROOT = Path(__file__).resolve().parent.parent
_PROD_DIRS = [
    _REPO_ROOT / "src" / "app" / "api",
    _REPO_ROOT / "src" / "app" / "core",
    _REPO_ROOT / "src" / "app" / "infrastructure",
    _REPO_ROOT / "src" / "app" / "shared",
    _REPO_ROOT / "src" / "app" / "workers",
]

_FORBIDDEN_PATTERNS = [
    re.compile(r"^\s*from\s+app\.scripts\b"),
    re.compile(r"^\s*import\s+app\.scripts\b"),
]


@pytest.mark.parametrize("prod_dir", _PROD_DIRS, ids=lambda p: p.name)
def test_no_prod_module_imports_app_scripts(prod_dir: Path):
    if not prod_dir.exists():
        pytest.skip(f"{prod_dir} does not exist")
    offenders = []
    for path in prod_dir.rglob("*.py"):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            for pattern in _FORBIDDEN_PATTERNS:
                if pattern.search(line):
                    offenders.append(f"{path}:{line_no}: {line.strip()}")
    assert not offenders, (
        "Production modules MUST NOT import from app.scripts:\n" + "\n".join(offenders)
    )
