"""Materialise SCCAP prompt templates into the evals tree.

The eval framework needs the same prompt strings the worker actually
runs. Hand-copying them creates drift the moment someone edits the
canonical seed — so we extract them at build time from the canonical
seed-prompt markdown files (`app/core/services/seed_prompts/*.md`, the
exact files `default_seed_service._load_prompt` reads) and commit the
result. CI runs `--check` on every PR; the build fails if the committed
files don't match the regenerated output.

Usage:
    python scripts/extract_eval_prompts.py --write  # regenerate
    python scripts/extract_eval_prompts.py --check  # exit 1 on diff

Output is deterministic: sorted iteration over the target paths, LF
endings, UTF-8 encoding.
"""

from __future__ import annotations

import argparse
import difflib
import sys
from pathlib import Path
from typing import Dict, Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent
EVALS_DIR = REPO_ROOT / "evals"

# Canonical prompt templates live as markdown files under the seed's
# `seed_prompts/` directory; `default_seed_service._load_prompt` reads
# exactly these. Read them straight off disk here rather than importing
# the seed module — that module pulls in the whole app (SQLAlchemy,
# pydantic `Settings`) and is not importable in the lightweight eval CI
# job (`poetry install --no-root`, no app env vars).
_SEED_PROMPTS_DIR = REPO_ROOT / "src" / "app" / "core" / "services" / "seed_prompts"


def _load_seed_prompt(filename: str) -> str:
    return (_SEED_PROMPTS_DIR / filename).read_text(encoding="utf-8")


_AUDIT_TEMPLATE = _load_seed_prompt("audit.md")
_REMEDIATION_TEMPLATE = _load_seed_prompt("remediation.md")
_CHAT_TEMPLATE = _load_seed_prompt("chat.md")


def _targets() -> Dict[Path, str]:
    """Map of {output_path: prompt_text} to materialise.

    Sorted so iteration order is stable across Python versions.
    """
    mapping: Dict[Path, str] = {
        EVALS_DIR
        / "agents"
        / "generic_specialized"
        / "prompts"
        / "quick_audit.txt": _AUDIT_TEMPLATE,
        EVALS_DIR
        / "agents"
        / "generic_specialized"
        / "prompts"
        / "detailed_remediation.txt": _REMEDIATION_TEMPLATE,
        EVALS_DIR / "agents" / "chat" / "prompts" / "chat.txt": _CHAT_TEMPLATE,
    }
    return dict(sorted(mapping.items()))


def _normalise(text: str) -> str:
    """LF endings, single trailing newline."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text.rstrip("\n") + "\n"


def _write(targets: Dict[Path, str]) -> None:
    for path, text in targets.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        # Use open() rather than Path.write_text(newline=...) so the
        # script runs on Python 3.9+ (write_text gained `newline` in
        # 3.10).
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(_normalise(text))
        print(f"wrote {path.relative_to(REPO_ROOT)}")


def _check(targets: Dict[Path, str]) -> int:
    """Diff committed files against the canonical templates.

    Exit 0 on parity, 1 on any drift; prints the unified diff so CI
    log readers can see what changed.
    """
    drift = 0
    for path, text in targets.items():
        expected = _normalise(text)
        if not path.exists():
            print(f"MISSING: {path.relative_to(REPO_ROOT)}")
            drift += 1
            continue
        actual = path.read_text(encoding="utf-8")
        if actual != expected:
            drift += 1
            print(f"DRIFT: {path.relative_to(REPO_ROOT)}")
            for line in difflib.unified_diff(
                actual.splitlines(keepends=True),
                expected.splitlines(keepends=True),
                fromfile=f"committed/{path.name}",
                tofile=f"canonical/{path.name}",
            ):
                sys.stdout.write(line)
    if drift:
        print(
            f"\n{drift} file(s) drifted. Run `python scripts/extract_eval_prompts.py --write` "
            "to regenerate, then commit the result."
        )
        return 1
    print("All prompt files in sync with the canonical seed.")
    return 0


def _parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", maxsplit=1)[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--write", action="store_true", help="Regenerate the prompt files."
    )
    group.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if committed files diverge from the canonical templates.",
    )
    return parser.parse_args(list(argv))


def main(argv: Iterable[str]) -> int:
    args = _parse_args(argv)
    targets = _targets()
    if args.write:
        _write(targets)
        return 0
    return _check(targets)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
