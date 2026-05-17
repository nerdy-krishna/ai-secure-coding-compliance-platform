"""Assemble a bundled framework RAG corpus CSV from its source markdown.

Some frameworks ship a RAG corpus inside the repository (Framework
Expansion #60 / #62). Each is authored as one markdown file per
concern-area — the human-reviewable source of truth, written as
original prose — under `src/app/data/<framework>_corpus/`. Operators
ingest the corpus through the Admin → RAG preprocess flow, which
consumes a CSV, so this script flattens the markdown into
`src/app/data/<framework>_corpus.csv`.

Supported frameworks:

* `cwe_essentials` — MITRE CWE Top 25 (2025), 14 concern-areas.
* `isvs` — OWASP IoT Security Verification Standard, 7 concern-areas.

Each markdown file carries a small frontmatter block; only
`concern_area` is required:

    ---
    concern_area: Firmware Integrity & Secure Boot
    edition: OWASP ISVS 1.0
    ---

The CSV columns are `id` (the file stem), `document` (the markdown body
after the frontmatter), and `concern_area` (the metadata facet a
framework agent filters retrieval on — see Framework Expansion #56).

Usage:
    python scripts/build_corpus.py --framework isvs --write
    python scripts/build_corpus.py --framework cwe_essentials --check

Output is deterministic: sorted file order, LF endings, UTF-8.
"""

from __future__ import annotations

import argparse
import csv
import io
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
_DATA_DIR = REPO_ROOT / "src" / "app" / "data"

# framework name → corpus directory stem under src/app/data/.
_CORPORA = {
    "cwe_essentials": "cwe_essentials_corpus",
    "isvs": "isvs_corpus",
}

_CSV_COLUMNS = ["id", "document", "concern_area"]


def _corpus_dir(framework: str) -> Path:
    return _DATA_DIR / _CORPORA[framework]


def _csv_path(framework: str) -> Path:
    return _DATA_DIR / f"{_CORPORA[framework]}.csv"


def _parse_frontmatter(text: str) -> Tuple[Dict[str, str], str]:
    """Split a `---`-delimited frontmatter block from the markdown body.

    Returns `(frontmatter_dict, body)`. Raises ValueError if the file
    has no frontmatter or no `concern_area` key.
    """
    if not text.startswith("---\n"):
        raise ValueError("missing frontmatter block")
    end = text.find("\n---\n", 4)
    if end == -1:
        raise ValueError("unterminated frontmatter block")
    front: Dict[str, str] = {}
    for line in text[4:end].splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        front[key.strip()] = value.strip()
    if "concern_area" not in front:
        raise ValueError("frontmatter missing 'concern_area'")
    body = text[end + len("\n---\n") :].lstrip("\n")
    return front, body


def _rows(framework: str) -> List[Dict[str, str]]:
    """Build the CSV rows from the corpus markdown, sorted by file name."""
    corpus_dir = _corpus_dir(framework)
    files = sorted(corpus_dir.glob("*.md"))
    if not files:
        raise SystemExit(f"no corpus markdown found under {corpus_dir}")
    rows: List[Dict[str, str]] = []
    for path in files:
        front, body = _parse_frontmatter(path.read_text(encoding="utf-8"))
        rows.append(
            {
                "id": path.stem,
                "document": body.rstrip("\n") + "\n",
                "concern_area": front["concern_area"],
            }
        )
    return rows


def _render_csv(rows: List[Dict[str, str]]) -> str:
    """Render rows to a deterministic CSV string (LF line endings)."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buf.getvalue()


def _write(framework: str) -> int:
    rows = _rows(framework)
    csv_path = _csv_path(framework)
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        f.write(_render_csv(rows))
    print(f"wrote {csv_path.relative_to(REPO_ROOT)} ({len(rows)} rows)")
    return 0


def _check(framework: str) -> int:
    expected = _render_csv(_rows(framework))
    csv_path = _csv_path(framework)
    if not csv_path.exists():
        print(f"MISSING: {csv_path.relative_to(REPO_ROOT)}")
        print(f"Run `python scripts/build_corpus.py --framework {framework} --write`.")
        return 1
    if csv_path.read_text(encoding="utf-8") != expected:
        print(
            f"DRIFT: {csv_path.relative_to(REPO_ROOT)} is out of sync with the "
            "corpus markdown."
        )
        print(
            f"Run `python scripts/build_corpus.py --framework {framework} --write`, "
            "then commit."
        )
        return 1
    print(f"{framework} corpus CSV is in sync with the source markdown.")
    return 0


def _parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", maxsplit=1)[0])
    parser.add_argument(
        "--framework",
        required=True,
        choices=sorted(_CORPORA),
        help="Which bundled corpus to build.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", action="store_true", help="Regenerate the CSV.")
    group.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if the committed CSV diverges from the markdown.",
    )
    return parser.parse_args(list(argv))


def main(argv: Iterable[str]) -> int:
    args = _parse_args(argv)
    return _write(args.framework) if args.write else _check(args.framework)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
