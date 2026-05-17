"""Assemble the CWE Essentials RAG corpus CSV from its source markdown.

The bundled CWE Essentials corpus (Framework Expansion #60) is authored
as one markdown file per concern-area under
`src/app/data/cwe_essentials_corpus/` — the human-reviewable source of
truth, written as original prose. Operators ingest the corpus through
the Admin → RAG preprocess flow, which consumes a CSV, so this script
flattens the markdown into `src/app/data/cwe_essentials_corpus.csv`.

Each markdown file carries a small frontmatter block:

    ---
    concern_area: Spatial Memory Safety
    cwes: CWE-787, CWE-125, ...
    edition: CWE Top 25 (2025)
    ---

The CSV columns are `id` (the file stem), `document` (the markdown body
after the frontmatter), and `concern_area` (the metadata facet a CWE
Essentials agent filters retrieval on — see Framework Expansion #56).

Usage:
    python scripts/build_cwe_corpus.py --write   # regenerate the CSV
    python scripts/build_cwe_corpus.py --check   # exit 1 on drift

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
CORPUS_DIR = REPO_ROOT / "src" / "app" / "data" / "cwe_essentials_corpus"
CSV_PATH = REPO_ROOT / "src" / "app" / "data" / "cwe_essentials_corpus.csv"

_CSV_COLUMNS = ["id", "document", "concern_area"]


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


def _rows() -> List[Dict[str, str]]:
    """Build the CSV rows from the corpus markdown, sorted by file name."""
    files = sorted(CORPUS_DIR.glob("*.md"))
    if not files:
        raise SystemExit(f"no corpus markdown found under {CORPUS_DIR}")
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


def _write() -> int:
    content = _render_csv(_rows())
    with open(CSV_PATH, "w", encoding="utf-8", newline="") as f:
        f.write(content)
    print(f"wrote {CSV_PATH.relative_to(REPO_ROOT)} ({len(_rows())} rows)")
    return 0


def _check() -> int:
    expected = _render_csv(_rows())
    if not CSV_PATH.exists():
        print(f"MISSING: {CSV_PATH.relative_to(REPO_ROOT)}")
        print("Run `python scripts/build_cwe_corpus.py --write`.")
        return 1
    actual = CSV_PATH.read_text(encoding="utf-8")
    if actual != expected:
        print(
            f"DRIFT: {CSV_PATH.relative_to(REPO_ROOT)} is out of sync with the corpus markdown."
        )
        print("Run `python scripts/build_cwe_corpus.py --write`, then commit.")
        return 1
    print("CWE Essentials corpus CSV is in sync with the source markdown.")
    return 0


def _parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", maxsplit=1)[0])
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
    return _write() if args.write else _check()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
