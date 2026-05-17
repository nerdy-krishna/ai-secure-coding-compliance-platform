"""Convert the OWASP ASVS CSV into a pattern-formatted RAG corpus CSV.

Reads `src/app/data/asvs_5.0.0_source.csv` — the OWASP Application
Security Verification Standard 5.0.0 export (© OWASP Foundation,
CC BY-SA 4.0) — and writes `src/app/data/asvs_corpus.csv`: one document
per verification requirement, in the `**Vulnerability Pattern**` /
`**Secure Pattern**` layout the scan agents parse. No LLM enrichment —
the requirement text is framed deterministically (a violation of the
requirement is the vulnerability pattern; compliance is the secure
pattern).

Each ASVS chapter maps to a `control_family` facet matching the ASVS
agents' retrieval filter. Three chapters whose ASVS 5.0 name differs
from the agent vocabulary are aliased (see `_CHAPTER_ALIAS`).

Usage:
    python scripts/build_asvs_corpus.py --write   # regenerate the CSV
    python scripts/build_asvs_corpus.py --check   # exit 1 on drift
"""

from __future__ import annotations

import argparse
import csv
import io
import sys
from pathlib import Path
from typing import Dict, Iterable, List

REPO_ROOT = Path(__file__).resolve().parent.parent
_DATA_DIR = REPO_ROOT / "src" / "app" / "data"
_SOURCE_CSV = _DATA_DIR / "asvs_5.0.0_source.csv"
_OUTPUT_CSV = _DATA_DIR / "asvs_corpus.csv"

_CSV_COLUMNS = ["id", "document", "control_family"]

# ASVS 5.0 chapter name → the `control_family` facet the `Asvs*` agents
# filter retrieval on. Chapters not listed keep their name verbatim
# (the chapter name already equals the agents' control_family value).
_CHAPTER_ALIAS: Dict[str, str] = {
    "Web Frontend Security": "Client Side",
    "Self-contained Tokens": "Session Management",
    "WebRTC": "Client Side",
}


def _control_family(chapter_name: str) -> str:
    return _CHAPTER_ALIAS.get(chapter_name, chapter_name)


def _safe(text: str) -> str:
    """Drop characters that truncate the agent's pattern extractor.

    `_extract_patterns_from_doc` captures `[^*\\[]`, so a `*` or `[` in
    the requirement text would cut the captured block short.
    """
    return text.replace("*", "").replace("[", "(").replace("]", ")").strip()


def _document(row: Dict[str, str]) -> str:
    chapter = row["chapter_name"].strip()
    control_family = _control_family(chapter)
    req_id = row["req_id"].strip()
    requirement = _safe(row["req_description"])
    section = _safe(row["section_name"])
    level = (row.get("L") or "").strip()
    level_note = f" (verification level {level})" if level else ""
    intro = (
        f'OWASP ASVS 5.0 requirement {req_id}, in the "{section}" section '
        f"of the {chapter} chapter{level_note}."
    )
    return (
        f"# ASVS {req_id} — {chapter}\n\n{intro}\n\n"
        f"**Vulnerability Pattern ({control_family}):**\n\n"
        f"A finding for ASVS {req_id} applies when the code does not "
        f"satisfy this verification requirement: {requirement}\n\n"
        f"**Secure Pattern ({control_family}):**\n\n"
        f"ASVS {req_id} — compliant code satisfies: {requirement}\n"
    )


def _rows() -> List[Dict[str, str]]:
    if not _SOURCE_CSV.exists():
        raise SystemExit(f"ASVS source CSV not found: {_SOURCE_CSV}")
    with open(_SOURCE_CSV, encoding="utf-8", newline="") as f:
        source = list(csv.DictReader(f))
    if not source:
        raise SystemExit(f"ASVS source CSV is empty: {_SOURCE_CSV}")
    rows: List[Dict[str, str]] = []
    for row in source:
        rows.append(
            {
                "id": row["req_id"].strip(),
                "document": _document(row),
                "control_family": _control_family(row["chapter_name"].strip()),
            }
        )
    return rows


def _render_csv(rows: List[Dict[str, str]]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buf.getvalue()


def _write() -> int:
    rows = _rows()
    with open(_OUTPUT_CSV, "w", encoding="utf-8", newline="") as f:
        f.write(_render_csv(rows))
    print(f"wrote {_OUTPUT_CSV.relative_to(REPO_ROOT)} ({len(rows)} rows)")
    return 0


def _check() -> int:
    expected = _render_csv(_rows())
    if not _OUTPUT_CSV.exists():
        print(f"MISSING: {_OUTPUT_CSV.relative_to(REPO_ROOT)}")
        return 1
    if _OUTPUT_CSV.read_text(encoding="utf-8") != expected:
        print(
            f"DRIFT: {_OUTPUT_CSV.relative_to(REPO_ROOT)} is out of sync with "
            "the ASVS source CSV. Run `--write`, then commit."
        )
        return 1
    print("ASVS corpus CSV is in sync with the source CSV.")
    return 0


def _parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", maxsplit=1)[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", action="store_true", help="Regenerate the CSV.")
    group.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if the committed CSV diverges from the source.",
    )
    return parser.parse_args(list(argv))


def main(argv: Iterable[str]) -> int:
    args = _parse_args(argv)
    return _write() if args.write else _check()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
