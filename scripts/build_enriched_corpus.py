"""Render hand-authored enriched framework corpora into ingestable CSVs.

This is the "mini enrichment pass" (Framework Expansion follow-up):
instead of an LLM enrichment job, each security entry is hand-authored
as structured YAML — `security_rule`, `vulnerability_pattern`,
`secure_pattern`, and short `code_patterns` per language — and this
script renders it into the exact `**Security Rule** / [[LANG PATTERNS]]`
document the scan agents' `_extract_patterns_from_doc` consumes.

Source layout (per framework):
    src/app/data/<framework>_corpus/*.yaml   — one file per chapter/domain

Each YAML file holds a list of entries:
    - id: V1.1.1
      facet: Encoding and Sanitization      # control_family / concern_area
      section: Encoding and Sanitization Architecture
      level: 2                               # optional
      security_rule: "..."
      vulnerability_pattern: "..."            # concept description, no code
      secure_pattern: "..."                   # concept description, no code
      code_patterns:                          # short, seed-sized snippets
        generic:    {vulnerable: "...", secure: "..."}
        python:     {vulnerable: "...", secure: "..."}
        ...

Output: `src/app/data/<framework>_corpus.csv` with columns
`id, document, embed_text, <facet>`:
  * `document`   — the full enriched doc (stored, shown, pattern-parsed).
  * `embed_text` — concept-only text (rule + descriptions, no code); the
    RAG ingest embeds THIS, not the code-heavy document (lever 1).
  * `<facet>`    — the framework's retrieval facet column.

Usage:
    python scripts/build_enriched_corpus.py --framework asvs --write
    python scripts/build_enriched_corpus.py --framework asvs --check
"""

from __future__ import annotations

import argparse
import csv
import io
import sys
from pathlib import Path
from typing import Dict, Iterable, List

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
_DATA_DIR = REPO_ROOT / "src" / "app" / "data"

# framework → (corpus source-dir stem, retrieval facet column name).
# The entry `facet` (an ASVS chapter name) is written verbatim to the
# CSV: every chapter has a dedicated agent that filters retrieval on it.
_FRAMEWORKS: Dict[str, Dict[str, str]] = {
    "asvs": {"dir": "asvs_corpus", "facet": "control_family"},
}


def _facet(framework: str) -> str:
    return _FRAMEWORKS[framework]["facet"]


def _render_document(entry: Dict) -> str:
    """Render one entry into the enriched document the agents parse.

    The base block carries the generic `**Vulnerability Pattern**` /
    `**Secure Pattern**` fallback; each language adds a `[[LANG PATTERNS]]`
    block (the agent prefers the block matching the scanned file).
    """
    base = (
        f"**Security Rule:** {entry['security_rule'].strip()}\n\n"
        f"**Vulnerability Pattern (Description):** "
        f"{entry['vulnerability_pattern'].strip()}\n\n"
        f"**Secure Pattern (Description):** {entry['secure_pattern'].strip()}"
    )
    blocks = ""
    for language in sorted(entry.get("code_patterns") or {}):
        pair = entry["code_patterns"][language]
        blocks += (
            f"\n\n[[{language.upper()} PATTERNS]]\n"
            f"Vulnerable:\n```\n{pair['vulnerable'].strip()}\n```\n"
            f"Secure:\n```\n{pair['secure'].strip()}\n```"
        )
    return base + blocks


def _render_embed_text(entry: Dict) -> str:
    """Concept-only text for embedding (lever 1) — no code, so the vector
    represents the security concern, not code-token soup."""
    return (
        f"{entry['security_rule'].strip()}\n"
        f"{entry['vulnerability_pattern'].strip()}\n"
        f"{entry['secure_pattern'].strip()}"
    )


def _validate(entry: Dict, source: str) -> None:
    for field in (
        "id",
        "facet",
        "security_rule",
        "vulnerability_pattern",
        "secure_pattern",
    ):
        if not str(entry.get(field, "")).strip():
            raise SystemExit(f"{source}: entry missing '{field}': {entry.get('id')}")
    # The agent's pattern extractor captures `[^*\[]`; a `*` or `[` in a
    # pattern *description* would truncate the capture mid-block.
    for field in ("vulnerability_pattern", "secure_pattern"):
        text = entry[field]
        if "*" in text or "[" in text:
            raise SystemExit(
                f"{source}: '{field}' of {entry['id']} contains '*' or '[' "
                "(breaks the pattern extractor) — rephrase"
            )


def _rows(framework: str) -> List[Dict[str, str]]:
    corpus_dir = _DATA_DIR / _FRAMEWORKS[framework]["dir"]
    files = sorted(corpus_dir.glob("*.yaml"))
    if not files:
        raise SystemExit(f"no corpus YAML found under {corpus_dir}")
    facet = _facet(framework)
    rows: List[Dict[str, str]] = []
    seen: set = set()
    for path in files:
        entries = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        for entry in entries:
            _validate(entry, path.name)
            if entry["id"] in seen:
                raise SystemExit(f"{path.name}: duplicate entry id {entry['id']}")
            seen.add(entry["id"])
            rows.append(
                {
                    "id": entry["id"],
                    "document": _render_document(entry),
                    "embed_text": _render_embed_text(entry),
                    facet: entry["facet"],
                }
            )
    return rows


def _render_csv(framework: str, rows: List[Dict[str, str]]) -> str:
    columns = ["id", "document", "embed_text", _facet(framework)]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buf.getvalue()


def _csv_path(framework: str) -> Path:
    return _DATA_DIR / f"{_FRAMEWORKS[framework]['dir']}.csv"


def _write(framework: str) -> int:
    rows = _rows(framework)
    _csv_path(framework).write_text(_render_csv(framework, rows), encoding="utf-8")
    print(f"wrote {_csv_path(framework).relative_to(REPO_ROOT)} ({len(rows)} rows)")
    return 0


def _check(framework: str) -> int:
    expected = _render_csv(framework, _rows(framework))
    path = _csv_path(framework)
    if not path.exists():
        print(f"MISSING: {path.relative_to(REPO_ROOT)}")
        return 1
    if path.read_text(encoding="utf-8") != expected:
        print(f"DRIFT: {path.relative_to(REPO_ROOT)} — run --write, then commit.")
        return 1
    print(f"{framework} enriched corpus CSV is in sync with the YAML source.")
    return 0


def _parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", maxsplit=1)[0])
    parser.add_argument(
        "--framework",
        required=True,
        choices=sorted(_FRAMEWORKS),
        help="Which framework corpus to render.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", action="store_true", help="Regenerate the CSV.")
    group.add_argument("--check", action="store_true", help="Exit 1 on drift.")
    return parser.parse_args(list(argv))


def main(argv: Iterable[str]) -> int:
    args = _parse_args(argv)
    return _write(args.framework) if args.write else _check(args.framework)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
