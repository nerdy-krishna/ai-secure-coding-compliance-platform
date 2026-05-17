"""Framework Expansion #60 — bundled CWE Essentials RAG corpus.

Guards two things the ingested corpus depends on:

1. the corpus CSV stays in sync with its source markdown, and
2. every corpus `concern_area` exactly matches a CWE Essentials agent's
   retrieval facet — a mismatch would silently leave a CWE agent with
   no RAG content.
"""

from __future__ import annotations

import csv
import importlib.util
import pathlib

from app.core.services.default_seed_service import AGENT_DEFINITIONS

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_CSV_PATH = _REPO_ROOT / "src" / "app" / "data" / "cwe_essentials_corpus.csv"
_BUILD_SCRIPT = _REPO_ROOT / "scripts" / "build_cwe_corpus.py"


def _load_build_script():
    spec = importlib.util.spec_from_file_location("build_cwe_corpus", _BUILD_SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _csv_rows() -> list[dict]:
    with open(_CSV_PATH, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _agent_concern_areas() -> set[str]:
    areas: set[str] = set()
    for agent in AGENT_DEFINITIONS:
        if agent["applicable_frameworks"] != ["cwe_essentials"]:
            continue
        areas.update(agent["domain_query"]["metadata_filter"]["concern_area"])
    return areas


def test_corpus_covers_all_14_concern_areas():
    rows = _csv_rows()
    assert len(rows) == 14
    assert {"id", "document", "concern_area"} == set(rows[0].keys())


def test_corpus_concern_areas_match_cwe_agent_facets():
    """Each corpus document's `concern_area` must equal a CWE agent's
    retrieval facet — otherwise the agent retrieves nothing."""
    corpus_areas = {r["concern_area"] for r in _csv_rows()}
    assert corpus_areas == _agent_concern_areas()


def test_corpus_documents_are_non_empty_prose():
    for row in _csv_rows():
        assert len(row["document"].strip()) > 200, row["id"]


def test_corpus_csv_is_in_sync_with_source_markdown():
    """The committed CSV must match what the build script produces from
    the corpus markdown — guards against hand-edits and stale rebuilds."""
    build = _load_build_script()
    assert build._check() == 0
