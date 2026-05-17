"""Framework Expansion #60 / #62 — bundled RAG corpora.

Covers the two frameworks that ship a RAG corpus in the repository —
CWE Essentials and OWASP ISVS. For each, guards that:

1. the corpus CSV stays in sync with its source markdown, and
2. every corpus `concern_area` exactly matches one of that framework's
   agent retrieval facets — a mismatch would silently leave an agent
   with no RAG content.
"""

from __future__ import annotations

import csv
import importlib.util
import pathlib

import pytest

from app.core.services.default_seed_service import AGENT_DEFINITIONS

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_BUILD_SCRIPT = _REPO_ROOT / "scripts" / "build_corpus.py"

# framework → (corpus CSV path, expected concern-area count).
_CORPORA = {
    "cwe_essentials": ("cwe_essentials_corpus.csv", 14),
    "isvs": ("isvs_corpus.csv", 7),
}


def _load_build_script():
    spec = importlib.util.spec_from_file_location("build_corpus", _BUILD_SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _csv_rows(framework: str) -> list[dict]:
    path = _REPO_ROOT / "src" / "app" / "data" / _CORPORA[framework][0]
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _agent_concern_areas(framework: str) -> set[str]:
    areas: set[str] = set()
    for agent in AGENT_DEFINITIONS:
        if agent["applicable_frameworks"] != [framework]:
            continue
        areas.update(agent["domain_query"]["metadata_filter"]["concern_area"])
    return areas


@pytest.mark.parametrize("framework", sorted(_CORPORA))
def test_corpus_covers_expected_concern_areas(framework: str):
    rows = _csv_rows(framework)
    assert len(rows) == _CORPORA[framework][1]
    assert {"id", "document", "concern_area"} == set(rows[0].keys())


@pytest.mark.parametrize("framework", sorted(_CORPORA))
def test_corpus_concern_areas_match_agent_facets(framework: str):
    """Each corpus document's `concern_area` must equal an agent's
    retrieval facet — otherwise the agent retrieves nothing."""
    corpus_areas = {r["concern_area"] for r in _csv_rows(framework)}
    assert corpus_areas == _agent_concern_areas(framework)


@pytest.mark.parametrize("framework", sorted(_CORPORA))
def test_corpus_documents_are_non_empty_prose(framework: str):
    for row in _csv_rows(framework):
        assert len(row["document"].strip()) > 200, row["id"]


@pytest.mark.parametrize("framework", sorted(_CORPORA))
def test_corpus_documents_carry_pattern_blocks(framework: str):
    """The build relabels each doc's weakness / mitigation paragraphs as
    `**Vulnerability Pattern**` / `**Secure Pattern**` blocks — the only
    shape the scan agent's `_extract_patterns_from_doc` consumes."""
    for row in _csv_rows(framework):
        assert "**Vulnerability Pattern (" in row["document"], row["id"]
        assert "**Secure Pattern (" in row["document"], row["id"]


@pytest.mark.parametrize("framework", sorted(_CORPORA))
def test_corpus_csv_is_in_sync_with_source_markdown(framework: str):
    """The committed CSV must match what the build script produces from
    the corpus markdown — guards against hand-edits and stale rebuilds."""
    build = _load_build_script()
    assert build._check(framework) == 0
