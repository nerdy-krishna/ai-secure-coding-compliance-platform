"""Bundled RAG corpora — CWE Essentials and OWASP ISVS.

Both frameworks ship an enriched RAG corpus in the repository, rendered
from per-concern-area YAML by `scripts/build_enriched_corpus.py`. For
each, this guards that:

1. the corpus CSV stays in sync with its YAML source,
2. every corpus `concern_area` exactly matches one of that framework's
   agent retrieval facets (a mismatch silently starves an agent), and
3. the enriched documents carry the pattern blocks the scan agent's
   extractor consumes, with concept-only `embed_text` (RAG lever 1).
"""

from __future__ import annotations

import csv
import importlib.util
import pathlib

import pytest

from app.core.services.default_seed_service import AGENT_DEFINITIONS
from app.infrastructure.agents.generic_specialized_agent import (
    _extract_patterns_from_doc,
)

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_BUILD_SCRIPT = _REPO_ROOT / "scripts" / "build_enriched_corpus.py"

# framework → (corpus CSV filename, expected distinct concern-area count).
_CORPORA = {
    "cwe_essentials": ("cwe_essentials_corpus.csv", 14),
    "isvs": ("isvs_corpus.csv", 7),
}


def _load_build_script():
    spec = importlib.util.spec_from_file_location("build_enriched", _BUILD_SCRIPT)
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
def test_corpus_has_enriched_columns(framework: str):
    rows = _csv_rows(framework)
    assert len(rows) > _CORPORA[framework][1]  # many entries per concern-area
    assert {"id", "document", "embed_text", "concern_area"} == set(rows[0].keys())


@pytest.mark.parametrize("framework", sorted(_CORPORA))
def test_corpus_concern_areas_match_agent_facets(framework: str):
    """Each corpus document's `concern_area` must equal an agent's
    retrieval facet — otherwise the agent retrieves nothing."""
    corpus_areas = {r["concern_area"] for r in _csv_rows(framework)}
    assert len(corpus_areas) == _CORPORA[framework][1]
    assert corpus_areas == _agent_concern_areas(framework)


@pytest.mark.parametrize("framework", sorted(_CORPORA))
def test_corpus_documents_carry_pattern_blocks(framework: str):
    """Every enriched doc carries the `**Vulnerability Pattern**` /
    `**Secure Pattern**` blocks the scan agent's extractor consumes."""
    for row in _csv_rows(framework):
        assert "**Vulnerability Pattern (" in row["document"], row["id"]
        assert "**Secure Pattern (" in row["document"], row["id"]


@pytest.mark.parametrize("framework", sorted(_CORPORA))
def test_corpus_documents_extract_cleanly(framework: str):
    """Every document yields non-empty vulnerability + secure patterns."""
    for row in _csv_rows(framework):
        vp, sp = _extract_patterns_from_doc(row["document"], "GENERIC")
        assert vp, row["id"]
        assert sp, row["id"]


@pytest.mark.parametrize("framework", sorted(_CORPORA))
def test_corpus_embed_text_is_concept_only(framework: str):
    """The embed_text column (RAG lever 1) carries concept text only."""
    for row in _csv_rows(framework):
        assert "```" not in row["embed_text"], row["id"]
        assert "[[" not in row["embed_text"], row["id"]


@pytest.mark.parametrize("framework", sorted(_CORPORA))
def test_corpus_csv_is_in_sync_with_yaml_source(framework: str):
    """The committed CSV must match what the build script produces from
    the per-concern-area YAML — guards against hand-edits and drift."""
    build = _load_build_script()
    assert build._check(framework) == 0
