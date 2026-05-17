"""ASVS RAG corpus — rendered from the hand-authored enriched chapter YAML.

Guards that `build_enriched_corpus.py` produces a corpus the ASVS scan
agents can actually use: the pattern blocks the extractor parses, and
`control_family` values that match the agents' retrieval filter.
"""

from __future__ import annotations

import csv
import importlib.util
import pathlib

from app.core.services.default_seed_service import AGENT_DEFINITIONS
from app.infrastructure.agents.generic_specialized_agent import (
    _extract_patterns_from_doc,
)

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_CSV_PATH = _REPO_ROOT / "src" / "app" / "data" / "asvs_corpus.csv"
_BUILD_SCRIPT = _REPO_ROOT / "scripts" / "build_enriched_corpus.py"


def _rows() -> list[dict]:
    with open(_CSV_PATH, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _asvs_agent_control_families() -> set[str]:
    families: set[str] = set()
    for agent in AGENT_DEFINITIONS:
        if agent["applicable_frameworks"] != ["asvs"]:
            continue
        families.update(agent["domain_query"]["metadata_filter"]["control_family"])
    return families


def test_asvs_corpus_has_requirements():
    rows = _rows()
    assert len(rows) > 300  # ASVS 5.0 ships ~345 verification requirements
    assert {"id", "document", "embed_text", "control_family"} == set(rows[0].keys())


def test_asvs_documents_carry_pattern_blocks():
    for row in _rows():
        assert "**Vulnerability Pattern (" in row["document"], row["id"]
        assert "**Secure Pattern (" in row["document"], row["id"]


def test_asvs_documents_extract_cleanly():
    """Every document must yield non-empty vulnerability + secure
    patterns — catches any `*` / `[` that would truncate the capture."""
    for row in _rows():
        vp, sp = _extract_patterns_from_doc(row["document"], "GENERIC")
        assert vp, row["id"]
        assert sp, row["id"]


def test_asvs_embed_text_is_concept_only():
    """The embed_text column (lever 1) carries the concept text only —
    no fenced code, so the vector represents the security concern."""
    for row in _rows():
        assert "```" not in row["embed_text"], row["id"]
        assert "[[" not in row["embed_text"], row["id"]


def test_asvs_control_families_are_retrievable_by_agents():
    """Every corpus `control_family` must match an ASVS agent's
    retrieval filter — otherwise those requirements reach no agent."""
    corpus_families = {row["control_family"] for row in _rows()}
    assert corpus_families <= _asvs_agent_control_families()


def test_asvs_corpus_in_sync_with_chapter_yaml():
    spec = importlib.util.spec_from_file_location("build_enriched", _BUILD_SCRIPT)
    assert spec and spec.loader
    build = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(build)
    assert build._check("asvs") == 0
