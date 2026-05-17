"""Bundled RAG corpus auto-ingest (Framework Expansion #60 / #62).

Drives `ingest_bundled_corpus` / `ingest_all_bundled_corpora` against a
fake vector store — verifies the delete-then-add idempotency, the
`scan_ready` + `concern_area` tagging the scan agents depend on, and the
`only_if_empty` skip the startup hook relies on. No real Qdrant needed.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.infrastructure.rag.bundled_corpus import (
    BUNDLED_CORPORA,
    ingest_all_bundled_corpora,
    ingest_bundled_corpus,
)


class _FakeStore:
    """Records add/delete calls; reports a configurable existing count."""

    def __init__(self, existing: Optional[Dict[str, int]] = None) -> None:
        self._existing = existing or {}
        self.added: List[Dict[str, Any]] = []
        self.deleted: List[str] = []

    def delete_by_framework(self, framework_name: str) -> int:
        self.deleted.append(framework_name)
        return 0

    def add(self, documents, metadatas, ids) -> None:  # noqa: ANN001
        self.added.append({"documents": documents, "metadatas": metadatas, "ids": ids})

    def get_by_framework(self, framework_name: str) -> Dict[str, Any]:
        return {"ids": [f"x{i}" for i in range(self._existing.get(framework_name, 0))]}


def test_ingest_bundled_corpus_loads_and_tags_cwe_essentials():
    store = _FakeStore()
    count = ingest_bundled_corpus(store, "cwe_essentials")

    assert count == 14
    # delete-then-add → re-running replaces, never duplicates.
    assert store.deleted == ["cwe_essentials"]
    call = store.added[0]
    assert len(call["documents"]) == 14
    for meta in call["metadatas"]:
        assert meta["framework_name"] == "cwe_essentials"
        assert meta["scan_ready"] is True  # required by the RAG facet resolver
        assert meta["concern_area"]  # required by the CWE agents' filter
    for doc_id in call["ids"]:
        assert doc_id.startswith("cwe_essentials::")


def test_ingest_bundled_corpus_tags_asvs_with_control_family():
    """ASVS uses the `control_family` facet (not `concern_area`) — its
    agents filter retrieval on it."""
    store = _FakeStore()
    count = ingest_bundled_corpus(store, "asvs")

    assert count > 300  # ASVS 5.0 ships ~345 verification requirements
    for meta in store.added[0]["metadatas"]:
        assert meta["framework_name"] == "asvs"
        assert meta["scan_ready"] is True
        assert meta["control_family"]  # required by the Asvs* agents' filter


def test_ingested_documents_carry_pattern_blocks():
    """The ingested text must hold the `**Vulnerability Pattern**` /
    `**Secure Pattern**` blocks the agent's extractor parses."""
    store = _FakeStore()
    ingest_bundled_corpus(store, "isvs")
    for doc in store.added[0]["documents"]:
        assert "**Vulnerability Pattern (" in doc
        assert "**Secure Pattern (" in doc


def test_only_if_empty_skips_already_populated_frameworks():
    # cwe_essentials + asvs already populated; only isvs is empty.
    store = _FakeStore(existing={"cwe_essentials": 14, "asvs": 345})
    result = ingest_all_bundled_corpora(store, only_if_empty=True)

    assert result["cwe_essentials"] == 14  # reported, not re-ingested
    assert result["isvs"] == 7  # the empty framework was ingested
    # Only the empty framework was (re)ingested.
    assert store.deleted == ["isvs"]


def test_ingest_all_covers_every_bundled_framework():
    store = _FakeStore()
    result = ingest_all_bundled_corpora(store)
    assert set(result) == set(BUNDLED_CORPORA)
    assert sorted(store.deleted) == sorted(BUNDLED_CORPORA)
