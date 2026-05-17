"""BM25 sparse embedder (RAG lever 2 — hybrid retrieval).

`sparse_embed` backs the term-match leg of hybrid retrieval. These
checks lock its output shape, so a fastembed bump that changed the
`SparseEmbedding` API would fail loudly here rather than silently
degrading every hybrid search to dense-only.
"""

from __future__ import annotations

import pytest

from app.infrastructure.rag.embedder import MAX_BATCH, sparse_embed


def test_sparse_embed_returns_indices_and_values_per_text():
    out = sparse_embed(
        ["SQL injection via string concatenation", "cross site scripting"]
    )
    assert len(out) == 2
    for indices, values in out:
        assert indices and values
        assert len(indices) == len(values)
        assert all(isinstance(i, int) for i in indices)
        assert all(isinstance(v, float) for v in values)


def test_sparse_embed_empty_input_returns_empty():
    assert sparse_embed([]) == []


def test_sparse_embed_query_mode_runs():
    indices, values = sparse_embed(
        ["server side request forgery"], is_query=True
    )[0]
    assert indices and len(indices) == len(values)


def test_sparse_embed_rejects_oversized_batch():
    with pytest.raises(ValueError):
        sparse_embed(["x"] * (MAX_BATCH + 1))
