"""Process-local ONNX embedder via fastembed (ADR-008).

`fastembed.TextEmbedding("sentence-transformers/all-MiniLM-L6-v2")`
loads the same MiniLM-L6-v2 ONNX bundle the chromadb-bundled
DefaultEmbeddingFunction used pre-PR3 — we measured byte-equivalent
output (max per-dim diff ~6e-9, cosine = 1.0) against the chromadb
path on three fixed inputs, so existing Qdrant collections seeded
under PR1 are still recall-compatible.

The model file is downloaded once at Docker-build time
(`Dockerfile` final stages run a warm-up `embed(["warmup"])` after
copying the venv) and cached at `FASTEMBED_CACHE_PATH`
(`/opt/fastembed-cache` per the base stage). Runtime never reaches
out to HuggingFace, which keeps air-gapped / restricted-egress
deployments working (threat-model row 6 / mitigation 7).
"""

from __future__ import annotations

import threading
from typing import List, Optional, Tuple

from fastembed import SparseTextEmbedding, TextEmbedding

# Same model name across PR1 and PR3 — see ADR-008.
_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

# Sparse BM25 model — drives the hybrid-retrieval term-match leg (RAG
# lever 2). Pure statistical BM25 (no neural weights); fastembed ships
# its small tokenizer/stopword artifact, pre-warmed into the Docker
# image alongside the dense model so air-gapped deployments stay offline.
_SPARSE_MODEL_NAME = "Qdrant/bm25"

# V02.4.1 — hard caps to prevent hostile callers from pinning ONNX CPU.
MAX_BATCH = 256
MAX_CHARS_PER_TEXT = 8192

# A BM25 sparse vector as (indices, values) — the shape Qdrant's
# `SparseVector` takes.
SparseVec = Tuple[List[int], List[float]]

_lock = threading.Lock()
_embedder: Optional[TextEmbedding] = None
_sparse_embedder: Optional[SparseTextEmbedding] = None


def _get_embedder() -> TextEmbedding:
    """Return the singleton TextEmbedding instance, loading on first use."""
    global _embedder
    if _embedder is not None:
        return _embedder
    with _lock:
        if _embedder is None:
            _embedder = TextEmbedding(_MODEL_NAME)
    return _embedder


def _get_sparse_embedder() -> SparseTextEmbedding:
    """Return the singleton BM25 SparseTextEmbedding, loading on first use."""
    global _sparse_embedder
    if _sparse_embedder is not None:
        return _sparse_embedder
    with _lock:
        if _sparse_embedder is None:
            _sparse_embedder = SparseTextEmbedding(_SPARSE_MODEL_NAME)
    return _sparse_embedder


def embed(texts: List[str]) -> List[List[float]]:
    """Embed a batch of texts to 384-dim cosine-normalised float vectors."""
    if not texts:
        return []
    if len(texts) > MAX_BATCH:
        raise ValueError(f"embed batch exceeds {MAX_BATCH}")
    if any(len(t) > MAX_CHARS_PER_TEXT for t in texts):
        raise ValueError("embed input text too long")
    fn = _get_embedder()
    out: List[List[float]] = []
    for vec in fn.embed(texts):
        out.append([float(x) for x in vec])
    return out


def sparse_embed(texts: List[str], *, is_query: bool = False) -> List[SparseVec]:
    """Embed a batch of texts to BM25 sparse vectors (RAG lever 2).

    Returns one `(indices, values)` pair per text. `is_query=True` uses
    the BM25 query-side embedding (no IDF on the query terms); the
    document side carries the IDF weighting.
    """
    if not texts:
        return []
    if len(texts) > MAX_BATCH:
        raise ValueError(f"sparse embed batch exceeds {MAX_BATCH}")
    if any(len(t) > MAX_CHARS_PER_TEXT for t in texts):
        raise ValueError("sparse embed input text too long")
    fn = _get_sparse_embedder()
    gen = fn.query_embed(texts) if is_query else fn.embed(texts)
    out: List[SparseVec] = []
    for se in gen:
        out.append(([int(i) for i in se.indices], [float(v) for v in se.values]))
    return out


def reset_for_tests() -> None:
    """Test-only: drop the singletons."""
    global _embedder, _sparse_embedder
    with _lock:
        _embedder = None
        _sparse_embedder = None
