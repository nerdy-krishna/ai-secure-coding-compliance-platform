"""Embedder parity (ADR-008).

Locks the lifted `app.infrastructure.rag.embedder` (now `fastembed`-
backed) against checked-in golden vectors that match what the prior
chromadb-bundled `DefaultEmbeddingFunction` produced on the same
inputs. Without this guard, a future fastembed bump (or a swap to a
different MiniLM-L6-v2 packaging) could silently drift vectors and
regress recall against existing Qdrant collections.

Goldens were captured under PR1 from
`chromadb.utils.embedding_functions.DefaultEmbeddingFunction()` and
reproduced byte-equivalent (max per-dim diff ~6e-9) by
`fastembed.TextEmbedding("sentence-transformers/all-MiniLM-L6-v2")`.
We pin the first 5 + last 5 values per fixed input + the L2 norm —
enough signal to catch tokenizer / ONNX-runtime drift without
checking 384 floats × 3 inputs verbatim.
"""

from __future__ import annotations

import math
from typing import Dict, List, TypedDict


class _Golden(TypedDict):
    head: List[float]
    tail: List[float]
    norm: float


# Pinned goldens from chromadb's DefaultEmbeddingFunction (PR1) and
# reproduced byte-equivalent by fastembed. See module docstring.
_GOLDEN_VECTORS: Dict[str, _Golden] = {
    "the quick brown fox": {
        "head": [
            0.002772714980539335,
            0.033268577897771524,
            -0.0006846626595895617,
            0.042996822714968,
            0.03614575338241844,
        ],
        "tail": [
            -0.006337404489525585,
            0.034638593206983696,
            0.013424814853403652,
            0.06427383888674565,
            0.02530470586288548,
        ],
        "norm": 1.0,
    },
    "OWASP A03 injection": {
        "head": [
            -0.0948797268031421,
            0.05040171843828086,
            -0.0512691261833692,
            0.03702648749613069,
            -0.06033030360393167,
        ],
        "tail": [
            0.07116581737816871,
            -0.01670442540772355,
            -0.039817026510216326,
            0.009675665541619975,
            -0.0402698415683178,
        ],
        "norm": 0.9999999999999999,
    },
    "asvs requirement 5.1.2": {
        "head": [
            -0.022813938659590624,
            -0.032077943410073875,
            -0.016536541148549997,
            0.0467351685871149,
            0.0465042057636244,
        ],
        "tail": [
            -0.009290361285439825,
            0.013600457401011177,
            0.05303565621730273,
            -0.0006414443491654928,
            -0.04853844121752693,
        ],
        "norm": 1.0,
    },
}

_TOLERANCE = 1e-6


def _close(a: float, b: float, tol: float = _TOLERANCE) -> bool:
    return abs(a - b) <= tol


def test_embedder_produces_384_dim_vectors() -> None:
    from app.infrastructure.rag.embedder import embed

    for text in _GOLDEN_VECTORS:
        out = embed([text])
        assert len(out) == 1
        assert len(out[0]) == 384


def test_embedder_matches_pr1_goldens() -> None:
    """Per-fixed-input head/tail/norm parity within 1e-6."""
    from app.infrastructure.rag.embedder import embed

    for text, golden in _GOLDEN_VECTORS.items():
        vec = embed([text])[0]
        head_actual = vec[:5]
        tail_actual = vec[-5:]
        norm_actual = math.sqrt(sum(x * x for x in vec))

        for i, (a, g) in enumerate(zip(head_actual, golden["head"])):
            assert _close(a, g), (
                f"{text!r} head[{i}] drifted: actual={a!r}, golden={g!r}"
            )
        for i, (a, g) in enumerate(zip(tail_actual, golden["tail"])):
            assert _close(a, g), (
                f"{text!r} tail[{i}] drifted: actual={a!r}, golden={g!r}"
            )
        assert _close(norm_actual, golden["norm"]), (
            f"{text!r} L2 norm drifted: actual={norm_actual!r}, "
            f"golden={golden['norm']!r}"
        )


def test_embedder_is_deterministic() -> None:
    """Same input → same output across repeated calls."""
    from app.infrastructure.rag.embedder import embed

    a = embed(["determinism check"])[0]
    b = embed(["determinism check"])[0]
    assert all(_close(x, y, tol=0.0) for x, y in zip(a, b))


def test_embedder_handles_empty_input() -> None:
    from app.infrastructure.rag.embedder import embed

    assert embed([]) == []
