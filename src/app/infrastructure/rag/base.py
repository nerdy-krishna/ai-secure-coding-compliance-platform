"""`VectorStore` Protocol — the abstraction every RAG caller depends on.

Two impls exist today (`ChromaStore`, `QdrantStore`) plus a thin
`DualWriteStore` wrapper used when `RAG_VECTOR_STORE=dual`. Callers
pick one via `app.infrastructure.rag.factory.get_vector_store()` and
should never instantiate the concrete classes directly.

Result shape (`RAGQueryResult`) mirrors what ChromaDB's
`Collection.query()` returns today, so existing call sites in
`generic_specialized_agent.py` and `chat_agent.py` don't change.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Protocol, TypedDict, runtime_checkable

# Same names the existing Chroma path uses; both stores honour these.
SECURITY_GUIDELINES_COLLECTION = "security_guidelines_v1"
CWE_COLLECTION_NAME = "cwe_collection"


class RAGQueryResult(TypedDict, total=False):
    """Shape returned by `query_guidelines` and `query_cwe_collection`.

    `ids`, `documents`, `metadatas`, and `distances` are lists-of-lists
    (one inner list per query in the batch), matching ChromaDB 0.5.x.
    """

    ids: List[List[str]]
    documents: List[List[str]]
    metadatas: List[List[Dict[str, Any]]]
    distances: List[List[float]]


@runtime_checkable
class VectorStore(Protocol):
    """Public surface every RAG store must implement."""

    def add(
        self,
        documents: List[str],
        metadatas: List[Dict[str, Any]],
        ids: List[str],
        embed_texts: Optional[List[str]] = None,
    ) -> None:
        """Upsert documents into the security-guidelines collection.

        `documents` is what queries store and return. When `embed_texts`
        is supplied (RAG lever 1), the embedding vector is built from it
        instead of from `documents` — so the vector represents the
        security concept while retrieval still returns the full,
        code-bearing document. Must be the same length as `documents`.
        """

    def query_guidelines(
        self,
        query_texts: List[str],
        n_results: int = 5,
        where: Optional[Dict[str, Any]] = None,
    ) -> RAGQueryResult:
        """Semantic + metadata-filtered search over guidelines."""

    def query_cwe_collection(
        self, query_texts: List[str], n_results: int = 3
    ) -> RAGQueryResult:
        """Semantic search over the CWE collection."""

    def get_by_framework(self, framework_name: str) -> Dict[str, Any]:
        """Return all docs whose `metadata.framework_name == framework_name`."""

    def get_framework_stats(self) -> Dict[str, int]:
        """Return per-framework document counts for the canonical set."""

    def delete_by_framework(self, framework_name: str) -> int:
        """Delete all docs for a framework; returns the count deleted."""

    def delete(self, ids: List[str]) -> None:
        """Delete docs by id."""

    def health_check(self) -> bool:
        """Lightweight liveness check; no exceptions."""
