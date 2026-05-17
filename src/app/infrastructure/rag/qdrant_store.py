"""Qdrant implementation of `VectorStore` (ADR-008).

The only RAG backend post-migration. ADR-007 staged the swap with a
`dual` flag value during PR1; PR2+PR3 (this commit) retired the flag
and made Qdrant the sole store.

Module guarantees:
- `_translate_filter` covers `$eq`, `$ne`, `$in`, `$and`, `$or` plus
  the literal filter shape used by `analysis_node` in
  `generic_specialized_agent.py` — pinned by
  `tests/test_rag_qdrant_filter_translator.py`.
- `_qdrant_id` deterministically maps Chroma string ids to UUIDs via
  `uuid5` so existing collections (and the `_chroma_id` payload key)
  round-trip cleanly.
- `_log_init_error_env` redacts any env var whose name contains
  `API_KEY` so init-failure logs cannot leak `QDRANT_API_KEY`.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import threading
import uuid
from typing import Any, Dict, List, Optional

from qdrant_client import QdrantClient
from qdrant_client.http import models as qmodels

from app.config.config import settings
from app.infrastructure.rag.base import (
    CWE_COLLECTION_NAME,
    SECURITY_GUIDELINES_COLLECTION,
    RAGQueryResult,
)
from app.infrastructure.rag.embedder import embed

logger = logging.getLogger(__name__)

# MiniLM-L6-v2 output dim and metric. Pinned to match the vectors any
# existing Qdrant collection already holds (the embedder ships byte-
# equivalent output to the prior chromadb-bundled ONNX path).
VECTOR_SIZE = 384
DISTANCE = qmodels.Distance.COSINE

# V02.2.1 — positive-validation bounds for query entry points.
MAX_N_RESULTS = 50
MAX_QUERY_TEXTS = 32

# V02.3.2 — cap on how many docs we retrieve per framework in a single scroll.
MAX_FRAMEWORK_DOCS = 50_000

# V02.3.2 — framework_name is validated by *format*, not against a fixed
# enum. A static allow-list went stale the moment a framework was added
# (CWE Essentials, ISVS) or an admin created a custom one — and made
# `get_by_framework` / `delete_by_framework` raise for those, which
# surfaced in the UI as "error loading documents". The format check
# still bounds length and charset so nothing unsafe reaches a Qdrant
# filter; it mirrors `admin_rag._validate_framework_name`.
_FRAMEWORK_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _check_framework_name(framework_name: str) -> None:
    """Raise ValueError unless `framework_name` is a safe identifier."""
    if not _FRAMEWORK_NAME_RE.match(framework_name or ""):
        raise ValueError(
            f"Invalid framework name {framework_name!r}; "
            "must match [A-Za-z0-9_-]{1,64}"
        )


# V02.4.1 — anti-automation semaphore: cap concurrent Qdrant calls at 8.
_RAG_CALL_SEM = threading.Semaphore(8)


class RAGUnavailableError(RuntimeError):
    """Raised when a write to Qdrant fails so callers can branch gracefully.

    V16.5.2 — domain-specific error for Qdrant backend unavailability.
    """


def _api_key() -> Optional[str]:
    secret = settings.QDRANT_API_KEY
    if secret is None:
        return None
    if hasattr(secret, "get_secret_value"):
        v = secret.get_secret_value()
    else:
        v = str(secret)
    return v or None


def _log_init_error_env() -> None:
    """Dump QDRANT_* env vars to the log on init failure, redacting
    anything that looks like a secret. Mirrors the Chroma path."""
    logger.critical("Environment variables (QDRANT_*):")
    for key, value in os.environ.items():
        if "QDRANT" not in key.upper():
            continue
        # G11 — never log API keys.
        if "API_KEY" in key.upper():
            continue
        logger.critical("  %s=%s", key, value)


def _translate_filter(where: Optional[Dict[str, Any]]) -> Optional[qmodels.Filter]:
    """Translate Chroma `where` syntax into a Qdrant `Filter`.

    Supported operators:
      - leaf clause `{"key": {"$eq": v}}`     → `must=[FieldCondition(...)]`
      - leaf clause `{"key": {"$ne": v}}`     → `must_not=[FieldCondition(...)]`
      - leaf clause `{"key": {"$in": [...]]}}` → `must=[FieldCondition(MatchAny)]`
      - composite `{"$and": [<leaf>, ...]}`   → `must=[...]`
      - composite `{"$or":  [<leaf>, ...]}`   → `should=[...]` with min_should=1
      - implicit `{"key1": v1, "key2": v2}`   → `must=[eq, eq]` (Chroma allows
        a flat dict of equalities; we honour the same shorthand)

    `analysis_node` in `generic_specialized_agent.py` constructs filters
    of the form `{"$and": [{"scan_ready": {"$eq": True}}, {"$or": [...]}]}`,
    which is fully covered by the recursive walk below.
    """
    if not where:
        return None

    must: List[qmodels.Condition] = []
    must_not: List[qmodels.Condition] = []
    should: List[qmodels.Condition] = []

    for key, val in where.items():
        if key == "$and":
            for clause in val:
                child = _translate_filter(clause)
                if child is None:
                    continue
                if child.must:
                    must.extend(child.must)
                if child.must_not:
                    must_not.extend(child.must_not)
                if child.should:
                    must.append(qmodels.Filter(should=child.should))
            continue
        if key == "$or":
            for clause in val:
                child = _translate_filter(clause)
                if child is None:
                    continue
                # The child becomes a single Filter inside `should`;
                # passing must/must_not/should together preserves the
                # AND-within-each-OR-branch semantics. Splitting them
                # into separate `should` siblings (the previous shape)
                # would have flattened `$or:[{$and:[a,not b]}, c]` into
                # `should:[a, not b, c]`, broadening the match.
                # Security review F1.
                should.append(
                    qmodels.Filter(
                        must=child.must,
                        must_not=child.must_not,
                        should=child.should,
                    )
                )
            continue

        # Leaf clauses: either {"key": {"$op": v}} or {"key": v}.
        if isinstance(val, dict) and len(val) == 1:
            op, op_val = next(iter(val.items()))
            if op == "$eq":
                must.append(
                    qmodels.FieldCondition(
                        key=key, match=qmodels.MatchValue(value=op_val)
                    )
                )
            elif op == "$ne":
                must_not.append(
                    qmodels.FieldCondition(
                        key=key, match=qmodels.MatchValue(value=op_val)
                    )
                )
            elif op == "$in":
                must.append(
                    qmodels.FieldCondition(
                        key=key, match=qmodels.MatchAny(any=list(op_val))
                    )
                )
            else:
                raise ValueError(f"Unsupported filter operator: {op!r}")
        else:
            # `{"key": value}` shorthand — equality.
            must.append(
                qmodels.FieldCondition(key=key, match=qmodels.MatchValue(value=val))
            )

    return qmodels.Filter(
        must=must or None,
        must_not=must_not or None,
        should=should or None,
    )


class QdrantStore:
    """Implements `VectorStore` against Qdrant."""

    def __init__(self) -> None:
        try:
            self._client = QdrantClient(
                host=settings.QDRANT_HOST,
                port=settings.QDRANT_PORT,
                api_key=_api_key(),
                # V12.1.1 / V12.3.1 / V12.3.3 — enforce TLS so the API key
                # is not sent over plaintext HTTP. Set QDRANT_USE_TLS=false
                # only in local development environments.
                https=getattr(settings, "QDRANT_USE_TLS", True),
                # Default 5s; we don't want a slow Qdrant to stall scans.
                timeout=10,
            )
            # Collection bootstrap: create with the right vector params
            # if absent. Idempotent — safe to call on every init.
            self._ensure_collection(SECURITY_GUIDELINES_COLLECTION)
            self._ensure_collection(CWE_COLLECTION_NAME)
            logger.info(
                "QdrantStore initialised against %s:%s",
                settings.QDRANT_HOST,
                settings.QDRANT_PORT,
            )
        except Exception as e:
            logger.critical("Failed to initialise QdrantStore: %s", e)
            _log_init_error_env()
            raise

    def _ensure_collection(self, name: str) -> None:
        existing = {c.name for c in self._client.get_collections().collections}
        if name in existing:
            return
        self._client.create_collection(
            collection_name=name,
            vectors_config=qmodels.VectorParams(size=VECTOR_SIZE, distance=DISTANCE),
        )
        logger.info("Created Qdrant collection %s", name)

    # ------------------------------------------------------------------
    # VectorStore protocol
    # ------------------------------------------------------------------

    def add(
        self,
        documents: List[str],
        metadatas: List[Dict[str, Any]],
        ids: List[str],
    ) -> None:
        embeddings = embed(documents)
        points = [
            qmodels.PointStruct(
                id=_qdrant_id(doc_id),
                vector=vec,
                payload={**meta, "_chroma_id": doc_id, "document": doc},
            )
            for doc_id, doc, meta, vec in zip(ids, documents, metadatas, embeddings)
        ]
        # V02.4.1 — cap concurrent Qdrant calls.
        with _RAG_CALL_SEM:
            try:
                self._client.upsert(
                    collection_name=SECURITY_GUIDELINES_COLLECTION, points=points
                )
            except Exception as e:
                # V16.5.2 — log and re-raise as domain error so callers can branch.
                logger.warning("qdrant_store: upsert failed: %s", e)
                raise RAGUnavailableError(str(e)) from e

    def query_guidelines(
        self,
        query_texts: List[str],
        n_results: int = 5,
        where: Optional[Dict[str, Any]] = None,
    ) -> RAGQueryResult:
        # V02.2.1 — positive-validation: reject out-of-range inputs.
        if not query_texts or len(query_texts) > MAX_QUERY_TEXTS:
            raise ValueError(
                f"query_texts must be a non-empty list of at most {MAX_QUERY_TEXTS} items"
            )
        if n_results <= 0 or n_results > MAX_N_RESULTS:
            raise ValueError(f"n_results must be between 1 and {MAX_N_RESULTS}")

        query_embeddings = embed(query_texts)
        flt = _translate_filter(where)
        ids_out: List[List[str]] = []
        docs_out: List[List[str]] = []
        metas_out: List[List[Dict[str, Any]]] = []
        dists_out: List[List[float]] = []
        # V02.4.1 — cap concurrent Qdrant calls.
        with _RAG_CALL_SEM:
            for vec in query_embeddings:
                try:
                    hits = self._client.search(
                        collection_name=SECURITY_GUIDELINES_COLLECTION,
                        query_vector=vec,
                        query_filter=flt,
                        limit=n_results,
                        with_payload=True,
                    )
                except Exception as e:
                    # V16.5.2 — log and return empty result for graceful degradation.
                    logger.warning("qdrant_store: search (guidelines) failed: %s", e)
                    return {
                        "ids": [],
                        "documents": [],
                        "metadatas": [],
                        "distances": [],
                    }
                ids_out.append([str(h.payload.get("_chroma_id", h.id)) for h in hits])
                docs_out.append([str(h.payload.get("document", "")) for h in hits])
                metas_out.append(
                    [
                        {
                            k: v
                            for k, v in (h.payload or {}).items()
                            if k not in ("_chroma_id", "document")
                        }
                        for h in hits
                    ]
                )
                # Qdrant returns similarity scores (cosine: higher = closer);
                # Chroma returns distances. We expose distance = 1 - score.
                dists_out.append([float(1.0 - (h.score or 0.0)) for h in hits])
        return {
            "ids": ids_out,
            "documents": docs_out,
            "metadatas": metas_out,
            "distances": dists_out,
        }

    def query_cwe_collection(
        self, query_texts: List[str], n_results: int = 3
    ) -> RAGQueryResult:
        # V02.2.1 — positive-validation: reject out-of-range inputs.
        if not query_texts or len(query_texts) > MAX_QUERY_TEXTS:
            raise ValueError(
                f"query_texts must be a non-empty list of at most {MAX_QUERY_TEXTS} items"
            )
        if n_results <= 0 or n_results > MAX_N_RESULTS:
            raise ValueError(f"n_results must be between 1 and {MAX_N_RESULTS}")

        query_embeddings = embed(query_texts)
        ids_out: List[List[str]] = []
        docs_out: List[List[str]] = []
        metas_out: List[List[Dict[str, Any]]] = []
        dists_out: List[List[float]] = []
        # V02.4.1 — cap concurrent Qdrant calls.
        with _RAG_CALL_SEM:
            for vec in query_embeddings:
                try:
                    hits = self._client.search(
                        collection_name=CWE_COLLECTION_NAME,
                        query_vector=vec,
                        limit=n_results,
                        with_payload=True,
                    )
                except Exception as e:
                    # V16.5.2 — log and return empty result for graceful degradation.
                    logger.warning("qdrant_store: search (cwe) failed: %s", e)
                    return {
                        "ids": [],
                        "documents": [],
                        "metadatas": [],
                        "distances": [],
                    }
                ids_out.append([str(h.payload.get("_chroma_id", h.id)) for h in hits])
                docs_out.append([str(h.payload.get("document", "")) for h in hits])
                metas_out.append(
                    [
                        {
                            k: v
                            for k, v in (h.payload or {}).items()
                            if k not in ("_chroma_id", "document")
                        }
                        for h in hits
                    ]
                )
                dists_out.append([float(1.0 - (h.score or 0.0)) for h in hits])
        return {
            "ids": ids_out,
            "documents": docs_out,
            "metadatas": metas_out,
            "distances": dists_out,
        }

    def get_by_framework(self, framework_name: str) -> Dict[str, Any]:
        # V02.3.2 — validate framework_name by format (any configured
        # framework is allowed; an un-ingested one simply scrolls empty).
        _check_framework_name(framework_name)
        flt = _translate_filter({"framework_name": {"$eq": framework_name}})
        # V02.3.2 / V02.4.1 — paginate with a hard cap so a huge framework
        # cannot drive unbounded memory or repeated large scrolls.
        all_hits = []
        offset = None
        # V02.4.1 — cap concurrent Qdrant calls.
        with _RAG_CALL_SEM:
            while True:
                try:
                    batch, next_offset = self._client.scroll(
                        collection_name=SECURITY_GUIDELINES_COLLECTION,
                        scroll_filter=flt,
                        limit=1_000,
                        offset=offset,
                        with_payload=True,
                    )
                except Exception as e:
                    # V16.5.2 — log failure; return whatever we collected so far.
                    logger.warning("qdrant_store: scroll (framework) failed: %s", e)
                    break
                all_hits.extend(batch)
                if len(all_hits) >= MAX_FRAMEWORK_DOCS:
                    # V02.3.2 — operator warning when cap is hit.
                    logger.warning(
                        "qdrant_store: get_by_framework %r hit MAX_FRAMEWORK_DOCS cap (%d); "
                        "data may be truncated",
                        framework_name,
                        MAX_FRAMEWORK_DOCS,
                    )
                    all_hits = all_hits[:MAX_FRAMEWORK_DOCS]
                    break
                if next_offset is None:
                    break
                offset = next_offset
        return {
            "ids": [str(h.payload.get("_chroma_id", h.id)) for h in all_hits],
            "documents": [str(h.payload.get("document", "")) for h in all_hits],
            "metadatas": [
                {
                    k: v
                    for k, v in (h.payload or {}).items()
                    if k not in ("_chroma_id", "document")
                }
                for h in all_hits
            ],
        }

    def get_framework_stats(self) -> Dict[str, int]:
        """Document count per `framework_name` across the guidelines
        collection — dynamic, so every ingested framework is reported."""
        stats: Dict[str, int] = {}
        offset = None
        scanned = 0
        with _RAG_CALL_SEM:
            while True:
                try:
                    batch, next_offset = self._client.scroll(
                        collection_name=SECURITY_GUIDELINES_COLLECTION,
                        limit=1_000,
                        offset=offset,
                        with_payload=["framework_name"],
                        with_vectors=False,
                    )
                except Exception as e:
                    logger.warning("qdrant_store: scroll (stats) failed: %s", e)
                    break
                for point in batch:
                    fw = (point.payload or {}).get("framework_name")
                    if isinstance(fw, str) and fw:
                        stats[fw] = stats.get(fw, 0) + 1
                scanned += len(batch)
                if next_offset is None or scanned >= MAX_FRAMEWORK_DOCS:
                    break
                offset = next_offset
        return stats

    def delete_by_framework(self, framework_name: str) -> int:
        # V02.3.2 — validate framework_name by format.
        _check_framework_name(framework_name)
        # V02.3.3 — use a single server-side filter delete (atomic) instead
        # of the prior query-then-delete two-call pattern which exposed a
        # partial-delete window on failure.
        flt = _translate_filter({"framework_name": {"$eq": framework_name}})
        # Count first so we can return the affected row count.
        count_result = self._client.count(
            collection_name=SECURITY_GUIDELINES_COLLECTION,
            count_filter=flt,
            exact=True,
        )
        n = count_result.count if count_result else 0
        if n == 0:
            return 0
        with _RAG_CALL_SEM:
            try:
                self._client.delete(
                    collection_name=SECURITY_GUIDELINES_COLLECTION,
                    points_selector=qmodels.FilterSelector(filter=flt),
                )
            except Exception as e:
                # V16.5.2 — log and re-raise as domain error.
                logger.warning(
                    "qdrant_store: delete_by_framework %r failed: %s", framework_name, e
                )
                raise RAGUnavailableError(str(e)) from e
        return n

    def delete(self, ids: List[str]) -> None:
        point_ids = [_qdrant_id(i) for i in ids]
        # V02.4.1 — cap concurrent Qdrant calls.
        with _RAG_CALL_SEM:
            try:
                self._client.delete(
                    collection_name=SECURITY_GUIDELINES_COLLECTION,
                    points_selector=qmodels.PointIdsList(points=point_ids),
                )
            except Exception as e:
                # V16.5.2 — log and re-raise as domain error.
                logger.warning("qdrant_store: delete failed: %s", e)
                raise RAGUnavailableError(str(e)) from e

    def health_check(self) -> bool:
        try:
            self._client.get_collections()
            return True
        except Exception:
            return False


_QDRANT_ID_NAMESPACE = uuid.UUID("a3a3a3a3-a3a3-a3a3-a3a3-a3a3a3a3a3a3")


def _qdrant_id(chroma_id: str) -> str:
    """Map a Chroma string id to a deterministic UUID for Qdrant.

    Qdrant rejects arbitrary string ids at the wire — its point-id
    contract is `uint64` or `UUID`. Without this mapping every
    secondary write in `dual` mode would raise and `_safe_secondary`
    would silently swallow it, leaving Qdrant empty while logs filled
    with WARNs. Hashing via `uuid5` keeps the mapping deterministic
    (same Chroma id → same Qdrant point id across processes), and the
    original Chroma id rides along in `payload._chroma_id` so we can
    round-trip identifiers through the API. Security review F3.
    """
    return str(uuid.uuid5(_QDRANT_ID_NAMESPACE, chroma_id))


# Reserved for the future `AsyncQdrantClient` swap. The current
# `QdrantClient` is sync; calls run inside the async graph but the
# upstream lib runs them on a thread under the hood (httpx). If
# profiling ever shows event-loop stalls, swap here. The bare
# `asyncio` reference keeps the import alive for the swap diff.
_ASYNC_CLIENT_PLACEHOLDER: Optional[Any] = None
asyncio  # silence unused-import warning; reserved for the swap.
