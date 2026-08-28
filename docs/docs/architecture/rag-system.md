---
title: RAG System
sidebar_position: 7
---

# RAG System

SCCAP's RAG layer is a single Qdrant collection shared across
every framework, with per-document metadata keyed on
`framework_name`. Retrieval is done with a metadata filter so the
Advisor only pulls context from the frameworks the caller selected
for the session.

## Qdrant + embedder

- **Engine**: Qdrant, run as a separate `qdrant` container in the
  compose stack (replaced ChromaDB per ADR-003). The `VectorStore`
  Protocol in `infrastructure/rag/base.py` keeps callers
  store-agnostic; `qdrant_store.py` is the singleton impl, including
  a Chroma-`where` → Qdrant-`Filter` translator so the historic
  query shape still works.
- **Embedder**: `fastembed.TextEmbedding("sentence-transformers/all-MiniLM-L6-v2")`
  via `infrastructure/rag/embedder.py`. Vectors are byte-equivalent
  to the prior chromadb-bundled ONNX embedder, so existing collections
  remain valid. Lazy-downloads on first use; first query after a
  fresh deploy takes a few seconds longer than subsequent ones.
- **Collection**: one global collection called `security_guidelines`.
  Per-document metadata carries `framework_name`, `control_id` (when
  the source has one), and `title`.

## Ingestion modes

Admins add knowledge under **Admin → Frameworks** +
**Admin → RAG**:

- **CSV** — used by the **OWASP ASVS** default. The admin uploads a
  CSV with one row per requirement + the columns
  `control_id`, `title`, `content`, `framework_name`. The CSV
  ingestion pipeline chunks long content, embeds, and writes rows
  with metadata intact.
- **Git URL** — used by **OWASP Proactive Controls** and
  **Cheatsheets** defaults, plus any custom framework that ships its
  docs in a repo. The admin pastes the repo URL; the
  `rag_preprocessor_service` clones the tree, walks markdown files,
  chunks, embeds, and writes. Re-ingesting the same URL replaces the
  framework's documents (no orphan duplication).

Both ingestion paths are backed by a `rag_jobs` row so admins can
track progress from the Admin UI.

## Retrieval

`src/app/infrastructure/rag/rag_client.py` exposes the consumer API:

```python
rag_service = get_rag_service()
retrieved = rag_service.query_guidelines(
    query_texts=[user_question],
    n_results=5,
    where={"framework_name": {"$in": session.frameworks}},
)
docs = retrieved.get("documents", [[]])[0]
```

Callers that need doc counts or ingestion stats use
`rag_service.get_framework_stats(framework_name)`, which powers the
Compliance page's per-framework tile.

## Consumers

- **Chat agent** (`src/app/infrastructure/agents/chat_agent.py`) —
  runs the filtered query above before every LLM call so the
  Advisor only cites content from the session's selected
  frameworks. The filtered docs are concatenated into the
  `rag_context` prompt variable.
- **Compliance service** — reads doc counts + `control_id` metadata
  for the per-framework posture tile and the drill-in control list.
- **Specialized agents (future)** — the framework chunker in
  `shared/analysis_tools` is ready to inject framework-specific
  controls directly into agent prompts; today most agents rely on
  Pydantic-validated prompt templates instead, but the RAG path
  remains available.

## Chat session scope vs. scan scope

- **Chat frameworks** are declared at session creation time and are
  metadata on the `chat_sessions` row. Changing them requires
  creating a new session; this keeps retrievals reproducible from a
  session's persisted context.
- **Scan frameworks** are declared per scan and are metadata on the
  `scans` row (`Scan.frameworks` JSONB). The Compliance page joins
  `findings.scan_id → scans.frameworks` to count matched findings
  per framework.

## Re-ingestion + cache invalidation

Re-ingesting a framework (CSV re-upload or Git URL re-crawl):

1. Deletes existing documents tagged with that `framework_name`
   from the collection.
2. Writes the fresh ones.
3. Bumps the framework's `updated_at` so the Compliance page shows
   the new doc count + scan posture on the next refresh.

This is idempotent — re-ingesting the same source twice leaves the
collection in the same shape.
