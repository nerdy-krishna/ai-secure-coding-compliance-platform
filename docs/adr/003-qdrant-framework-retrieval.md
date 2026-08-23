# ADR-003: Qdrant-backed framework retrieval

- Status: accepted; supersedes the historical Chroma dual-write plan
- Last verified: 2026-08-22

## Context

Security agents and the advisor need retrieval over bundled OWASP, CWE, ASVS,
MASVS, and related framework material without coupling vector workloads to the
transactional PostgreSQL database.

## Decision

Use Qdrant as the vector store behind the RAG abstraction. Embeddings are created
in application code so indexing and querying share one representation. Qdrant is
reachable only on the compose network, requires an API key, and is rebuilt via
the administrative RAG ingestion surface when corpora change.

## Consequences

Framework retrieval is isolated from OLTP traffic and callers do not depend on a
specific vector client. Qdrant becomes a production dependency that needs backup,
health checks, capacity monitoring, and reproducible corpus rebuild procedures.
The earlier staged Chroma/dual-write migration is complete and no longer defines
the running architecture.
