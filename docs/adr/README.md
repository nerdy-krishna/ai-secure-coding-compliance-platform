# Architecture decision records

This directory holds the durable decisions that match the current SCCAP
implementation. Historical discovery notes, run logs, threat models, and plans
are working material rather than architectural truth; they are archived outside
the repository after their implemented decisions are distilled here.

An ADR records a decision, its consequences, and any known implementation gap.
When the architecture changes, update or supersede the relevant ADR instead of
leaving a completed plan as the only explanation of the system.

- [ADR-001: Durable scan orchestration and approval gates](001-durable-scan-orchestration.md)
- [ADR-002: Deterministic scanners before AI analysis](002-deterministic-scanners-before-ai.md)
- [ADR-003: Qdrant-backed framework retrieval](003-qdrant-framework-retrieval.md)
- [ADR-004: Unified CVSS-weighted risk scoring](004-unified-risk-scoring.md)
- [ADR-005: Self-hosted, fail-open LLM observability](005-llm-observability.md)
- [ADR-006: Bounded operational log storage](006-bounded-log-storage.md)
- [ADR-007: Immutable scan-attempt evidence storage](007-immutable-scan-evidence.md)
- [ADR-011: Observable, autoscaled worker pools](011-observable-autoscaled-worker-pools.md)
