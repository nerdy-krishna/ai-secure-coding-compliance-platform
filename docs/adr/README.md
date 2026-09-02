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
- [ADR-012: KMS-first supply chain and cross-store evidence governance](012-supply-chain-and-evidence-governance.md)
- [ADR-013: Pentesting bounded context and versioned Foundation 0 contracts](013-pentesting-bounded-context-contracts.md)
- [ADR-014: Pentesting Foundation 1 exact-origin tracer](014-pentesting-foundation1-exact-origin-tracer.md)
- [ADR-015: Pentesting Foundation 2 durable execution and evidence commit](015-pentesting-foundation2-execution-evidence.md)
- [ADR-016: Pentesting Foundation 3 deterministic scope and isolated gateway](016-pentesting-foundation3-scope-execution-gateway.md)
- [ADR-017: Pentesting Capability 4 bounded adaptive controller](017-pentesting-capability4-adaptive-controller.md)
- [ADR-018: Pentesting Capability 5 initial Web/API tool pack](018-pentesting-capability5-initial-web-api-tool-pack.md)
- [ADR-019: Pentesting Capabilities 6 and 7 identity-aware verification](019-pentesting-capabilities6-7-identity-verification.md)
- [ADR-020: Pentesting Capability 8 white-box Code Scan integration](020-pentesting-capability8-white-box-sccap-integration.md)
- [ADR-021: Pentesting Capability 9 canonical tests, operations and coverage](021-pentesting-capability9-canonical-tests-operations-coverage.md)
- [ADR-022: Pentesting Capability 10 reversible mutations, locking and restoration](022-pentesting-capability10-reversible-mutations-cleanup.md)
