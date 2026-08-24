# ADR-011: Observable, autoscaled worker pools

Status: Accepted (2026-08-24)

## Context

The original RabbitMQ worker consumed submission and approval traffic in one
process. That compatibility shape remains useful for development and rollback,
but deterministic scanners, provider-bound LLM work, and report/export work
have different resource and scaling signals. Production also needs a durable
boundary between expensive analysis and report generation, not an in-memory
handoff that is lost when a pod drains.

## Decision

Kubernetes 1.30+ with the versioned `deploy/helm/sccap` chart is the production
orchestrator. Docker Compose remains the development and single-node target.
The chart deploys scanner, LLM workflow, and report/export worker pools with
dedicated RabbitMQ queues, prefetch values, resources, and security contexts.
The unified worker stays supported and subscribes to all three queues.

`save_results` is followed by the internal `report_handoff` graph node. In
split mode it idempotently writes one outbox row per attempt and parks a
LangGraph interrupt. The outbox sweeper remains the only publisher. A report
worker resumes only when tenant, scan, attempt, outbox, node, and durable
checkpoint identities all match. This interrupt is operational: it creates no
approval gate and accepts no API decision. Legacy/unified states omit the split
flag and continue straight through.

KEDA scales each split pool from queue length and RabbitMQ head-message age.
Default min/max replicas are scanner 1/20, LLM 1/50, and report 1/10. Scale-down
stabilizes for 60 seconds. A terminating worker cancels consumption, drains
active deliveries, and leaves unfinished deliveries unacknowledged for durable
redelivery within a 600-second pod grace period.

OpenTelemetry exports W3C-correlated operational traces and metrics through an
OTel Collector. The allowlist excludes source, prompts, responses, message
bodies, credentials, SQL text, vector payloads, and unbounded exceptions.
Langfuse remains the separate, existing model-observability facility.

Rollouts are schema-first and N-1 compatible. The migration hook only upgrades;
rollback never runs Alembic downgrade. A current-version unified bridge must
drain any new report handoffs before the final N-1 worker rollback.

## Consequences

- Queue/outbox/checkpoint identity becomes part of the workflow compatibility
  contract and needs regression coverage.
- RabbitMQ must expose detailed queue-head timestamps for age scaling.
- KEDA and Prometheus Operator CRDs are production prerequisites when their
  chart features are enabled.
- The unified default remains prefetch 5, at most three approval workflows, and
  serialized submission workflows. Split pools override prefetch explicitly.
- No Task21 database migration is required; existing outbox uniqueness and
  checkpointer persistence provide the durable boundary.
