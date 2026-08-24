# Dependency degradation runbook

Preserve durable work first. Do not purge queues, rewind schema, delete
checkpoints, or manually set outbox rows to published during an incident.

## RabbitMQ

Symptoms are unpublished outbox growth, connection retries, or rising queue
age with no consumers. Confirm broker quorum/disk alarms, credentials, queue
policy, and network. The API can continue accepting scans while PostgreSQL is
healthy because the outbox is atomic; publisher retries after recovery. Queue
overflow uses `reject-publish`, never `drop-head`, so pressure becomes visible
instead of silently deleting old work. Reduce intake if the bounded queue is
near 100,000 messages. After recovery, verify publisher attempts fall, every
queue has consumers, and duplicate delivery remains idempotent.

## PostgreSQL

Symptoms include API/worker DB spans failing, no checkpoint advancement, and
outbox polling errors. Stop rollout and new intake, verify primary health,
replication, connections, disk, and the non-BYPASSRLS runtime role. Do not fail
over to a stale replica: outbox and LangGraph checkpoint ordering must remain
consistent. Resume workers only after the migration head, current attempt IDs,
outbox rows, and checkpoint tables are readable together.

## Qdrant

RAG failures must be explicit/degraded; never substitute another tenant's or a
stale unverified collection. Check service health, API key, storage, collection
dimensions, and snapshot recovery. Deterministic scanners and persisted work
remain authoritative. Resume failed workflows from their checkpoints after
Qdrant is healthy; do not restart them unless operators intentionally want a
new scan attempt.

## LLM provider

Inspect provider-class spans, rate limiters, circuit breakers, queue age, and
the canonical usage ledger. Do not place prompts/responses in incident tools.
Allow retry/jitter and circuit-breaker recovery; lower LLM pool replicas if
provider throttling amplifies failures. Budget reservations remain durable.
Reconcile provider billing after recovery and resume the same attempt where
possible.

## Evidence/object store

Treat failed artifact writes or digest checks as integrity failures, not clean
results. Check private endpoint, KMS/key-provider permissions, exact object
versions, capacity, and clock. Never bypass the application download path or
replace a failed immutable generation. Retention/deletion retries stay in the
governance queue until exact-version deletion succeeds.

## Recovery proof

Before closing the incident, verify:

1. unpublished outbox age and all three queue ages return to baseline;
2. no current attempt is stranded at an internal or user approval checkpoint;
3. cancellation and terminal outcome rates normalize;
4. evidence manifests/digests and usage ledger reconciliation pass;
5. a canary scan exercises deterministic, approval/LLM, report, SSE, and
   download paths with one trace lineage and no sensitive attributes.
