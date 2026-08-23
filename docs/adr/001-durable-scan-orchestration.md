# ADR-001: Durable scan orchestration and approval gates

- Status: accepted
- Last verified: 2026-08-23

## Context

Scans are long-running, costly, and can pause for human review. Process memory
alone cannot provide reliable recovery or an auditable approval trail.

## Decision

SCCAP persists scan state in PostgreSQL, records dispatch intent in a database
outbox, executes scans through RabbitMQ and a LangGraph PostgreSQL checkpointer,
and treats these as distinct approval gates:

1. deterministic prescan findings approval;
2. profiling-cost approval;
3. full AI-analysis cost approval.

LangGraph node identifiers are persisted compatibility keys. They must not be
renamed without a checkpointer migration. Terminal paths retain audit records
while cleaning up resumable graph state where appropriate.

Each initial execution has a `ScanAttempt`. Resume reuses it; restart creates a
new sequenced child attempt and supersedes the prior identity. Dispatches,
events, tasks, gates, evidence, and scan usage records bind to that attempt.

## Consequences

The API and worker can be restarted without making every scan unrecoverable,
and approvals have explicit semantics. Every dispatch and resume path must be
idempotent. Submission now commits Project/source rows, Scan, Snapshot, queued
event, and outbox intent atomically and relies exclusively on the sweeper for
publication. Approval/decline and manual resume/restart also commit status, events, cleanup where
applicable, and outbox intent atomically. Cancellation commits its terminal status and event
together. Compare-and-set claims reject racing decisions before another outbox intent is created.
All status writers constrain transitions through the shared policy; terminal states cannot be
overwritten by late worker/finalizer writes. Successful graph nodes persist `completed_stages` in
their output checkpoint. Failed threads remain available to resume, clean restart deletes the old
thread, and no consumer-side task heuristic bypasses graph stages.

Every human pause is represented by a durable `ApprovalGate`. Its immutable identity includes the
scan/thread, graph node, occurrence sequence, decision evidence hash, and gate kind. The API binds a
decision to that identity and atomically records one decision plus one outbox intent. Identical
idempotency-key retries return the recorded decision; conflicting decisions fail closed. Workers
acquire a bounded database resume lease before invoking LangGraph and bind it to the parked
checkpoint. The interrupt records `resumed`, while the consumer records `completed` only after the
checkpoint advances. On recovery, an unchanged checkpoint permits lease reclamation; an advanced
checkpoint proves the command already ran and permits completion without replay. Concurrent
delivery and RabbitMQ redelivery therefore cannot resume the same interrupt twice. Completion,
expiry, cancellation, and restart close the gate idempotently. The frontend renders only the active
backend gate and keys optimistic dismissal by `gate_id`, not a broad scan status.

The profiling-cost and full-analysis-cost pauses remain distinct one-actor gates. High-cost metadata
must not claim separation-of-duties or dual approval is enforced until that policy has two durable
actor decisions on one gate.
