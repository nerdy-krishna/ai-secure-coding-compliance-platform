# SCCAP domain context

SCCAP is a secure-code analysis platform that combines deterministic scanners with LLM-based
security analysis. PostgreSQL is the authoritative store; RabbitMQ carries work notifications;
LangGraph checkpoints resumable scan execution; the React application is the operator surface.

## Domain glossary

### Submission

The validated upload, archive, or supported Git repository input from which SCCAP creates a
Project, Scan, source files, and an `ORIGINAL_SUBMISSION` Snapshot.

### Project

The long-lived owner of related Scans. Project visibility is constrained by tenant and user-group
scope.

### Scan

One immutable analysis configuration applied to an original source snapshot. A Scan owns status,
cost approvals, file profiles, findings, events, durable tasks, artifacts, reports, and optional
post-remediation output.

### Scan lifecycle

The LangGraph workflow plus its API and worker transitions. It includes deterministic preparation,
up to three approval gates, LLM analysis, consolidation, optional remediation, verification, and
final reporting.

### Approval gate

A persisted pause requiring an operator decision. The gates are Prescan Approval when deterministic
findings exist, Profiling Approval before utility-model profiling, and Cost Approval before deep
analysis.

### Prescan

The deterministic scanner pass using Bandit, database-selected Semgrep rules, Gitleaks, and
OSV-Scanner. It also produces dependency/BOM information where available.

### Analysis lane

One reasoning-LLM configuration executing the routed security agents. A Scan may use one or two
lanes. Concurrency is fixed per configuration and separately constrained by rate limits and circuit
breakers; it is not adaptive.

### Finding bucket

The persisted stage of a Finding: `sast` for deterministic scanner output, `raw_llm` for
pre-consolidation LLM output, and `consolidated` for user-facing results.

### Durable task

A ScanTask ledger entry keyed by stage and input hash. Completed matching work can be reused during
resume; restart deletes derived work and reruns from the original snapshot.

### Snapshot

An immutable code tree associated with a Scan. Current snapshot types include
`ORIGINAL_SUBMISSION` and, for successful remediation scans, `POST_REMEDIATION`.

### Scan event

An append-only lifecycle/activity record consumed by the status and SSE progress interfaces. Events
must carry actionable stage details; status changes alone are insufficient operator telemetry.

### Scan artifact

A versioned structured payload associated with a Scan. Finding lineage and patch-plan projections
remain structured artifacts. Large native scanner reports and exact rule bodies are stored as
encrypted, versioned, attempt-addressed evidence objects; bounded legacy JSON artifacts remain
readable only during migration.

### Finding lineage

The graph connecting raw deterministic/LLM findings to consolidated or dropped outcomes. New scans
use a persisted lineage artifact; legacy scans fall back to inferred title-based relationships.

### Visibility scope

The tenant and user-group constraints applied to user-owned list/query operations. Tenant-wide
permission may remove the ownership/group filter inside the active tenant, but no role bypasses the
tenant predicate or forced PostgreSQL RLS. Other callers receive an explicit same-tenant visible-user
set.

### Feature catalog

The runtime feature flags seeded by an installation variant. Scan is always enabled; optional
features include chat, compliance, multi-user, groups, SSO, SCIM, multi-tenancy, email,
observability stacks, MCP, admin authoring, and the separately gated Pentesting bounded context.

### Pentest Engagement

A Project-linked, tenant-scoped authorization and rules aggregate for black-box, gray-box, or
white-box pentesting. It is separate from Code Scan and owns Pentest Attempts, decisions,
executions, evidence references, finding truth, coverage effects, mutations, cleanup, and retests.

### Pentest Attempt

The immutable execution identity for an Engagement run. Resume retains the Attempt; restart or
retest creates a linked child. Every Attempt pins its contract, policy, catalog, adapter, evidence,
prompt, model, report, and runner versions.

### Pentest DecisionDelta

A digest-chained, monotonically sequenced summary of one atomic committed state change. A dependent
orchestrator decision may consume only committed deltas, never in-flight tool output.

### Pentest finding truth

The deterministic progression from evidence-backed Observation to CandidateFinding and, only after
a configured evidence predicate or independent reproduction, ConfirmedFinding. A scanner, adapter,
specialist, or model cannot directly confirm a finding.

## Invariants

- PostgreSQL status, events, tasks, artifacts, and snapshots are authoritative; UI state is derived.
- Submission and approval work must be recoverable through the DB outbox even if RabbitMQ is down.
- Prescan Approval and Cost Approval are distinct decisions; Profiling Approval is a third gate.
- Only consolidated findings are normal user-facing results.
- Resume reuses matching durable tasks; restart preserves audit history but removes derived work.
- Scanner and LLM provenance must survive consolidation and reporting.
- Secrets are encrypted before database persistence and must not appear in logs or public artifacts.
- Every list operation over user-owned data must enforce tenant and visibility scope.
- Pentesting remains a separate Project-linked bounded context; it never stretches or mutates the
  existing Code Scan aggregate or lifecycle.
- PostgreSQL is authoritative for Pentesting state; RabbitMQ is notification-only through an
  outbox, and Qdrant is methodology retrieval only.
- Every Pentesting target interaction requires authorization, tenant/attempt identity, and a pinned
  deterministic scope-policy decision. Secrets use opaque handles outside their broker boundary.
- Pentest coverage passes only through exact evidence predicates; absence of a tool alert is not a
  pass, and no unverified observation is a confirmed finding.
- Mutations are registered before execution, cleanup remains durable and visible, and cancellation
  cannot turn partial work into success.
- Changes to lifecycle nodes, edges, statuses, events, or approvals update the canonical workflow
  documentation in the same change.

## Current implementation notes and limitations

- Submission, approval/decline, resume, and restart commit their aggregate changes and outbox intent
  atomically and never publish inline. Cancellation commits its status and audit event atomically.
- The declared status-transition policy is enforced by API, repository, worker-finalizer, and
  sweeper writes. Terminal statuses have no normal exits; authorized manual run control is the only
  `FAILED`/`CANCELLED` reset path.
- Successful graph nodes append their exact identifier to `WorkerState.completed_stages` in the
  same LangGraph checkpoint as their outputs. Resume retains the failed thread; restart deletes it.
- Native scanner evidence is stored in encrypted, versioned, attempt-addressed object storage.
  Bounded PostgreSQL JSON remains a migration-only read path and never overrides verified evidence.
- SSE exposes persisted scan events and scanner-level activity, but many non-scanner stages still
  contain only coarse state transitions.
- Prompt limits currently reject oversized calls; they do not split or compact prompts.
- Global consolidation uses deterministic exact-field grouping rather than an LLM-assisted
  cross-file root-cause pass.
- Browser traffic uses an HttpOnly, opaque, stateful server-side session plus a memory-only CSRF
  proof. The bearer-token FastAPI Users surface remains only as a compatibility/non-browser boundary
  while browser-managed access tokens are retired; browser-level longevity testing is still missing.
- The inherited automated test suites were removed on 2026-08-22. Replacement tests are added only
  at verified production seams as defects and invariants are addressed.
- Pentesting Foundation 0 currently implements versioned contracts, vocabulary, feature discovery,
  permissions, generated frontend wire types, and provider/consumer tests only. It does not yet
  persist Engagements or execute target activity.
