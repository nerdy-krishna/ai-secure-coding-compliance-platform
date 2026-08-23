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

A versioned structured payload associated with a Scan. Finding lineage and bounded native scanner
reports are currently persisted as artifacts.

### Finding lineage

The graph connecting raw deterministic/LLM findings to consolidated or dropped outcomes. New scans
use a persisted lineage artifact; legacy scans fall back to inferred title-based relationships.

### Visibility scope

The tenant and user-group constraints applied to user-owned list/query operations. Superusers may
receive an unrestricted scope; ordinary users receive the explicit visible-user set within their
tenant.

### Feature catalog

The runtime feature flags seeded by an installation variant. Scan is always enabled; optional
features include chat, compliance, multi-user, groups, SSO, SCIM, multi-tenancy, email,
observability stacks, MCP, and admin authoring.

## Invariants

- PostgreSQL status, events, tasks, artifacts, and snapshots are authoritative; UI state is derived.
- Submission and approval work must be recoverable through the DB outbox even if RabbitMQ is down.
- Prescan Approval and Cost Approval are distinct decisions; Profiling Approval is a third gate.
- Only consolidated findings are normal user-facing results.
- Resume reuses matching durable tasks; restart preserves audit history but removes derived work.
- Scanner and LLM provenance must survive consolidation and reporting.
- Secrets are encrypted before database persistence and must not appear in logs or public artifacts.
- Every list operation over user-owned data must enforce tenant and visibility scope.
- Changes to lifecycle nodes, edges, statuses, events, or approvals update the canonical workflow
  documentation in the same change.

## Known current limitations

- Submission, approval/decline, resume, and restart commit their aggregate changes and outbox intent
  atomically and never publish inline. Cancellation commits its status and audit event atomically.
- The declared status-transition policy is enforced by API, repository, worker-finalizer, and
  sweeper writes. Terminal statuses have no normal exits; authorized manual run control is the only
  `FAILED`/`CANCELLED` reset path.
- Successful graph nodes append their exact identifier to `WorkerState.completed_stages` in the
  same LangGraph checkpoint as their outputs. Resume retains the failed thread; restart deletes it.
- Scanner reports are retained in bounded PostgreSQL JSONB, but they are not yet immutable,
  attempt-addressed evidence in object storage.
- SSE exposes persisted scan events and scanner-level activity, but many non-scanner stages still
  contain only coarse state transitions.
- Prompt limits currently reject oversized calls; they do not split or compact prompts.
- Global consolidation uses deterministic exact-field grouping rather than an LLM-assisted
  cross-file root-cause pass.
- Authentication uses bearer access/refresh tokens. Password, SSO, and WebAuthn login now share the
  refresh-cookie issuance path, and logout expires both cookies; browser-level longevity testing is
  still missing.
- The inherited automated test suites were removed on 2026-08-22. Replacement tests are added only
  at verified production seams as defects and invariants are addressed.
