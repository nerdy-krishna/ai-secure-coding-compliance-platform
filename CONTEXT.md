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
observability stacks, MCP, admin authoring, and the separately gated pentest engine.

### Pentest run

One authorised assessment of one target: the operator supplies a target origin, a box type
(black, gray, white), optional credentials, and the tools to leave out. It is unconnected to Code
Scan except in white-box mode, where it reads one completed Code Scan report. A run is a single
row and a single engine loop — there is no engagement/attempt/execution hierarchy.

### Pentest lead

A single concrete thing left to test, held in the run's lead ledger. Leads are written whenever a
tool observes surface (a host, a port, a path, an API operation, a parameter, a form, a secret) and
carry a priority band: attacker-controlled input first, then endpoints, then hosts, then plain
inventory. The model claims leads as it tests them, and an early "done" is refused while testable
leads remain. The ledger, not the conversation, is the completion authority.

### Pentest observation

Surface intelligence recorded as a finding with `category = observation`: open ports, technologies,
security headers, discovered paths, subdomains, API operations with their parameters, endpoints and
parameters mined from JavaScript, TLS certificates, leaked secrets, error stack traces. Observations
are not weaknesses, but they are retained because exploit chains are built out of them.

### Pentest finding

A weakness recorded with `category = vulnerability`: a scanner verdict (nuclei, ZAP, sqlmap), an
exposed secret or source map, a published API schema or enabled GraphQL introspection, a
subdomain-takeover candidate, a sensitive reachable path, missing security headers, or a leaked
stack trace. Every finding is kept, exploitable or not; exploitability is recorded later.

### Pentest exploit chain

The next-level analysis over a completed run: the model reads weaknesses, observations and untested
leads, and records ordered chains (steps, impact, confidence) on the findings they involve.

## Invariants

- PostgreSQL status, events, tasks, artifacts, and snapshots are authoritative; UI state is derived.
- Submission and approval work must be recoverable through the DB outbox even if RabbitMQ is down.
- Prescan Approval and Cost Approval are distinct decisions; Profiling Approval is a third gate.
- Only consolidated findings are normal user-facing results.
- Resume reuses matching durable tasks; restart preserves audit history but removes derived work.
- Scanner and LLM provenance must survive consolidation and reporting.
- Secrets are encrypted before database persistence and must not appear in logs or public artifacts.
- Every list operation over user-owned data must enforce tenant and visibility scope.
- Pentesting is a separate engine and never writes Code Scan status, events, checkpointers, outbox
  rows, or approval state. A white-box run reads one completed Code Scan report and has no write
  authority.
- A pentest run's coordination is PostgreSQL alone: no broker message, signed task, or outbox row is
  required for a run to progress, and none is produced by it.
- Every pentest target interaction is inside scope: the operator's origin plus the in-scope estate
  discovered beneath its registrable domain, resolved through `RunContext.scoped_url()`. Nothing
  outside it is touched, and private/loopback destinations are refused.
- Findings and observations are both persisted; nothing a scanner observed is discarded, because
  exploit chaining depends on it.
- The lead ledger is the completion authority: a run may conclude only when no testable lead
  remains. Context truncation, pause/resume and an engine restart never lose queued work.
- An operator stop takes effect inside an in-flight model call and inside a running subprocess, not
  only between steps.
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
- Pentesting is one autonomous engine (ADR-029), not the controller/qualification stack recorded in
  ADR-013 to ADR-028. A run is recon (evasive, rate-limited, discovery-first) followed by an LLM +
  tool loop that works a persistent lead queue until testable surface is exhausted. Findings and
  observations are both persisted; exploit chaining is a separate pass over a completed run. The
  binding limits are scope (the operator's origin plus the in-scope estate discovered beneath its
  registrable domain) and the SSRF guard — there are no intensity, budget, qualification, signature,
  or per-run duration limits.
