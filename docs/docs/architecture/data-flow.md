---
title: Data Flow
sidebar_position: 5
---

# Scan data flow

This page describes the implemented workflow. Status names come from
`src/app/shared/lib/scan_status.py`; graph wiring comes from
`src/app/infrastructure/workflows/worker_graph.py`.

## 1. Submission

`POST /api/v1/scans` accepts selected uploads, a supported HTTPS Git URL, or an archive. The
submission module validates framework and LLM selections, file counts and sizes, executable magic,
and supported Git hosts. It creates or updates the Project, stores deduplicated SourceCodeFiles,
creates the Scan, initial `ScanAttempt`, and `ORIGINAL_SUBMISSION` Snapshot, appends the queued event, and writes a
`scan_outbox` message. Project/source changes and those scan-owned rows commit atomically. The
request path does not contact RabbitMQ; the sweeper is the sole publisher and preserves the request
correlation ID from the outbox payload.

## 2. Worker preparation

The RabbitMQ worker consumes `code_submission_queue`, verifies the message's attempt is current,
creates the initial WorkerState, and invokes the LangGraph thread keyed by `scan_id` using the
Postgres checkpointer. Resume keeps the same attempt; restart creates the next child attempt.

`retrieve_and_prepare_data` reloads the original snapshot, selected frameworks and agents, creates a
tree-sitter repository map and dependency graph, and stores workflow artifacts for later stages.

`classify_files` applies deterministic first-party, vendor, minified, generated, static, and unknown
classification. The policy is persisted to `Scan.file_profiles`. Low-value files skip selected
expensive paths unless `deep_vendor_scan` is enabled.

## 3. Deterministic prescan

`deterministic_prescan` stages the selected tree and runs applicable scanners concurrently:

- Bandit for Python security checks.
- Semgrep using enabled, database-ingested rules selected for the scan.
- Gitleaks for secrets.
- OSV-Scanner for dependency vulnerabilities and CycloneDX BOM generation.

Parsed findings are persisted in the `sast` bucket before any LLM call. Individual scanner failure
is non-fatal and is recorded as an event/log. Bounded native scanner reports and a status manifest
are retained as an encrypted, versioned, attempt-scoped object. Its append-only manifest binds
exact object version, digests, provenance, actor, and retention metadata. The API authorizes the
caller, decrypts the exact version, and verifies integrity before returning it. Legacy JSON remains
readable while backfill expands existing rows; object-integrity failures never fall back.

If findings exist, `pending_prescan_approval` sets `PENDING_PRESCAN_APPROVAL` and interrupts. A
decline ends at `BLOCKED_USER_DECLINE`; continuing past a Critical Gitleaks result requires an
explicit override. With no findings, this gate is skipped.

## 4. Profiling approval and profiling

`estimate_profiling_cost` estimates utility-model profiling cost and always pauses at
`PENDING_PROFILING_APPROVAL`. Approval resumes the same checkpoint and `profile_files` generates a
summary, security-relevant operations, and applicable domains for each eligible file. Profiling uses
a fixed concurrency limit. The estimate counts the complete rendered profiling envelope and returns
expected/upper-bound cost, confidence, historical sample count, planned requests, and assumptions.

## 5. Deep-analysis cost approval

`estimate_cost` resolves routed agents per file, renders the same system/RAG/scanner/dependency/code/
schema envelope execution will send, and prices one or two reasoning lanes. Model/stage ledger
history supplies median expected and p90 upper output/retry factors; sparse history uses an explicit
conservative fallback. It also estimates a rough processing duration and emits configured RPM/TPM or
prompt-limit warnings. It persists the range and its assumptions, sets `PENDING_COST_APPROVAL`, and
interrupts. The conservative bound controls scan ceilings and high-value approval flags.

Prompt-size enforcement currently happens at the LLM client and rejects calls over
`max_prompt_tokens`; no automatic prompt splitting or compaction is implemented.

An accepted approval or decline compare-and-sets the matching gate to `QUEUED_FOR_SCAN`, writes its
audit events, and inserts an `analysis_approved_queue` outbox intent in one transaction. The request
does not contact RabbitMQ; the outbox sweeper publishes it and the worker resumes with
`Command(resume=payload)`. Duplicate or stale decisions create no additional intent.

## 6. Parallel analysis and durable tasks

`analyze_files_parallel` plans file × chunk × agent × lane invocations. Routing combines each
agent's deterministic language baseline with profiler-selected domains. Low-value classified files
may be skipped according to policy.

Every invocation is represented by a ScanTask keyed by stage and input hash. Matching completed
tasks are reused during resume. Calls use a fixed semaphore per LLM configuration plus per-config
RPM/TPM rate limiting, retry with jitter, and a circuit breaker. Concurrency is not adaptive.

The optional secondary reasoning model creates a second lane. Findings from both lanes retain model
provenance. If all attempted agents fail, the scan fails; partial lane degradation is recorded.

`save_raw_llm_findings` snapshots analysis output to the `raw_llm` bucket before consolidation.

## 7. Consolidation and validation

`consolidate_findings` runs a durable reasoning-model pass per file. It merges same-root findings,
drops noise/false positives, and records a flow map. Failure falls back to passthrough findings.

`global_consolidate_findings` then performs deterministic cross-file grouping using exact normalized
source, CWE, title, and remediation keys. It is not currently an LLM-assisted global root-cause
analysis.

When enabled, `validate_cross_file` makes a non-destructive reasoning pass over eligible findings and
adds `confirmed`, `mitigated`, or `unconfirmed` status plus rationale. It does not change severity or
delete findings.

## 8. Remediation and verification

For SUGGEST and REMEDIATE, patch candidates are tied to stable raw/canonical finding UUIDs and the
exact original source hash; consolidation rejects dropped candidates and validates selected anchors
and syntax. `consolidate_and_patch` resolves exact byte ranges, collapses duplicates, routes
ambiguous anchors and transitive overlap components to manual review, and atomically applies the
remaining disjoint edits with a whole-file syntax gate. Each planned file then runs against the
original repository tree in the fixed-profile, networkless `patch-validator` container. Its child
cannot access SCCAP secrets, the host workspace, or the shared job spool. Both modes persist a
versioned unified-diff patch plan. Automatic plans are bounded before persistence to 64 hunks,
256 KiB positive replacement expansion, and 512 KiB UTF-8 unified diff per file, with scan-wide
limits of 256 hunks, 1 MiB expansion, and 2 MiB diff. The sorted planner admits files against one
scan budget; overflow discards that file's proposed output and records a blocking
`patch_size_policy` manual-review check without growing the checkpoint artifact. Remediation mode
is selected at submission; there is no current
post-result workflow where arbitrary findings are selected and applied incrementally.

Patch-plan version 2 distinguishes parser pass/failure, tool absence, skipped/not-run checks,
timeouts, and infrastructure errors. Blocking non-pass outcomes never promote a file. Semgrep
findings persist native rule identity, and replay uses that identity plus the resolved patch site,
including line shifts from earlier hunks; file+CWE matching is retained only for legacy findings.
Semgrep replay validates the current attempt's scanner-report evidence and exact-loads only the
rule identities recorded by prescan. It verifies the complete ruleset digest and each retained
YAML body's ingestion hash before materialization. Removed, disabled, reassigned, changed, or newly
added live rule rows cannot affect replay. Legacy evidence without an exact historical body fails
closed.

`verify_patches` runs before promotion for both modes. It rejects persistent originating Semgrep,
Bandit, or Gitleaks rules and new changed-file findings from any of those scanners, then promotes
passing files only for REMEDIATE. A successfully parsed native report is required; a swallowed
runner failure is never treated as a clean scan. Failures are file-atomic, so a scan can finish as
`partial_remediation`. OSV-originated fixes and dependency-lockfile changes use
the manifest-hashed advisory snapshot through explicit offline/no-resolve
flags. Missing, mutable, corrupt, timed-out, or invalid OSV replay evidence
blocks promotion; the exact snapshot digests remain in the validation check.
LLM-originated fixes use a separate reasoning-model gate over bounded file-local
before/after evidence at the resolved patch location. Only an evidence-citing `resolved` verdict
passes; `not_resolved`, `uncertain`, missing configuration, provider failure, and missing audit
projection all keep the file in manual review. The verdict/rationale are stored separately from
native scanner replay, and the call is recorded in the usage ledger and retained LLM interaction
log.
Candidate summaries reconcile governance and planner outcomes into mutually exclusive terminal
categories, expose `validated` explicitly, and keep `applied` as its REMEDIATE-only subset.
Candidate-scoped LLM usage identity is checked before provider invocation. A retained interaction
is reused only after exact scan/configuration/stage/agent/template/candidate/file binding and
structured-verdict validation. An orphaned, expired, malformed, or mismatched interaction fails
closed without another provider call. Before a new call, SCCAP commits a unique, attempt-bound,
non-reclaimable reservation. A crash after possible provider acceptance therefore blocks retry
instead of risking a second billable request. The ledger also exposes whether the current response
won the idempotency insert, preventing a concurrent second verdict from being validated against the
first response's audit record.

## 9. Results and artifacts

`save_results` replaces the Scan's consolidated finding bucket and governed candidate rows
idempotently. `save_final_report`
then computes the weighted CVSS aggregate, writes summary/status metadata, saves the remediation
snapshot when applicable, and persists a versioned finding-lineage ScanArtifact.

These operations use separate database transactions. New lineage links use exact raw/canonical UUIDs
and include candidate decisions; stable hash/title inference is retained only for legacy scans.

HTML, CSV, PDF, and SARIF reports are rendered from stored results on demand. SARIF is not stored as
a separate blob.

## 10. Activity streaming and cancellation

The API exposes a tokenized Server-Sent Events stream; SCCAP does not use WebSockets for scan
progress. PostgreSQL `LISTEN/NOTIFY` wakes the process when new ScanEvents arrive, and polling/replay
supports reconnects. The frontend projects these events into its progress model.

Every new activity row is a version-1 envelope containing a monotonic cursor/event ID, attempt ID,
activity kind, stage/status, timestamp, and bounded redacted details. The taxonomy separates
workflow, scanner, LLM-call, retry, warning, degradation, decision, cancellation, and terminal
activity. The browser reconnects from its last cursor, receives only greater IDs, and deduplicates
the HTTP seed, SSE replay, and polling fallback by the same ID. The running page provides stage and
type filters and renders timings, retry backoff, warnings, and degraded lanes/components.

Cancellation compare-and-sets an active scan to `CANCELLED` and appends `REQUESTED` in one
transaction. Paused work records `OBSERVED` and `COMPLETED` immediately. A running worker polls at
250 ms, acknowledges observation, terminates registered scanner process groups, cancels the current
provider/workflow task, and records completion latency against a two-second SLO. SSE withholds its
terminal `done` event until cancellation completion is durable.

## 11. Resume and restart

Eligible failed or cancelled scans can resume when reusable artifacts exist. Resume keeps completed
matching ScanTasks. Restart deletes tasks, findings, and derived snapshots but preserves the original
snapshot, configuration, events, and LLM audit records. The status claim, restart cleanup, lifecycle
events, and replacement outbox intent commit atomically.

Successful graph nodes record their exact node name in `WorkerState.completed_stages` as part of the
same LangGraph checkpoint update. Failed threads are retained and resume re-enters that thread;
restart explicitly deletes it. The worker no longer infers a safe jump from completed consolidation
tasks, so it cannot bypass cross-file validation, patch merge, verification, results persistence, or
final reporting. Checkpoint deserialization is strict: only SCCAP's explicitly registered state
models may be reconstructed, rather than allowing checkpoint data to import arbitrary Python types.

Patch compilation runs in the separate networkless validator. Fixed profiles cover Python
compile/pytest, JavaScript syntax, TypeScript no-emit type checking, Go package compilation, and
Java compilation with annotation processing disabled. It never evaluates package-manager scripts;
Go binaries are compiled behind a fixed no-op executor. Every check records the actual image
toolchain version because Debian security rebuilds may advance compiler patch levels.

Before compilation, the planner inventories Python, npm, Go, Maven/fixed-string Gradle, .NET project,
Ruby Gemfile, and PHP Composer dependency manifests without executing repository code. Requirements
pass only when the package/module identity is already declared and the requested constraint can be
proven compatible. A missing declaration, weaker or ambiguous version, malformed relevant manifest,
configuration/migration requirement, or operator manual step remains blocking evidence. Cross-file
dependency additions are not silently synthesized under the current file-atomic promotion model.

The planner also builds a bounded, read-only import index from the uploaded
snapshot. It validates declared required imports and imports introduced directly
inside replacement code for Python, JavaScript/TypeScript, Go, and Java. Local
module paths and local Python/JavaScript names must resolve; external module roots
must be platform-provided or conservatively backed by the existing dependency
manifest inventory. Malformed, ambiguous, missing, wildcard-Python, oversized,
or unsupported required imports block the file. This stage parses text only and
does not import uploaded modules or execute package-manager/repository code.

## Persistence summary

| Record | Purpose |
| --- | --- |
| Scan | Configuration, status, estimates, summary, preferences |
| ScanEvent | Append-only lifecycle and activity timeline |
| ScanOutbox | Recoverable RabbitMQ publication intent |
| ScanTask | Durable per-invocation work ledger |
| Finding | `sast`, `raw_llm`, or `consolidated` result |
| CodeSnapshot | Original and post-remediation code trees |
| ScanArtifact | Versioned structured artifacts such as finding lineage |
| LLMInteraction | Prompt/output/usage/cost audit record |
