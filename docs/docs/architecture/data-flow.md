---
title: Data Flow
sidebar_position: 5
---

# Data Flow

This page is the narrative version of
[`.agent/scanning_flow.md`](https://github.com/nerdy-krishna/ai-secure-coding-compliance-platform/blob/main/.agent/scanning_flow.md).
Code references inside the repo — `worker_graph.py`,
`scan_service.py`, `consumer.py` — are authoritative; this page is a
pointer-heavy summary.

## Scan lifecycle

### 1. Submit (API)

- UI posts to `POST /api/v1/scans` with files / git URL / archive +
  framework selection + per-slot LLM ids.
- `projects.py` router → `scan_service.create_scan_from_uploads`
  (or `from_git` / `from_archive`) dedupes files by hash, creates
  the `Scan` row + an `ORIGINAL_SUBMISSION` code snapshot, and
  inserts a row into `scan_outbox` targeting
  `code_submission_queue`. All in one transaction.
- Response: `{ scan_id, project_id, message }`.

### 2. Outbox sweep

- `outbox_sweeper` (background task on the API) reads unpublished
  rows older than 30 s and publishes them to RabbitMQ with
  exponential backoff on `attempts`. If the broker is down when the
  API transaction commits, the scan is **still safely enqueued** —
  the sweeper catches it when RabbitMQ comes back.

### 3. Worker pickup

- `workers/consumer.py` pulls the message, builds a `WorkerState`,
  and invokes the compiled LangGraph with a Postgres-backed
  `AsyncPostgresSaver` checkpointer keyed on `scan_id`.
- Status transitions are written as `ScanEvent` rows so the UI can
  subscribe to `/scans/{id}/stream` (SSE) and paint a live progress
  rail.

### 4. Context + deterministic prescan

`retrieve_and_prepare_data` → `RepositoryMappingEngine` +
`ContextBundlingEngine` → `deterministic_prescan`:

- Tree-sitter builds a symbol index for every file; the dependency
  graph bundles import chains for later cross-file context.
- `deterministic_prescan` runs Bandit, Semgrep, Gitleaks, and
  OSV-Scanner against a staged copy of the tree, seeds
  `WorkerState.findings` with `source="<scanner>"` rows, and persists
  a CycloneDX BOM. No LLM has been called yet.
- If the prescan produced findings, the graph pauses at
  `pending_prescan_approval` (status `PENDING_PRESCAN_APPROVAL`) for
  operator review. A declined gate ends the scan at
  `BLOCKED_USER_DECLINE`; an unacknowledged Critical secret ends it
  at `BLOCKED_PRE_LLM`.

### 5. Profiling-cost gate + per-file profiler

`estimate_profiling_cost` → `profile_files`:

- `estimate_profiling_cost` token-counts every file on the **utility**
  LLM slot, persists the estimate, and pauses at `interrupt()` with
  status `PENDING_PROFILING_APPROVAL`. This gate fires even when the
  prescan found nothing.
- On approval, `profile_files` runs the `FileProfiler` over every
  file on the utility slot. Each profile carries a summary, the
  file's security-relevant operations, and its **applicable
  domains** — the subset of the scan's agent roster relevant to the
  file. Profiles are persisted to `Scan.file_profiles`.

### 6. Analysis-cost gate

`estimate_cost`:

- For each file, resolves the **content-routed agent set** from its
  profile's applicable domains (`resolve_agents_for_file`).
- Tokenizes the routed prompt set with `litellm.token_counter` and
  prices it against `litellm.cost_per_token` (honoring any
  per-`LLMConfiguration` override) — the estimate reflects the agents
  each file is actually routed to, not a worst-case roster.
- `cost_details` is persisted, status flips to
  `PENDING_COST_APPROVAL`, and the node calls **`interrupt()`**.

### 7. User approves (or cancels)

Each gate works the same way. The UI shows the estimate / findings;
the user:

- **Approves** → API publishes to `analysis_approved_queue` with a
  `kind` discriminator (`prescan_approval` / `profiling_approval` /
  `cost_approval`); the worker invokes the same LangGraph thread with
  `Command(resume=payload)` and execution continues from the pause.
- **Cancels / declines** → `cancel_scan` sets `CANCELLED`, or a
  declined prescan/profiling gate routes to `BLOCKED_USER_DECLINE`.
  Checkpointer state is left in place for inspection.

### 8. Single-pass parallel analysis

`analyze_files_parallel`:

- Every file from the `ORIGINAL_SUBMISSION` snapshot is analyzed in
  parallel — **no topological ordering, no cross-file patch
  propagation**. The dependency graph is consulted to inject per-file
  dependency context (symbol signatures from successors) into each
  chunk's prompt.
- **Content-based routing**: each file is analyzed only by the agents
  its profile routed to (`resolve_agents_for_file` narrowed by the
  profile's applicable domains, systems/web gating applied first). A
  file with no profile falls back to extension-only routing.
- Files larger than `CHUNK_ONLY_IF_LARGER_THAN` (~150 000 chars) are
  split with `semantic_chunker`; small files run as a single chunk.
- Concurrency is bounded by a single
  `asyncio.Semaphore(CONCURRENT_LLM_LIMIT=5)` over the union of
  file × chunk × agent calls.
- No mid-graph DB writes. Findings + `proposed_fixes` flow through
  state to `consolidate_findings` and beyond.

### 9. Consolidation

`consolidate_findings` (backed by the `FindingConsolidator`, reasoning
slot) replaces the old exact-key `correlate_findings`. Per file, it
feeds the source plus all raw findings to the reasoning LLM in one
pass: findings describing the same root cause merge into one root
finding (leading with the root cause + fix, listing every
`affected_location`, unioning `corroborating_agents`, re-assessing
CVSS); false positives, fully-subsumed duplicates, and non-actionable
noise are dropped. `save_results_node` then deletes the raw prescan
rows and writes the consolidated set fresh.

### 10. Remediation (REMEDIATE only)

`consolidate_and_patch` runs after `consolidate_findings`:

- Groups `proposed_fixes` by file.
- Detects line-range conflicts and runs `_run_merge_agent` to
  resolve overlaps.
- Tree-sitter syntax-verifies the patched content
  (`_verify_syntax_with_treesitter`).
- Builds `final_file_map` for the `POST_REMEDIATION` snapshot saved
  by `save_results_node`, so users can diff against the
  `ORIGINAL_SUBMISSION`.

For AUDIT it's a no-op. For SUGGEST the consolidated findings keep
their embedded `fixes` field (so the UI shows suggested fixes) but
no `POST_REMEDIATION` snapshot is built.

### 11. Final report

`save_final_report`:

- Computes the CVSS-weighted 0–10 `risk_score` via
  `shared.lib.risk_score.compute_cvss_aggregate`.
- Persists the `summary` JSON.
- Sets final status `COMPLETED` or `REMEDIATION_COMPLETED`.

The per-scan `Scan.risk_score` and the Dashboard / Compliance posture
score share this one calculation: the worker stores it as a 0–10
intensity value, and `to_posture_score` maps it to a 0–100 posture
scale (higher = healthier) for the dashboard. Same math, two views.

## Chat (Advisor) flow

1. `POST /chat/sessions` creates a session with a title, LLM config
   id, optional project id, and framework list.
2. `POST /chat/sessions/{id}/ask` calls `chat_service.post_message_to_session`:
   - Persist the user message.
   - Load full history (or a summary, if the session has been
     compacted).
   - Call `chat_agent.generate_response` → RAG retrieval scoped to
     the session's frameworks via
     `rag_service.query_guidelines(where={"framework_name": {"$in": [...]}})`
     → LLM call → Pydantic AI validation.
   - Persist the assistant message + link to its `llm_interaction`
     row.
3. `GET /chat/sessions/{id}/context` aggregates the right-rail feed:
   session frameworks as knowledge sources, plus the top-severity
   findings + file paths from the linked project's latest terminal
   scan.

## Observability

Every step above writes at least one log line carrying the request's
`X-Correlation-ID`, and every LLM call writes an `llm_interaction`
row with the exact prompt_context + usage + cost. Scans can be
replayed via Admin → LLM Interactions; logs can be traced via
Grafana → Loki with the correlation id.

## Queue names

Wired from `src/app/config/config.py`:

- `RABBITMQ_SUBMISSION_QUEUE` → `code_submission_queue`
- `RABBITMQ_APPROVAL_QUEUE` → `analysis_approved_queue`
- `RABBITMQ_REMEDIATION_QUEUE` → `remediation_trigger_queue`

## Status strings

Canonical values live at the top of
`src/app/shared/lib/scan_status.py`:

`QUEUED`, `PENDING_PRESCAN_APPROVAL`, `PENDING_PROFILING_APPROVAL`,
`PENDING_COST_APPROVAL`, `QUEUED_FOR_SCAN`, `ANALYZING_CONTEXT`,
`RUNNING_AGENTS`, `GENERATING_REPORTS`, `COMPLETED`,
`REMEDIATION_COMPLETED`, `BLOCKED_PRE_LLM`, `BLOCKED_USER_DECLINE`,
`FAILED`, `CANCELLED`.

`ACTIVE_SCAN_STATUSES` and `COMPLETED_SCAN_STATUSES` tuples are
exported for the filters used across services. `BLOCKED_PRE_LLM` and
`BLOCKED_USER_DECLINE` are the two terminal states a gate decline can
produce; the `GENERATING_REPORTS` constant is preserved for tuple
membership but no node sets it today.
