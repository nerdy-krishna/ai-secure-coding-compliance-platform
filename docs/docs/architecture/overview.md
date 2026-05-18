---
title: Architecture Overview
sidebar_position: 1
---

# Architecture Overview

SCCAP runs as a small compose stack: an API service, a worker, the
data stores the two share, and an observability pipeline.

```
┌──────────┐       ┌─────────┐       ┌─────────┐
│   UI     │  ◄─►  │   API   │  ◄─►  │ Postgres│
│ (Vite)   │       │(FastAPI)│       └─────────┘
└──────────┘       └────┬────┘       ┌─────────┐
                        │       ◄─►  │ Qdrant  │
                        ▼            └─────────┘
                   ┌─────────┐
                   │RabbitMQ │
                   └────┬────┘
                        │
                        ▼
                   ┌─────────┐       ┌────────────────────┐
                   │ Worker  │  ───► │ Fluentd → Loki →   │
                   │(LangGr.)│       │ Grafana            │
                   └─────────┘       └────────────────────┘
```

## Responsibilities

- **API (`app`)** — FastAPI routers under `src/app/api/v1/routers/`.
  Handles auth, admin CRUD, scan submissions, scan result lookups,
  chat sessions, and the MCP tool surface. Writes scan rows +
  outbox rows in a single transaction; never publishes to RabbitMQ
  inline.
- **Worker (`worker`)** — consumes `code_submission_queue` and
  `analysis_approved_queue` via `aio-pika`. Every message invokes the compiled
  LangGraph (`infrastructure/workflows/worker_graph.py`) keyed on
  `scan_id` via an `AsyncPostgresSaver` checkpointer.
- **Outbox sweeper** — a background task inside the API (see
  `src/app/infrastructure/messaging/outbox_sweeper.py`) periodically
  reads `scan_outbox` for unpublished rows and actually publishes them
  to RabbitMQ. This closes the race between "scan row committed" and
  "RabbitMQ publish failed."
- **Postgres** — authoritative store for everything SCCAP writes,
  including the LangGraph checkpoint tables (`checkpoints`,
  `checkpoint_writes`, `checkpoint_blobs`, `checkpoint_migrations`)
  managed by the Postgres checkpointer.
- **Qdrant** — vector store for RAG (replaced ChromaDB per ADR-008).
  Uses `fastembed` with `sentence-transformers/all-MiniLM-L6-v2`
  (lazy-downloaded on first use); framework-scoped via metadata filters.
- **Fluentd → Loki → Grafana** — structured log aggregation.

## Code layout (backend)

- `src/app/api/v1/routers/` — FastAPI routers; wired in `main.py`.
  Admin endpoints are split by concern (`admin_agents`,
  `admin_frameworks`, `admin_prompts`, `admin_rag`, `admin_config`,
  `admin_users`, `admin_groups`, `admin_seed`, `llm_config`).
- `src/app/core/services/` — orchestration layer. Routers delegate
  here rather than touching repositories directly.
- `src/app/infrastructure/database/repositories/` — one repository
  per aggregate: `scan_repo`, `chat_repo`, `user_repo`,
  `framework_repo`, `agent_repo`, `prompt_template_repo`,
  `llm_config_repo`, `rag_job_repo`, `system_config_repo`,
  `user_group_repo`.
- `src/app/infrastructure/agents/` — LangGraph sub-graphs
  (`generic_specialized_agent`, `impact_reporting_agent`,
  `chat_agent`, `symbol_map_agent`).
- `src/app/infrastructure/workflows/worker_graph.py` — the top-level
  LangGraph `StateGraph`. Any edit to nodes / edges must be reflected
  in `.agent/scanning_flow.md`.
- `src/app/shared/analysis_tools/` — `chunker.py` (semantic
  splitter), `context_bundler.py` (dependency graph), `repository_map.py`
  (tree-sitter symbol index).

## Cross-cutting services

- **`SystemConfigCache`** (`src/app/core/config_cache.py`) — a
  process-local singleton populated at startup from `system_config`
  rows. Drives the dynamic CORS middleware, log level, and SMTP
  settings. When editing `system_config` at runtime, the cache is
  also updated or the change won't take effect until restart.
- **`correlation_id_middleware`** — attaches an `X-Correlation-ID`
  to every inbound request and stores it in a `ContextVar` so all
  log entries automatically carry it.
- **`DynamicCORSMiddleware`** — allows all origins until setup
  completes, then tightens to
  `system_config['security.allowed_origins']` + env `ALLOWED_ORIGINS`.
- **`correlation_id_var`** — propagated into the worker via the
  message envelope; worker logs stitch across the boundary.

## Scan lifecycle (short form)

Full flow: see
[Architecture → Data Flow](./data-flow.md) or
[`.agent/scanning_flow.md`](https://github.com/nerdy-krishna/ai-secure-coding-compliance-platform/blob/main/.agent/scanning_flow.md)
for the canonical version.

1. UI `POST /api/v1/scans` → `projects.py` router →
   `scan_service.create_scan_from_*` dedupes files, creates `Scan` +
   `ORIGINAL_SUBMISSION` snapshot, writes an outbox row to
   `code_submission_queue`.
2. Worker picks up the message, builds a `WorkerState`, and calls the
   compiled LangGraph with the Postgres checkpointer.
3. Audit pass: `retrieve_and_prepare_data` → `RepositoryMappingEngine`
   + `ContextBundlingEngine` → `deterministic_prescan` (Bandit /
   Semgrep / Gitleaks / OSV). If findings are non-empty, the scan
   pauses at `PENDING_PRESCAN_APPROVAL` (ADR-009) for operator review;
   Critical Gitleaks findings need an explicit override to continue.
4. After prescan approval, `estimate_cost` runs a token-counting dry
   run, persists `cost_details`, atomically flips status to
   `PENDING_COST_APPROVAL` (firing a `pg_notify` so SSE wakes
   immediately), then native `interrupt()` pauses the graph and
   checkpoints state.
5. User approves: API publishes to `analysis_approved_queue`; worker
   resumes the same thread with `Command(resume=payload)`.
6. Single-pass parallel analysis: `analyze_files_parallel` runs every
   relevant agent against every file from the `ORIGINAL_SUBMISSION`
   snapshot in parallel, bounded by a single
   `asyncio.Semaphore(CONCURRENT_LLM_LIMIT=5)` over the union of
   file × chunk × agent calls. Per-file agent triage is inline
   (extension-based routing); per-file dependency context is still
   injected from the repository map.
7. `correlate_findings` (group by file/CWE/line, merge agent
   corroborations) → `consolidate_and_patch` (REMEDIATE-only:
   merges per-file fixes via the merge agent, tree-sitter
   syntax-verifies, builds the `POST_REMEDIATION` snapshot) →
   `save_results` (splits findings into fresh / existing — fresh
   LLM-agent rows are inserted, existing prescan rows get correlation
   updates; applies to all scan types including REMEDIATE) →
   `save_final_report` (writes the CVSS-weighted 0–10 `risk_score` +
   the `summary` JSON, sets `COMPLETED` / `REMEDIATION_COMPLETED`)
   → END.
