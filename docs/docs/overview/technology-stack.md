---
title: Technology Stack
sidebar_position: 2
---

# Technology Stack

## Backend

- **Python 3.12 + FastAPI** with [Poetry](https://python-poetry.org/)
  for dependency management. Async everywhere (`async def` routes,
  SQLAlchemy async, `asyncpg`).
- **SQLAlchemy 2.x** with declarative `Mapped[]` models and
  **Alembic** for migrations. `prepend_sys_path = src` in
  `alembic.ini` so `env.py` imports live models directly.
- **fastapi-users** for auth with a JWT Bearer transport; a custom
  `/api/v1/auth/refresh` endpoint supplements what fastapi-users
  ships.
- **LangGraph 1.x + LangChain 1.x** for the multi-agent workflow.
  Scan approval is a native `interrupt()` / `Command(resume=...)`
  refactor (I.1) with a Postgres-backed checkpointer keyed on
  `scan_id`.
- **LiteLLM** as the source of truth for token counting and cost
  estimation (I.2). `LITELLM_LOCAL_MODEL_COST_MAP=True` keeps it
  offline; per-`LLMConfiguration` overrides stay for bespoke
  endpoints.
- **Pydantic AI** (I.3) wraps `llm_client.generate_structured_output`
  to enforce per-call validation retries on structured responses.
- **FastMCP** (I.4) mounts the scan + advisor tool surface at `/mcp`,
  reusing the same JWT auth.

## Worker

A separate container consumes RabbitMQ via the blocking
[`pika`](https://pika.readthedocs.io/) client and runs the compiled
LangGraph workflow with an `AsyncPostgresSaver` checkpointer. Queues:
`code_submission_queue`, `analysis_approved_queue` (names live in
`src/app/config/config.py`).

## Pentesting tooling (opt-in)

The separately gated pentest engine does **not** use the RabbitMQ spine at all —
PostgreSQL is its only coordination point (ADR-029):

- **One container** — `pentest-engine` (Dockerfile target `worker-pentest-local`)
  runs `python -m app.pentest.engine`, polls `pentest_runs` for queued work, and
  executes one run at a time in-process.
- **Scanners in the image** — nmap, nuclei (full community template library), OWASP
  ZAP, sqlmap, ffuf, hydra, whatweb, gobuster, hashcat and Playwright Chromium, with
  wordlists under `src/app/pentest/data/`. Startup verifies each binary and reports
  availability to the UI.
- **Networks** — `scpnetwork` for the API, database and model providers;
  `pentest-egress` for target traffic.
- **State** — `pentest_runs`, `pentest_run_events`, `pentest_findings` (with
  `category` = `vulnerability` | `observation`) and `pentest_leads`.
- **Live view** — the run page polls the event stream, the findings and the lead
  ledger, and receives the browser frame the engine pushes from Playwright.

## Data + infra

- **PostgreSQL 16** — primary store for users, scans, findings,
  chat, RAG metadata, system_config, and the `scan_outbox`
  transactional-outbox table that guarantees RabbitMQ publication
  survives a crash between commit and publish.
- **RabbitMQ** — message broker between API and worker.
- **Qdrant** — vector store for RAG (replaced ChromaDB per ADR-003).
  Embedding via `fastembed.TextEmbedding("sentence-transformers/all-MiniLM-L6-v2")`
  in `infrastructure/rag/embedder.py`; vectors are byte-equivalent
  to the prior chromadb-bundled ONNX so existing collections stay
  valid. Callers go through the `VectorStore` Protocol so the store
  is swappable without touching call sites.
- **Fluentd → Loki → Grafana** — log aggregation. Every request
  carries an `X-Correlation-ID` propagated via `correlation_id_var`
  so logs stitch across services.
- **Let's Encrypt / certbot** — optional HTTPS, wired into
  `setup.sh` when the user opts in.

## Frontend (`secure-code-ui/`)

- **React 18 + Vite + TypeScript** with a feature-sliced layout:
  `app/` (providers + routes), `pages/` (route views), `features/`
  (feature-scoped components), `widgets/` (layouts), `shared/api/`
  (one service module per backend domain — all traffic goes through
  `apiClient.ts`).
- **Custom SCCAP UI primitives and CSS**; Ant Design is not installed.
- **TanStack Query** for server-state caching.
- **React Router v7** with centralized authentication/role and feature guards in `App.tsx`
  (`auth`, `unauth`, `superuser`, `root-redirect`). Every guard
  redirects to `/setup` when `isSetupCompleted === false`.

## Verification + tooling

- The inherited executable test suites were removed on 2026-08-22.
  Replacement tests are added at reproduced production seams; see the
  [Verification Strategy](../development/testing-strategy.md).
- **ruff + black + mypy** for Python lint/format/type-check.
- **ESLint + tsc** for the frontend.
- **No CI service is configured.** Run `ruff check src`, `pytest`,
  `npm --prefix secure-code-ui run lint` and `npm --prefix secure-code-ui run build`
  locally or on the installation host; the same commands are listed in `AGENTS.md`.
  (The repository previously used GitHub Actions; the workflows and the Dependabot /
  Renovate configs were removed so nothing opens pull requests or runs on push.)
