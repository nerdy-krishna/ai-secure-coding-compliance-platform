---
title: Backend Services
sidebar_position: 3
---

# Backend Services

The backend is a FastAPI monolith with a clean three-layer separation:
**routers → services → repositories**. Routers handle HTTP concerns
(auth, serialization, status codes); services orchestrate business
logic; repositories own SQL.

## Router map

All routers are prefixed with `/api/v1` and live under
`src/app/api/v1/routers/`. Wired up in `main.py`.

### Public (authenticated user)

| Router | Responsibilities |
| ------ | ---------------- |
| `setup.py` | First-run wizard (`/setup/*`). Gates the app via `SystemConfigCache.is_setup_completed()`. |
| `refresh.py` | Custom `/auth/refresh` endpoint (fastapi-users doesn't ship one for the Bearer transport). |
| `projects.py` | Project + scan CRUD, scan submission, cost approval / cancel, SSE status stream, PDF summary, SARIF download. |
| `chat.py` | Chat sessions + messages + live context rail (`/chat/sessions/{id}/context`). |
| `compliance.py` | Per-framework posture stats + RAG control listing for the Compliance page. |
| `dashboard.py` | `/dashboard/stats` — risk score, severity bar, trend, spend. |
| `search.py` | `/search?q=...` — grouped hits across projects / scans / findings. |

### Admin-only (superuser)

| Router | Responsibilities |
| ------ | ---------------- |
| `admin_config.py` | Arbitrary key/value `system_config` rows + metadata endpoints. |
| `admin_users.py` | User list / create / invite / activate. |
| `admin_groups.py` | User Groups CRUD + member add/remove (H.2). |
| `admin_frameworks.py` | Framework CRUD + agent mappings. |
| `admin_agents.py` | Agent definitions. |
| `admin_prompts.py` | Prompt templates used by agents. |
| `admin_rag.py` | RAG ingestion jobs (CSV upload + git URL). |
| `admin_seed.py` | "Restore defaults" — re-seed the 3 baseline frameworks + agents. |
| `admin_logs.py` | LLM interaction viewer (scan-scoped log replay). |
| `admin.py` / `llm_config.py` | LLM configuration CRUD (encrypted API keys). |

## Service layer

Services live under `src/app/core/services/`. They are the only code
that spans multiple repositories in a single operation:

- `scan_service.SubmissionService` — the big one. Owns scan
  submission, cost estimation lookups, paginated list
  queries that forward `visible_user_ids` into `scan_repo`.
- `chat_service.ChatService` — chat sessions, message history,
  context-rail aggregation.
- `admin_service.AdminService` — thin wrapper over admin CRUD when
  the operation needs multiple repositories together.
- `compliance_service.ComplianceService` — reads `rag_service` stats
  + joins to `findings` for per-framework posture.
- `dashboard_service.DashboardService` — one round-trip per metric
  against scans + findings + llm_interactions.
- `search_service.SearchService` — three parallel ILIKE queries over
  projects / scans / findings, scoped through `visible_user_ids`.
- `rag_preprocessor_service` / `security_standards_service` — ingest
  pipelines for framework knowledge bases.
- `default_seed_service` — idempotent seed of the eight bundled
  frameworks + their agents + prompt templates.

## Repositories

One repository per aggregate under
`src/app/infrastructure/database/repositories/`:

`scan_repo`, `scan_outbox_repo`, `chat_repo`, `user_repo`,
`framework_repo`, `agent_repo`, `prompt_template_repo`,
`llm_config_repo`, `rag_job_repo`, `system_config_repo`,
`user_group_repo`.

Repositories are intentionally small and focused on one root. The
`user_group_repo.get_peer_user_ids(user_id)` is a good example: a
single `SELECT DISTINCT` self-join on memberships that powers the
scope filter on every list endpoint.

## Auth

`fastapi-users` with `BearerTransport`. Tokens are JWTs signed with
`SECRET_KEY`. The custom `/auth/refresh` accepts a refresh token and
returns a new access token. Routes that need superuser access use the
`current_superuser` dependency; regular authenticated routes use
`current_active_user`; SSE streams use `current_active_user_sse`
(reads the token from a query param since browsers can't set headers
on `EventSource`).

## Scan-scope filter

The H.2 visibility filter threads through every list endpoint:

1. `get_visible_user_ids` dependency
   (`src/app/api/v1/dependencies.py`) asks `scan_scope.visible_user_ids(user, repo)`
   for the caller — returns `None` for admins, `[user.id, ...peers]`
   for regular users.
2. Routers pass that list through to service methods, which forward
   it to `scan_repo.get_paginated_*` and friends.
3. `ScanRepository._scope_column(col, user_id, visible_user_ids)`
   translates it into a SQLAlchemy predicate (`sa.true()` for admin,
   `col.in_(ids)` otherwise).

Any new endpoint that lists user-owned data just needs to take
`visible_user_ids = Depends(get_visible_user_ids)` and pass it
through; the repositories already honor it.

## Transactional outbox

The `scan_outbox` table is the only way scan jobs reach RabbitMQ.
`scan_service` inserts an outbox row in the **same transaction** as
the scan row; an in-process sweeper
(`src/app/infrastructure/messaging/outbox_sweeper.py`) reads
unpublished rows and actually publishes them with an exponential
backoff on `attempts`. This guarantees the worker always sees every
scan even if RabbitMQ was down when the API committed.

## MCP server

FastMCP is mounted on the same FastAPI app under `/mcp` via
`src/app/api/mcp/server.py`. It reuses the regular JWT Bearer auth
through a custom `TokenVerifier` that wraps
`CustomCookieJWTStrategy`, so MCP clients authenticate with an
ordinary user JWT:

```
Authorization: Bearer <token>
```

Current tool surface: `sccap_submit_scan`, `sccap_get_scan_status`,
`sccap_get_scan_result`, `sccap_approve_scan`,
`sccap_ask_advisor`. Each tool calls straight into the existing
service layer (no extra duplicated logic). Admin surfaces
(user management, framework ingestion) stay REST-only — those are
human workflows, not agentic.

Rate limiting is shared with UI calls via the existing per-user
bucket. See `.agent/mcp.md` for the connection-side instructions for
a Claude Code client.

## Observability

Every request flows through `correlation_id_middleware` which:

1. Reads `X-Correlation-ID` if the caller sent one, otherwise
   generates a new UUID.
2. Stores it in `correlation_id_var` (a `ContextVar`).
3. Attaches it to every log record via the logging filter in
   `src/app/config/logging_config.py`.

The same id travels in the RabbitMQ message envelope so worker logs
for a given scan are easy to stitch together in Grafana + Loki.
