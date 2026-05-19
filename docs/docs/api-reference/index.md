---
sidebar_position: 1
title: API Reference Overview
---

# API Reference

SCCAP exposes a FastAPI REST API under `/api/v1/*` plus an
MCP server at `/mcp`. Every REST endpoint is documented interactively
by FastAPI itself at `http://<host>/docs` (Swagger UI) and
`http://<host>/redoc` (ReDoc). The pages in this section are a
curated human-readable guide to the ones you're most likely to hit
first.

## Endpoint groups

| Group | Prefix | Router file | Guide |
| ----- | ------ | ----------- | ----- |
| Setup wizard | `/setup/*` | `setup.py` | N/A — setup.md in UI |
| Auth | `/auth/*` | `fastapi-users` + `refresh.py` | [Authentication](./authentication.md) |
| LLM configurations | `/admin/llm-configs` | `admin.py` / `llm_config.py` | [LLM Configuration](./llm-configuration.md) |
| Projects + scans | `/projects`, `/scans` | `projects.py` | [Code Analysis Endpoints](./code-analysis-endpoints.md) |
| Scan results | `/scans/{id}/result`, `/scans/{id}/report`, etc. | `projects.py` | [Results Endpoints](./results-endpoints.md) |
| Dashboard | `/dashboard/stats` | `dashboard.py` | see [User Guide → Dashboard](../user-guide/dashboard-overview.md) |
| Compliance | `/compliance/*` | `compliance.py` | see [Security Frameworks](../security-frameworks/supported-frameworks.md) |
| Search | `/search` | `search.py` | see [User Guide → Dashboard](../user-guide/dashboard-overview.md) |
| Chat | `/chat/sessions/*` | `chat.py` | see [User Guide → Advisor](../user-guide/chat-interfaces/guideline-provision.md) |
| Admin | `/admin/*` | many | superuser only |

## Authentication

All endpoints (except `/setup/*` during first-run) require a Bearer
token. See [Authentication](./authentication.md) for the login +
refresh flow.

## MCP (non-REST)

The MCP tool surface lives at `/mcp` and is **not** REST. It reuses
the same JWT auth with an `Authorization: Bearer <token>` header;
see [Architecture → Backend Services](../architecture/backend-services.md#mcp-server)
for the tool catalog + a Claude Code connection example.

## Correlation ids

Every API response carries an `X-Correlation-ID` header. Include the
same header on follow-up requests (retries, upload chunks, etc.) to
keep server-side logs stitched to the same operation — a huge help
when diagnosing issues via Grafana + Loki.
