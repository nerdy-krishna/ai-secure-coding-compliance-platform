---
sidebar_position: 9
title: FAQ
---

# Frequently Asked Questions

## Setup + accounts

### Why did my first account become superuser?

SCCAP uses a single-instance bootstrap model: the first registered
user gets the superuser flag + is routed through `/setup` to finish
configuring LLMs, SMTP, and system settings before anyone else can
register. This avoids the chicken-and-egg problem of needing an
admin to exist before the instance is usable. If you registered as
the first user by accident, delete the user row (after creating a
new admin) to revoke the flag, or have another admin flip your
`is_superuser` via **Admin → Users**.

### How do I disable registration after setup?

Flip `auth.allow_registration` to `false` under
**Admin → Platform → System config**. Existing accounts can still
log in; new ones must be created by an admin.

## Visibility + user groups

### How does the scope filter work?

Every list endpoint (projects, scans, findings, compliance,
dashboard, search) takes a `visible_user_ids` parameter computed
from the caller:

- **Admins** → `None` → no filter (they see everything).
- **Regular users** → `[user.id, ...peers]` where peers come from
  the users they share a group with via `user_group_memberships`.

The helper is `scan_scope.visible_user_ids(user, repo)` in
`src/app/shared/lib/scan_scope.py`.

### Can two users see each other's scans without being in a group?

Only if one of them is a superuser. Otherwise, no — add them to a
group under **Admin → Groups**.

## Cost + LLMs

### Why does the scan pause at "Pending cost approval"?

That's the **audit-first** gate. The worker runs a cheap audit
pass first to build a repo map + dependency graph, tokenizes every
prompt that would run in the deep analysis, and prices it via
LiteLLM. The LangGraph workflow pauses with a native `interrupt()`
until you approve the estimate in the UI. Nothing expensive runs
without a human yes.

### Where are LLM API keys stored?

In the `llm_configurations` table, **Fernet-encrypted at rest**
using the installation's `ENCRYPTION_KEY`. They're never in
`.env` (H.0.2 removed the placeholders) and never surface
decrypted in logs or the UI.

### How do I rotate `ENCRYPTION_KEY`?

Generate a new key, update `.env`, restart the stack, and re-enter
every LLM API key + SMTP password via the Admin UI. The old
encrypted values won't decrypt against the new key, which is the
desired outcome. See
[Architecture → LLM Integration](./architecture/llm-integration.md#key-rotation).

### What does `LITELLM_LOCAL_MODEL_COST_MAP` do?

Pins LiteLLM to its bundled `model_prices_and_context_window.json`
instead of fetching it from the network at runtime. Recommended for
deployments where runtime outbound traffic is restricted. The map
is refreshed whenever we bump the `litellm` pin.

## RAG + frameworks

### How does the bundled ONNX embedder work offline?

`infrastructure/rag/embedder.py` wraps
`fastembed.TextEmbedding("sentence-transformers/all-MiniLM-L6-v2")`.
On the first embed call after a fresh deploy, fastembed downloads
the ONNX weights to its cache directory. Subsequent starts hit the
cache, so the second+ boot works offline. Vectors are byte-equivalent
to the prior chromadb-bundled embedder we used before ADR-008, so
existing Qdrant collections remain valid across the migration.

### Why are my scans tagged with a framework that has no docs?

Because framework tagging and RAG ingestion are decoupled. A scan
can be tagged with a framework that has zero ingested documents —
the tag drives Compliance-page aggregation but the chat agent
won't have context for it. The Compliance page flags frameworks in
this state with a "Not configured" chip.

## UI

### The Dashboard role toggle doesn't give me admin access

It's cosmetic only. The Tweaks panel lets designers preview the
Admin snapshot variant without actually needing a superuser account.
Every `/admin/*` route guard still requires `user.is_superuser`
server-side.

### What happened to the "Enterprise" role?

H.3 collapsed the three-role preview (`dev` / `enterprise` /
`admin`) down to two (`user` / `admin`). Legacy localStorage
values are migrated to `user` on read, so nothing breaks for
existing sessions.

## MCP

### How do I authenticate to the MCP server?

With an ordinary user JWT, via `Authorization: Bearer <token>`.
The MCP mount at `/mcp` uses the same `TokenVerifier` as the REST
API. Expired tokens return 401 and can be refreshed via the regular
`/auth/refresh` endpoint. See
[Architecture → Backend Services](./architecture/backend-services.md#mcp-server)
for a Claude Code connection example.

### Which admin operations are exposed over MCP?

None. The v1 MCP surface covers scan + advisor (submit, approve,
status, result, ask-advisor). Admin surfaces
(user management, framework ingestion) stay REST-only — those are
human workflows where agentic automation is a bad fit.

## Troubleshooting

### Alembic fails to connect to the database

Check `ALEMBIC_DATABASE_URL` in `.env`. `alembic/env.py` drives
migrations through `create_async_engine()`, so the URL must use
`postgresql+asyncpg://…` (the async driver from `psycopg[binary]`).
Even though Alembic's own CLI is sync, the engine inside `env.py`
is async, so a `postgresql://` or sync-driver URL will fail at
connect time.

### My scan SSE stream returns 401

Browsers can't set arbitrary headers on `EventSource`. The
`/scans/{id}/stream` endpoint reads the access token from a
`token` query param via the `current_active_user_sse` dependency.
Pass `?token=<jwt>` when opening the EventSource.

### RabbitMQ is up but scans sit in QUEUED forever

Check the outbox sweeper logs:
`docker compose logs app | grep -i outbox`. If the sweeper is
idle, the `scan_outbox` rows may be stuck in a retry backoff —
check the `attempts` column on the row.
