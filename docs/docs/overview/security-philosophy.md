---
title: Security Philosophy
sidebar_position: 3
---

# Security Philosophy

SCCAP is built around one principle: **audit first, remediate
intelligently**. Every core design decision — the checkpointed, multi-gate scan
workflow, the encrypted secret store, the scoped visibility filter,
the checkpointed workflow — follows from applying that principle to
both the scanned code and the scanning platform itself.

## Audit before you spend

Large-model calls are expensive and non-deterministic. SCCAP uses up to three
durable human gates before expensive stages:

1. The API atomically commits the scan aggregate and a submission outbox intent. The outbox sweeper,
   not the request path, publishes to `code_submission_queue`.
2. The worker builds the repository map, classifies files, and runs deterministic scanners. If they
   find issues, `pending_prescan_approval` pauses for operator review.
3. `estimate_profiling_cost` prepares the utility-model estimate and `profiling_cost_gate` pauses
   before profiling.
4. Profiling feeds `estimate_cost`; `cost_gate` pauses before full reasoning-model analysis.
5. Every approval atomically records the gate decision and an outbox intent. The sweeper publishes
   it to `analysis_approved_queue`, and a worker resumes the **same** LangGraph thread with
   `Command(resume=payload)`.

Nothing expensive runs without an explicit human yes. Nothing is lost
if the worker restarts between the estimate and the approval.

## Trust but verify

SCCAP uses LLMs for **finding** vulnerabilities, not for **gating**
anything. Every LLM-driven decision is written into
`llm_interactions` (prompt context, parsed output, cost,
correlation id) so admins can replay every step via the Admin → Logs
viewer. Structured outputs go through Pydantic AI, which validates the
response against a typed model and retries on malformed JSON instead
of silently falling back to regex parsing.

## Scoped visibility by default

A regular user sees their own scans plus scans owned by users in an allowed **User Group**. A caller
with tenant-wide permission may remove that ownership/group filter, but still remains inside the
active tenant; no role bypasses the tenant predicate or forced PostgreSQL RLS. The shared visibility
helper and repository paths enforce this scope consistently.

## Encrypted secrets

Every LLM API key and SMTP password is **Fernet-encrypted at rest**
with the installation's `ENCRYPTION_KEY`. The key never leaves the
container; neither the UI nor the logs ever surface a decrypted
secret.

- `llm_configurations.encrypted_api_key` — the provider credential
  admins enter in the `/admin/llm` settings page.
- `system_config` rows with `is_secret: true` — currently holds the
  SMTP password.

`.env.example` deliberately does **not** include `OPENAI_API_KEY` /
`GOOGLE_API_KEY` placeholders (H.0.2) — all provider credentials live
in the database, not on the filesystem.

## Correlated observability

Every request entering the API gets an `X-Correlation-ID`
(`correlation_id_middleware` in `main.py`). The ID is propagated via a
`ContextVar` and attached to every log entry, every LLM interaction
row, and every worker message so a single scan can be followed across
services in Grafana + Loki without grep-archaeology.

## Safe automation

The `DynamicCORSMiddleware` tightens once setup completes: before the
first superuser finishes `/setup`, it allows all origins (so the UI
can reach the API wherever the operator hosts it); after setup, it
only allows origins from the `security.allowed_origins` system_config
row plus `ALLOWED_ORIGINS` env. MCP tools reuse this same middleware
plus the same JWT auth — there's no separate "agent" auth surface to
misconfigure.
