---
title: Platform Features
sidebar_position: 1
---

# Platform Features

The SCCAP UI is organized into focused pages; the Admin console is only
visible to superusers. Every surface that lists scans, projects, or
findings is scoped through the H.2 visibility filter — regular users
see their own data plus any peer they share a **User Group** with;
admins see everything.

## Dashboard

- **Risk ring** — weighted-findings score (100 − clamp(weighted, 95),
  floor 5). Same heuristic server-side for the Dashboard, Compliance
  page, and Projects cards so numbers are consistent across surfaces.
- **Severity breakdown** — stacked bar and legend across critical /
  high / medium / low / informational.
- **14-day scan trend** — inline sparkline pulled from
  `/api/v1/dashboard/stats`.
- **Fixes-ready counter** — findings with an AI-suggested fix that
  hasn't been applied yet.
- **Monthly spend** — sum of `llm_interactions.cost` for the current
  month, constrained to the visibility scope.
- **Admin snapshot** — superusers get a platform-wide variant with
  deep links to the Groups and Users admin pages.

## Submit

- File upload, Git repository URL, or archive (`.zip` / `.tar.gz`).
- Selective-files tree that lets you prune before cost estimation.
- Two LLM slots per scan — a **utility** (cheap) model for the
  per-file profiler and fix verification, and a **reasoning**
  (capable) model for analysis and consolidation. Put the same model
  in both, or split them.
- Optional **second reasoning LLM** — every analysis agent runs on
  both models and the findings union, so what one model misses the
  other may catch; each finding records which model(s) detected it.
- Per-stage temperature tunable at submit time, or disable temperature
  entirely so each model uses its provider default.
- Framework multi-select (8 bundled OWASP frameworks plus any
  admin-added custom framework).

Before the deep analysis, every file is profiled on the utility model
(see [Data Flow](../architecture/data-flow.md)). The deep analysis
then runs as a single parallel pass, but each file is analysed only by
the agents its profile routed to — not the whole roster — bounded by
`CONCURRENT_LLM_LIMIT=5`. Per-file dependency context is injected from
the repository map so agents have visibility into imports.

## Results

- Per-file finding panels: severity, CVSS score, suggested fix, and —
  for a consolidated finding — every affected location and the agents
  that corroborated it.
- **Download report** buttons export the scan's findings as a
  self-contained HTML page, a CSV (one row per finding), or a
  paginated PDF.
- Timeline and LLM-logs drill-downs for the full scan trail.

## Projects

- Grid of projects owned by any user in the caller's visibility set.
- Per-card rollup served by `/api/v1/projects`: risk score, five-bucket
  severity bar, fixes-ready count, derived from the latest terminal
  scan.
- Card click opens the Results page for that scan.

## Compliance

- Per-framework card for the 8 bundled OWASP frameworks plus every
  custom framework in the `frameworks` table.
- Posture score + RAG document count + matched / open finding
  counts.
- Admins can deep-link to `/admin/rag` from the card to ingest the
  knowledge base for uninstalled defaults.

## Advisor

- Framework-scoped chat sessions, one LLM config per session.
- Live context rail populated from
  `/api/v1/chat/sessions/{id}/context`: knowledge sources (the
  session's frameworks), referenced findings (from the linked project's
  latest terminal scan, severity-ordered), and referenced files.
- Quick-reply chips for common prompts (finding explanation, framework
  mapping, scan summary).

## Admin console

All admin routes are superuser-gated server-side and hidden behind the
TopNav "Admin" item + an in-page `AdminSubNav` strip:

- **Platform** — system config (log level, LLM optimization mode, CORS
  settings, arbitrary key/values).
- **Users** — list, create, invite, flip is_active / is_superuser /
  is_verified.
- **Groups** (H.2) — create groups, add/remove members by email,
  drives the scan-scope filter.
- **Agents** — CRUD agent definitions used by `framework` mappings.
- **Frameworks** — CRUD frameworks + inline CSV or Git URL RAG
  ingestion.
- **Prompts** — CRUD prompt templates consumed by agents.
- **SMTP** — outbound mail config for password resets.
- **LLM configs** — encrypted provider credentials + per-config cost
  overrides.

## MCP server

FastMCP-mounted at `/mcp`, reusing the same JWT auth as the REST API.
Current tool surface:

| Tool | Backs |
|---|---|
| `sccap_submit_scan` | `scan_service.create_scan_from_*` |
| `sccap_get_scan_status` | `GET /scans/{id}` |
| `sccap_get_scan_result` | `GET /scans/{id}/result` |
| `sccap_approve_scan` | resumes the LangGraph thread with `Command(resume=...)` |
| `sccap_ask_advisor` | single-shot chat through `chat_service`, skips session persistence |

External agentic clients (Claude Code, Cursor, etc.) authenticate with
an ordinary user JWT; all visibility-scope rules apply.
