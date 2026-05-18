---
sidebar_position: 3
title: Code Analysis Endpoints
---

# Code Analysis Endpoints

All paths are under `/api/v1`. Every endpoint here requires a Bearer
token and respects the H.2 scope filter — regular users only see
their own scans + scans from peers they share a User Group with;
admins see everything.

## Projects

### List projects

```http
GET /projects?skip=0&limit=100&search=<term>
```

Paginated; response items carry a `stats` rollup (risk score,
severity buckets, fixes-ready count) derived from the latest terminal
scan per project.

### Create a project

```http
POST /projects
{ "name": "payments-api" }
```

Creates an empty project — typically not needed; the first scan
submission auto-creates its project by name.

### Project name autocomplete

```http
GET /projects/search?q=<term>
```

Returns a list of project names visible to the caller. Used by the
TopNav search combobox.

## Submit a scan

```http
POST /scans
Content-Type: multipart/form-data
```

Required form fields:

| Field | Description |
| ----- | ----------- |
| `project_name` | Creates the project on first use; reuses it on subsequent submissions. |
| `scan_type` | `AUDIT` (read-only), `SUGGEST` (findings + inline suggested fixes), or `REMEDIATE` (applies fixes + builds a patched snapshot). |
| `frameworks` | Comma-separated framework names (e.g. `asvs,proactive_controls`). |
| `reasoning_llm_config_id` | UUID of the registered `LLMConfiguration` for the **reasoning** slot (analysis, consolidation, merge). Falls back to the first registered config when omitted. |
| `utility_llm_config_id` | UUID for the **utility** slot (per-file profiler, fix verification). Falls back to the reasoning slot's config when omitted — "the same model in both slots" is the baseline. |
| `secondary_reasoning_llm_config_id` | *Optional.* UUID of a **second** reasoning LLM. When set, every analysis agent runs on both this config and `reasoning_llm_config_id` and the findings union (PRD #91). Rejected with `400` if it is not a registered config. Null ⇒ single-LLM analysis. |
| `temperature_profiler` / `temperature_analysis` / `temperature_consolidation` / `temperature_merge` | *Optional* per-stage LLM temperature, `0.0`–`1.0`, default `0.2`. |
| `temperature_analysis_secondary` | *Optional* analysis temperature for the second reasoning LLM, `0.0`–`1.0`, default `0.2`. Used only when `secondary_reasoning_llm_config_id` is set. |
| `disable_temperature` | *Optional* boolean, default `false`. When `true`, no temperature is sent on any LLM call — each model runs at its provider default and the per-stage temperatures are ignored. |
| `cross_file_validation` | *Optional* boolean, default `false`. Opt in to cross-file finding validation. |

Exactly one submission method:

- `files`: multipart file uploads.
- `repo_url`: a public Git URL. Use `POST /scans/preview-git` first
  to confirm the repo is readable.
- `archive_file`: `.zip` or `.tar.gz`. Use `POST /scans/preview-archive`
  first to list contents.

Optional: `selected_files` is a comma-separated list of paths —
submitted files outside this list are excluded from the scan.

Response: `{ scan_id, project_id, message }`. The scan enters the
`QUEUED` state; poll status via SSE or `GET /scans/{id}`.

## Approve / cancel an interrupt gate

```http
POST /scans/{scan_id}/approve        # resume the scan past its current gate
POST /scans/{scan_id}/cancel         # flip to CANCELLED
```

A scan can pause at three native-`interrupt()` gates. The `approve`
body's `kind` field discriminates which one is being resumed; the
service validates `kind` against the scan's current status:

| `kind` | Gate status | Body |
| ------ | ----------- | ---- |
| `prescan_approval` | `PENDING_PRESCAN_APPROVAL` | `{ "kind", "approved", "override_critical_secret" }` |
| `profiling_approval` | `PENDING_PROFILING_APPROVAL` | `{ "kind", "approved" }` |
| `cost_approval` | `PENDING_COST_APPROVAL` | `{ "kind", "approved" }` (empty body also accepted, defaults to `cost_approval` + approved) |

`approved=false` at the prescan or profiling gate ends the scan at
`BLOCKED_USER_DECLINE`. Approve publishes to `analysis_approved_queue`;
the worker resumes the paused LangGraph thread with
`Command(resume=...)`. Scans left at the prescan or profiling gate
for over 24 h are auto-declined by a background sweeper.

## Stream scan progress (SSE)

```http
GET /scans/{scan_id}/stream
```

Server-Sent Events. Emits a `scan_state` event on every status
transition, a `scan_event` for each new `ScanEvent` row, and a
terminal `done` event when the scan reaches a final state. The
client reconnects via EventSource's native retry.

Because browsers can't set arbitrary headers on an `EventSource`,
the endpoint reads the access token from the `token` query param via
`current_active_user_sse`.

## Applying fixes

There is no separate apply-fixes endpoint. To have fixes applied to
the code, submit the scan with `scan_type=REMEDIATE` — the worker
graph then merges the per-finding fixes, syntax-verifies them with
tree-sitter, and writes a patched `POST_REMEDIATION` snapshot. A
`SUGGEST` scan is advisory: it shows the suggested fix inline but does
not mutate code.

## Preview endpoints

```http
POST /scans/preview-archive
Content-Type: multipart/form-data
```

Returns `{ "files": [<path>, ...] }` — list the contents of an
archive before uploading it for scan, so users can populate the
Submit page's selective-files tree.

```http
POST /scans/preview-git
{ "repo_url": "https://github.com/…" }
```

Clones the repo into a temp dir, returns a file list, discards the
clone. Rejects repos that yield zero analyzable files.
