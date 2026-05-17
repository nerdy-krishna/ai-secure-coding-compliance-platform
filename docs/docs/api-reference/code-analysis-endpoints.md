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

## Apply fixes

```http
POST /scans/{scan_id}/apply-fixes
{ "finding_ids": [101, 102, 103] }
```

Starts an incremental remediation run. The worker applies each fix
in order; a merge agent resolves conflicts when multiple fixes touch
the same file. Status lands at `REMEDIATION_COMPLETED` on success.

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
