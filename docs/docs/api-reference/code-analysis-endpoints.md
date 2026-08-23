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
| `reasoning_llm_config_id` | UUID of the registered `LLMConfiguration` for the **reasoning** slot (analysis and consolidation). Falls back to the first registered config when omitted. |
| `utility_llm_config_id` | UUID for the **utility** slot (per-file profiler). Falls back to the reasoning slot's config when omitted — "the same model in both slots" is the baseline. |
| `secondary_reasoning_llm_config_id` | *Optional.* UUID of a **second** reasoning LLM. When set, every analysis agent runs on both this config and `reasoning_llm_config_id` and the findings union (PRD #91). Rejected with `400` if it is not a registered config. Null ⇒ single-LLM analysis. |
| `temperature_profiler` / `temperature_analysis` / `temperature_consolidation` | *Optional* per-stage LLM temperature, `0.0`–`1.0`, default `0.2`. |
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

A scan can pause at three native-`interrupt()` gates. Read
`active_approval_gate` from `GET /scans/{scan_id}/result` or the `scan_state`
SSE projection, then echo its identity in the decision. Supply a stable,
caller-generated `X-Idempotency-Key` header (maximum 128 characters):

| `kind` | Gate status | Body |
| ------ | ----------- | ---- |
| `prescan_approval` | `PENDING_PRESCAN_APPROVAL` | `{ "gate_id", "gate_version", "evidence_hash", "kind", "approved", "override_critical_secret" }` |
| `profiling_approval` | `PENDING_PROFILING_APPROVAL` | `{ "gate_id", "gate_version", "evidence_hash", "kind", "approved" }` |
| `cost_approval` | `PENDING_COST_APPROVAL` | `{ "gate_id", "gate_version", "evidence_hash", "kind", "approved" }` |

`approved=false` at the prescan or profiling gate ends the scan at
`BLOCKED_USER_DECLINE`. An accepted decision atomically records the transitional status, audit
events, and durable `analysis_approved_queue` outbox intent. The API does not publish inline;
the worker eventually resumes the paused LangGraph thread with
`Command(resume=...)`. Scans left at the prescan or profiling gate
for over 24 h are auto-declined by a background sweeper.

The response includes the recorded gate. Repeating the same decision with the same idempotency key
returns `202` and that original gate without creating another resume intent. A different or stale
decision for an already-decided gate returns `409`. Compatibility clients may omit identity only
while exactly one matching pending gate exists; new clients should always bind all three identity
fields. Profiling and full-analysis gates have different IDs, sequences, labels, purposes, and
evidence hashes.

## Stream scan progress (SSE)

```http
GET /scans/{scan_id}/stream
```

Server-Sent Events. Emits a `scan_state` event on every status
transition, a `scan_event` for each new `ScanEvent` row, and a
terminal `done` event when the scan reaches a final state. The
client reconnects via EventSource's native retry.

When `scan_state.status` enters `PENDING_PROFILING_APPROVAL` or
`PENDING_COST_APPROVAL`, its allow-listed `cost_details` includes the expected
and conservative upper-bound costs/tokens/request counts, confidence, sample
count, assumptions, rendered-envelope components, and per-model slots. This is
the same persisted contract returned by the scan result endpoint; the UI does
not need to wait for a polling refresh to render the approval card.

Because browsers can't set arbitrary headers on an `EventSource`,
the endpoint reads the access token from the `token` query param via
`current_active_user_sse`.

## Applying fixes

There is no separate apply-fixes endpoint. To have fixes applied to
the code, submit the scan with `scan_type=REMEDIATE` — the worker
graph then resolves candidates against exact source ranges, rejects
ambiguity and overlap for manual review, atomically applies disjoint
edits, syntax-verifies each whole file, and writes a patched
`POST_REMEDIATION` snapshot. A `SUGGEST` scan persists the same advisory
plan but does not mutate code.

### Download the patch plan

```http
GET /scans/{scan_id}/patch-plan
```

Returns the latest authorized version-2 `patch_plan` artifact as a JSON
attachment for SUGGEST or REMEDIATE scans. It contains source hashes,
resolved ranges, unified diffs, stable hunk IDs, candidate-to-hunk lineage,
requirements, explicit validation outcomes, and rejected/manual-review decisions. Returns `404`
when no patch plan was produced.

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
