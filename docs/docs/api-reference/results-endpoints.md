---
sidebar_position: 4
title: Results Endpoints
---

# Results Endpoints

All paths are under `/api/v1` and require a Bearer token. These
endpoints read the outputs of a completed (or in-progress) scan;
they never mutate scan state.

## Paginated scan history for the caller

```http
GET /scans/history?page=1&page_size=10&search=<term>&sort_order=desc&status=<All|In Progress|Completed|FAILED|...>
```

Used by the History page and the dashboard's "recent scans" tile.
Scoped by H.2 visibility.

## Scans for a specific project

```http
GET /projects/{project_id}/scans?skip=0&limit=10
```

## Full scan result (JSON)

```http
GET /scans/{scan_id}/result
```

Returns `AnalysisResultDetailResponse`: the parsed `summary_report`,
the per-file findings bundle, original / fixed code maps, and the
final scan `status`. New `SUGGEST` and `REMEDIATE` results also include the persisted `patch_plan`;
legacy and `AUDIT` results return `null`.

Use this for the Results page.

## Resume or restart a failed/cancelled scan

```http
POST /scans/{scan_id}/run-control
Content-Type: application/json

{ "mode": "resume" | "restart" }
```

Manually resume or restart an eligible failed (or cancelled-with-
durable-artifacts) scan. Both modes keep the same scan id and
the original submitted snapshot/config while preserving audit
history (`scan_events` and `llm_interactions`).

| Mode | Behaviour |
| ---- | --------- |
| `resume` | Keeps completed durable task rows; analysis and consolidation stages reuse matching completed work. |
| `restart` | Deletes `scan_tasks` and derived final findings but keeps audit history; reruns analysis from the original snapshot. |

* Pending-approval statuses are rejected (use existing approval
  endpoints).
* Authorization matches existing scan lifecycle mutation permissions.
* The endpoint atomically commits the status claim, lifecycle events, restart cleanup where
  applicable, and durable worker-queue intent, then returns `202` on success.

## Downloadable findings report

```http
GET /scans/{scan_id}/report?format=html|csv|pdf|sarif
```

Renders the scan's consolidated findings as a downloadable report and
streams it as a file attachment (`Content-Disposition`). `format`
defaults to `html`; an unsupported value returns `400`.

| `format` | Media type | Content |
| -------- | ---------- | ------- |
| `html` | `text/html` | A self-contained styled HTML document (inline CSS, no external assets). |
| `csv` | `text/csv` | One row per finding; columns for file, line, severity, CVSS, confidence, CWE, source, title, description, remediation, corroborating agents, affected lines. |
| `pdf` | `application/pdf` | A paginated, print-oriented PDF — cover page, running header/footer, a card per finding. Rendered with WeasyPrint. |
| `sarif` | `application/sarif+json` | SARIF 2.1.0 JSON suitable for GitHub code scanning upload; includes stable rules, rule indexes, repository-relative artifact URIs, locations / related locations, CWE/CVSS/source/triage metadata. |

Scoped by H.2 visibility — the same `404`-not-`403` rule applies.

## Download persisted patch plan

```http
GET /scans/{scan_id}/patch-plan?format=json|patch
```

Available when a completed scan has a persisted patch-plan artifact. `json` returns the versioned
artifact with exact resolved ranges, per-candidate requirements, validation evidence and
dispositions. `patch` returns the same artifact as a reviewable apply document containing the
persisted unified diff and adjacent requirements/commands/manual steps. Unsupported formats return
`400`; missing or unauthorized artifacts return `404`.

Consumers must treat `validation_checks[].status` literally: `not_run` is not success. Candidate
`is_applied` is authoritative; a passed `SUGGEST` candidate remains unapplied.

!!! note "SARIF export"

    SARIF is generated on demand from the same consolidated findings as
    HTML / CSV / PDF. SCCAP does not persist a separate SARIF blob or run
    a reporting graph node.

## Download native scanner JSON

```http
GET /scans/{scan_id}/scanner-reports
```

Downloads the validated native JSON captured from Bandit, Semgrep, Gitleaks, and OSV-Scanner during
the deterministic prescan. The response includes per-scanner status plus complete toolchain
provenance: runtime/config digests, exact Semgrep rule hashes, resolved source commits, and advisory
database status. Each execution appends an immutable scan-scoped artifact generation; the endpoint
returns the latest. Each scanner payload is capped at 5 MiB and oversized payloads are represented
by a truncation manifest. Scans created before this capability return `404` because no artifact
exists. `GET /scans/{scan_id}/result` exposes a bounded provenance summary without the per-rule
inventory for operator UI/report rendering.

## LLM interactions for a scan

```http
GET /scans/{scan_id}/llm-interactions
```

Returns every `llm_interactions` row tied to the scan: agent name,
prompt template, prompt context (JSONB), full raw response, parsed
output, cost, token counts, timestamp. Intended for debugging agent
drift; access follows the same owner/admin/group-peer and tenant scope
as the scan result.

## Findings debug (pipeline breakdown)

```http
GET /scans/{scan_id}/findings/debug
```

Returns findings from all three storage buckets (SAST, raw LLM,
consolidated) plus Sankey-flow nodes/links and grouped counts by
source, severity, and CWE. Used by the Pipeline & Logs diagnostics
page and the compact findings panel on the results page.
Access follows the same detail-read visibility policy as the result,
reports, lineage, and SSE stream.

## Delete

```http
DELETE /scans/{scan_id}                     # superuser only
DELETE /projects/{project_id}               # superuser only
```

Deletes the scan (or the project + all child scans) including every
finding, snapshot, and LLM-interaction row.

## Error shapes

The backend uses FastAPI's default problem-JSON shape:

```json
{ "detail": "Scan not found or not authorized." }
```

Authorization failures return `404` rather than `403` for scans the
user can't see — the existence of a scan shouldn't leak across the
scope boundary.
