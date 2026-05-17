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
final scan `status`.

Use this for the Results page.

## Downloadable findings report

```http
GET /scans/{scan_id}/report?format=html|csv|pdf
```

Renders the scan's consolidated findings as a downloadable report and
streams it as a file attachment (`Content-Disposition`). `format`
defaults to `html`; an unsupported value returns `400`.

| `format` | Media type | Content |
| -------- | ---------- | ------- |
| `html` | `text/html` | A self-contained styled HTML document (inline CSS, no external assets). |
| `csv` | `text/csv` | One row per finding; columns for file, line, severity, CVSS, confidence, CWE, source, title, description, remediation, corroborating agents, affected lines. |
| `pdf` | `application/pdf` | A paginated, print-oriented PDF — cover page, running header/footer, a card per finding. Rendered with WeasyPrint. |

Scoped by H.2 visibility — the same `404`-not-`403` rule applies.

!!! note "SARIF export"

    SCCAP previously exposed `/scans/{id}/sarif` and an
    `/executive-summary/download` endpoint; both were removed in the
    2026-04-26 cleanup (the impact-reporting node that backed them was
    never wired into the graph). The HTML / CSV / PDF report above is
    the replacement. SARIF export is not currently offered.

## LLM interactions for a scan

```http
GET /scans/{scan_id}/llm-interactions
```

Returns every `llm_interactions` row tied to the scan: agent name,
prompt template, prompt context (JSONB), full raw response, parsed
output, cost, token counts, timestamp. Intended for admins debugging
agent drift — regular users only see interactions for their own
scans.

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
