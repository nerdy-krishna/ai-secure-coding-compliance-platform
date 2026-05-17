---
sidebar_position: 4
title: Reporting
---

# Reporting

Every completed scan produces structured outputs you can read in
the UI and download as a report.

## Findings + summary (UI)

The [Results page](./code-analysis/understanding-results.md) is the
canonical view. It shows:

- Header: scan ID, project, status, created / completed timestamps,
  per-scan cost (sum of `llm_interactions.cost`).
- Summary strip: total findings grouped by severity + a CVSS-weighted
  0–10 risk score.
- Per-file panels: every analyzed file gets a collapsible section
  with its consolidated findings. Each finding shows its severity,
  CVSS score, the corroborating agents, the suggested fix (when the
  agent produced one), external references, and — for a finding
  merged from several sites — an *also affects* strip listing every
  affected location. A CWE id is shown only for findings emitted by
  the deterministic SAST scanners; LLM-agent findings carry no CWE.

## Downloadable report (HTML / CSV / PDF)

The Results header has **HTML**, **CSV**, and **PDF** download
buttons. Each renders the scan's consolidated findings through a
dedicated format-native generator:

- **HTML** — a single self-contained document (inline CSS, no
  external assets) that opens in any browser.
- **CSV** — one row per finding, columns for file, line, severity,
  CVSS, source, title, description, remediation, corroborating
  agents, and affected lines. Drop it straight into a spreadsheet.
- **PDF** — a paginated, print-oriented document with a cover page,
  running headers/footers, and a card per finding.

All three are served on demand by
`GET /api/v1/scans/{scan_id}/report?format=html|csv|pdf` — see
[API → Results Endpoints](../api-reference/results-endpoints.md).

## Raw findings (JSON)

For custom integrations, call
`GET /api/v1/scans/{scan_id}/result`. Response includes the full
`summary_report`, per-file findings bundle, cost details, and every
`ScanEvent` emitted during the run. See
[API → Results Endpoints](../api-reference/results-endpoints.md) for
the full shape.

## Patched codebase (remediation only)

When a remediation run completes (status
`REMEDIATION_COMPLETED`), a **Download patched codebase** button
appears on the Results header. It zips the `POST_REMEDIATION` code
snapshot for the scan and streams it as an attachment. Diff against
the `ORIGINAL_SUBMISSION` to review what the auto-fixer changed.

## Audit trail

Every LLM call made during a scan writes an `llm_interactions` row
— prompt context, raw response, parsed output, cost, token counts.
Admins can inspect the full trail from
**Admin → Scans → LLM Interactions** or via
`GET /api/v1/scans/{scan_id}/llm-interactions`.

## History

Earlier versions of SCCAP exported a SARIF 2.1 document and an
Executive Summary PDF backed by an `impact_reporting_agent` whose
graph node was never actually wired in; both were removed in the
2026-04-26 cleanup. The downloadable HTML / CSV / PDF report
described above is the replacement — it renders directly from the
consolidated findings, with no separate reporting node. SARIF export
is not currently offered.
