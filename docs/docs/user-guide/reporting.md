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

## Downloadable report (HTML / CSV / PDF / SARIF)

The Results header has **HTML**, **CSV**, **PDF**, and **SARIF** download
buttons. Each renders the scan's consolidated findings through a
dedicated format-native generator:

- **HTML** — a single self-contained document (inline CSS, no
  external assets) that opens in any browser.
- **CSV** — one row per finding, columns for file, line, severity,
  CVSS, source, title, description, remediation, corroborating
  agents, and affected lines. Drop it straight into a spreadsheet.
- **PDF** — a paginated, print-oriented document with a cover page,
  running headers/footers, and a card per finding.
- **SARIF** — SARIF 2.1.0 JSON suitable for GitHub code scanning upload;
  includes stable rule IDs / indexes, repository-relative artifact URIs,
  primary locations, related locations for merged findings, and
  CWE/CVSS/source/triage metadata.

For `SUGGEST` and `REMEDIATE`, every format also identifies the persisted patch-plan artifact and
its exact resolved hunks, candidate outcome, required imports/dependencies/configuration/migrations,
commands and manual steps, and validation tool/profile/version/outcome/timestamp. `AUDIT` reports
show remediation guidance but explicitly say that no code patch was generated or applied. Partial
remediation is called out in the summary; CSV includes governance-summary and fixed-lineage rows so
that fixed-only scans retain their evidence.

All four are served on demand by
`GET /api/v1/scans/{scan_id}/report?format=html|csv|pdf|sarif` — see
[API → Results Endpoints](../api-reference/results-endpoints.md).

## Native scanner reports

The **Scanner JSON** button downloads the validated native output captured during the deterministic
prescan, including the status and immutable evidence recorded for Bandit, Semgrep, Gitleaks, and
OSV-Scanner. Evidence includes binary versions/digests, configuration identifiers/digests, exact
selected Semgrep rule hashes, and resolved rule-source commits. Each execution appends a generation
and hash-verified historical rule bodies. Each execution appends an encrypted generation to the
current scan attempt instead of overwriting earlier evidence; the endpoint returns the latest
authorized generation after exact-version decryption and digest verification. Each scanner
payload is capped at 5 MiB; a truncation manifest is returned for larger output. Older scans have no
scanner-report artifact; the UI explains that the artifact was not retained for those legacy scans.

The Results page and generated HTML/PDF/SARIF/CSV reports show the bounded provenance summary.
**Degraded** means SCCAP cannot prove one or more inputs were immutable. OSV currently shows this
state because advisory matching uses the live OSV service rather than a dated, hashed offline
database snapshot; the pinned OSV executable alone does not make the advisory result reproducible.

## Raw findings (JSON)

For custom integrations, call
`GET /api/v1/scans/{scan_id}/result`. Response includes the full
`summary_report`, per-file findings bundle, cost details, and every
`ScanEvent` emitted during the run. See
[API → Results Endpoints](../api-reference/results-endpoints.md) for
the full shape.

## Validated patch artifact (suggestion and remediation)

Completed `SUGGEST` and `REMEDIATE` scans expose the versioned artifact that SCCAP actually
validated and persisted:

```http
GET /api/v1/scans/{scan_id}/patch-plan?format=json
GET /api/v1/scans/{scan_id}/patch-plan?format=patch
```

JSON is the complete machine-readable plan. The patch download includes requirements, validation
evidence, and the persisted unified diff; save it as `scan-{scan_id}.patch`, review it, then use
`git apply --check` before `git apply`. The Results page copy/download actions read this artifact and
never reconstruct a patch by searching an LLM-provided snippet.

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

Earlier versions of SCCAP exposed a separate `/scans/{id}/sarif`
endpoint and an Executive Summary PDF backed by an
`impact_reporting_agent` whose graph node was never actually wired in;
both were removed in the 2026-04-26 cleanup. The current SARIF export
is the on-demand `format=sarif` variant of the consolidated findings
report, with no separate reporting node or persisted SARIF artifact.
