---
sidebar_position: 2
title: Understanding Results
---

# Understanding Results

The **Results** page (`/analysis/results/{scan_id}`) opens when a
scan reaches a terminal state. It's the main place users read
findings, decide what to remediate, and export downstream artifacts.

## Layout

- **Header** — scan ID, project name, final status, created/completed
  timestamps, cost (sum of `llm_interactions.cost` for this scan),
  and a link to the LLM-interactions log.
- **Summary strip** — total findings grouped by severity; the
  CVSS-weighted 0–10 risk score on the scan row (the same calculation
  the Dashboard / Compliance posture is derived from, shown here as a
  0–10 intensity rather than a 0–100 posture).
- **Download report** — HTML, CSV, and PDF buttons in the header
  export the scan's consolidated findings (see [Reporting](../reporting.md)).
- **Per-file panels** — every analyzed file gets a collapsible
  section. Expand to see its consolidated findings, with:
  - Title + severity chip + CVSS score
  - Description (a consolidated finding leads with the root cause)
  - Affected line + an *also affects* strip listing every other site
    the same issue manifests
  - CWE id — shown only for deterministic SAST-scanner findings;
    LLM-agent findings carry no CWE
  - Corroborating agents (the agent names that flagged this
    finding; a finding merged from multiple agents lists them all)
  - Suggested fix (if the agent produced one)
  - External references (links to ASVS, Cheatsheets, CWE, etc.)

Findings are **consolidated** before they reach this page: a
reasoning-model pass merges raw per-agent findings describing the
same root cause into one root finding and drops false positives and
noise, so the same bug never shows up as several rows.

## Severity vs. confidence

Findings carry **both** a severity (Critical / High / Medium / Low /
Informational) and a confidence (High / Medium / Low). Severity is
derived from the finding's CVSS score; the UI surfaces confidence
inline so reviewers can prioritize triage.

## Report formats

The Results header exports the scan's findings as a self-contained
HTML page, a CSV (one row per finding), or a paginated PDF — see
[Reporting](../reporting.md). The earlier Impact tab, SARIF export,
and Executive Summary PDF (backed by an `impact_reporting_agent` node
that was never wired in) were removed in the 2026-04-26 cleanup; the
HTML / CSV / PDF report is their replacement.

## Related links

- [Managing Findings + Remediation](./managing-findings.md) — apply
  fixes from the Results page.
- [API → Results Endpoints](../../api-reference/results-endpoints.md)
  for the JSON shapes.
