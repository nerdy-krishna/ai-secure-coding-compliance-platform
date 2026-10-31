---
title: Platform Features
sidebar_position: 1
---

# Platform Features

SCCAP — Secure Coding Compliance and Pentesting — has two engines on one installation:
**code scanning** and **pentesting**. They share a tenant, a user and group model, encrypted
credential storage, an audit trail and a reporting layer, and they never write into each
other's records.

Every list surface is scoped by the same visibility filter: a regular user sees their own
work plus that of peers in a shared group; admins see everything.

## Dashboard

Two sections, code scanning first, then pentesting. Shared tiles — projects, scans or
assessments, findings, tokens in and out, estimated cost — are followed by the
product-specific ones.

- Risk score and severity breakdown across critical / high / medium / low / informational.
- Recent scans and assessments with status, duration and finding counts.
- Usage and spend over the last 30 days, per operation kind.

## Submitting a scan

- **Four sources** — individual files, pasted code, an archive (`.zip`, `.tar.gz`, `.rar`),
  or a repository URL (GitHub, GitLab, Bitbucket). GitHub repositories are previewed through
  the API without cloning, and a file tree lets you include or exclude paths before any
  estimate is produced.
- **One ingest manifest** — every source passes the same rules: paths normalised, duplicates
  collapsed, per-file and total caps enforced, and binaries, empty files and unsupported
  types recorded with a reason. A submission whose every file would be skipped is refused
  with the breakdown instead of producing an empty scan.
- **Two LLM slots** — a *utility* (cheap) model for profiling and verification and a
  *reasoning* (capable) model for analysis and consolidation. An optional **second reasoning
  model** runs every agent twice and unions the findings, recording which model detected
  each one.
- **Per-stage temperatures** (profiler / analysis / consolidation / merge), or turn
  temperature off entirely so each model uses its provider default.
- **Framework multi-select** — the 8 bundled OWASP frameworks plus custom frameworks.
- **Tool selection** — choose which deterministic scanners and, for pentesting, which tools
  may run. Everything applicable runs by default.
- **Scan vendor and generated files too** — by default dependencies, generated bundles and
  minified output get a secrets scan only; this toggle gives them the full treatment.

## File classification

Every file is classified by **evidence, not by path**: first-party source, vendored library,
generated artefact, runtime file, lockfile, empty, or binary.

- A hand-written module inside `build/` is still first-party; a `@generated` file outside it
  is still generated.
- Language and scanner capability come from one shared table (~50 languages plus filename
  rules such as `Dockerfile`, `Makefile`, `Jenkinsfile`, `requirements.txt`, `go.mod`,
  `.env*`, `*.d.ts`), so Semgrep rule selection matches what the repository actually
  contains.
- The results page shows a **File coverage** table listing every scanned and excluded file
  with the reason — empty, binary, vendored, generated, too large, beyond the budget, or no
  scanner for the language.

## The scanning pipeline

1. **Classification** — as above, with a ranked selection so a truncated scan keeps
   first-party source rather than whatever arrived first.
2. **Pre-LLM scan** — Bandit, Semgrep, Gitleaks and OSV over the eligible files, each
   recorded in a per-scanner, per-input coverage ledger with provenance (binary version and
   SHA-256).
3. **Pre-LLM review gate** (`PENDING_PRESCAN_APPROVAL`) — the deterministic findings with
   the exact source line, before any code is sent to a model.
4. **Profiling** — eligible files are profiled on the utility model: what the file does, its
   security-relevant operations, and which domains apply, grounded in a tree-sitter symbol
   index.
5. **Profiling cost gate** (`PENDING_PROFILING_APPROVAL`).
6. **Cost estimate gate** (`PENDING_COST_APPROVAL`) — priced on the routed agent set, per
   model, with a duration estimate.
7. **Analysis** — specialised agents per file under a fixed per-configuration concurrency
   pool, RPM/TPM budgets, retry with jitter and circuit breakers. Each invocation is a
   durable task keyed by input hash.
8. **Consolidation** — per-file, then a deterministic cross-file pass; duplicates become
   contributors rather than extra rows.
9. **Cross-file validation** (opt-in) — each finding re-judged against its callers and
   inputs, attaching `confirmed` / `mitigated` / `unconfirmed` without changing severity.
10. **Proof** — every finding is replayed where a deterministic reproduction exists
    (curl against the endpoint, sensitive-path disclosure, SQL injection payload, nuclei
    template replay, API schema, GraphQL introspection, takeover, secret hash, source map,
    TLS). No replay means `needs_review` — never an upgrade.

## Stopping, pausing and resuming

- **Stop at any gate.** Stopping at the pre-LLM gate records `STOPPED_BEFORE_LLM`: the
  deterministic findings are kept and rendered as the scan's results, with a banner stating
  that no LLM review, validation or fix generation ran.
- **Durations measure work.** The reported duration excludes time parked at an approval
  gate, so a three-minute scan that waited twenty minutes for you reads as three minutes.
- **Resume or restart** — failed scans, and cancelled scans with durable artifacts, can be
  resumed (reusing completed work) or restarted from the original snapshot. Both preserve
  the audit trail.

## Results page

- **Risk score** with a severity strip, and the counts that produced it.
- **Scan information** — status, type, ID, source, frameworks, cross-file validation,
  temperature, consolidation tally and the models used, in one two-column block.
- **File coverage** — every scanned and excluded file, with reasons.
- **Findings tree and list** — by file, filterable by severity, source and triage
  disposition, with bulk disposition changes.
- **Finding detail** — severity and CVSS, confidence, corroborating agents, the exact source
  with the vulnerable line highlighted, description, remediation, triage history, the patch
  evidence when a validated patch exists, and **Merged from N findings** — the raw findings
  and agents that produced this row.
- **Downloads** — HTML, PDF, CSV, SARIF 2.1.0, and the raw Scanner JSON.
- **Timeline** — the full event stream for the scan, with the pipeline rail.

## Pipeline & Logs

The diagnostics page for a scan:

- **Findings consolidation swimlane** — one lane per detection source, severity, file or
  CWE (your choice), raw claims on the left, the consolidated findings they became on the
  right, an edge only where consolidation merged them, dropped claims marked, with zoom and
  fullscreen.
- **Findings breakdown** — the raw, consolidated and SAST buckets side by side, expandable
  per row.
- **LLM calls** — every interaction with prompt, response, tokens, cost and latency.
- **Governed fix candidates** — disposition, validation and applicability per candidate.

## Projects and scans

- Project grid with the latest terminal scan's risk score, severity bar and fixes-ready
  count, all served by the API.
- Projects and scans are grouped; a project holds many scans.
- Global search across projects, scans and findings, always scoped to what the caller may
  see.

## Compliance

- Per-framework card for the 8 bundled OWASP frameworks (ASVS, Proactive Controls,
  Cheatsheets, CWE Essentials, ISVS, LLM Top 10, Agentic Top 10, MASVS) and any custom
  framework, with RAG document count and open findings per framework.
- Admins ingest or replace framework knowledge from CSV or a git URL.

## Advisor

- Framework-scoped chat grounded in the RAG store, with a live context rail showing the
  knowledge sources, referenced findings and files it used.
- Available from *Security Advisor* under Code Scanning and from the floating advisor button
  on every authenticated page.

## Pentesting

Enabled during setup, or with the `pentesting-v5` Compose profile. Three pages: launch an
engagement, browse projects and assessments, review history.

- **Attack-surface discovery** — six passive subdomain indexes with per-source timeouts and
  retries, DNS brute-force, dangling-CNAME takeover detection, OpenAPI/Swagger and GraphQL
  discovery, and JavaScript bundle mining for endpoints, parameters, source maps and secrets.
- **Scope guard** — the operator's origin plus the in-scope estate beneath its registrable
  domain. Private and loopback destinations are refused, and raw-TCP tools resolve and
  refuse non-public addresses. No intensity, budget, qualification or duration gates.
- **Model-in-the-loop tools** — nmap, nuclei (full template library), ZAP active scan,
  sqlmap, ffuf, whatweb, gobuster, a real Playwright browser, hydra and hashcat, driven one
  turn at a time against de-duplicated probes.
- **Persistent lead ledger** — observations become leads with priority bands, claimed as
  they are tested; the ledger decides when a run is finished.
- **Chaining** — findings are chained into exploit paths; a chain is confirmed only when a
  step demonstrated impact.
- **Secret vault** — discovered credentials are stored encrypted, masked everywhere else,
  revealed on explicit audited action, and masked in reports unless unmasked is requested.
- **Live cockpit** — event stream with prompts and tool actions, live browser frame, findings
  as they land, pause/resume/stop.
- **Recovery and schedules** — a heartbeat marks stale runs interrupted and can re-queue
  them without losing findings; a run can be cloned on an interval and each clone reports
  what is new, resolved and still present.
- **Reports** — Markdown, JSON, HTML and PDF, with masked and unmasked variants.

See [the pentesting engine](../operations/pentesting-engine.md) and
[ADR-029](https://github.com/nerdy-krishna/ai-secure-coding-compliance-platform/blob/main/docs/adr/029-pentesting-autonomous-engine.md).

## Administration

| Area | Contents |
|---|---|
| Framework Config | Standards, agents, prompt templates, CWE mappings |
| Semgrep Config | Rule sources (git repositories), enable/sync, scheduled syncs |
| LLM Configs | Provider credentials, rate limits, effective-dated price overrides |
| Usage & Spend | Consumption and cost per operation kind, budgets |
| Access & Roles | Tenants, users, groups, authorization |
| Identity & Email | SSO, SCIM, SMTP |
| Integrations | SIEM, ticketing, provider reconciliation |
| Auth Audit | Sign-in events with username resolved server-side |
| Platform | Runtime feature flags and platform settings |
| Appearance | Theme and branding |

Secrets — LLM keys, SMTP passwords, tenant credentials, discovered pentest secrets — are
envelope-encrypted at rest and never stored plaintext.

## Integrations and automation

- **MCP server** at `/mcp` — submit scans, read status and results, approve gates and ask
  the advisor from Claude Code, Cursor or any MCP client, over the same JWT auth.
- **REST API** at `/api/v1` with OpenAPI documentation, plus a generated frontend client
  contract checked by `npm run check:api`.
- **CI policy endpoints** — coverage and finding-governance gates with SARIF output.
- **Observability** — `X-Correlation-ID` on every request, structured JSON logs, and an
  optional Fluentd → Loki → Grafana stack with provisioned dashboards.

## Operational features

- **Lifecycle** — `setup.sh` installs, updates, rolls back, uninstalls, purges and
  factory-resets, with a backup before anything is destroyed. See
  [Maintenance and Uninstallation](../getting-started/maintenance.md).
- **Feature flags** — every optional surface is a runtime flag, seeded by the installation
  variant and changeable under *Admin → Platform*.
- **Tenancy** — single-tenant or multi-tenant, with tenant-scoped data and credentials.
- **Audit** — scan events, LLM interactions, auth events and pentest run events are retained
  and exportable.
