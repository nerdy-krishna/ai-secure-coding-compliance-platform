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

The header carries a **resource monitor** (CPU, memory and disk with a detail panel:
load average, cores, host and container memory, free space, uptime, running scans and
pentests) and the **running version** in the profile menu.

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

Enabled during setup, or with the `pentesting-v5` Compose profile. Launch an assessment,
browse projects and history, and watch or steer a run while it works.

- **Plan first** — reconnaissance runs every discovery tool and stores each full payload.
  The model reads it and writes **hypotheses** (endpoint × vulnerability class × the evidence
  that justifies it). The loop works that plan; `done` is deferred while hypotheses or leads
  are open, and a hypothesis closes only with a verdict: confirmed, ruled out with the
  evidence, or blocked with the reason.
- **Scope ledger** — each tool declares what a call covers and what justifies a re-run.
  A repeat inside a covered scope is answered from the stored output, not executed again; the
  agent is given the digest, the artefact id and two ways to get detail: `read` the whole
  payload, or `queries` for a declarative filter (`path`, `contains`, `regex`, `limit`). Effort
  knobs (`--level`, threads, severity filters) do not count as new work.
- **Memory** — every turn is persisted with the calls and arguments; past a token budget older
  turns are compacted into a summary and the rows are kept for audit. A restart resumes with
  the transcript instead of a blank page.
- **Steering** — a brief at launch; directives mid-run (each shows the agent's reply);
  pause-and-instruct; operator-authored targets that join the lead queue; and a tool policy
  that disables or pins a tool for the run.
- **Harness tools** — `check_environment`, `diagnose_tool`, `run_diagnostic` let the agent
  inspect the runtime and repair it from an allowlist. `run_shell` adds arbitrary commands,
  only when the operator enables *Allow shell commands (expert)* for that run.
- **Attack-surface discovery** — six passive subdomain indexes with per-source timeouts and
  retries, DNS brute-force, dangling-CNAME takeover detection, OpenAPI/Swagger and GraphQL
  discovery, and JavaScript bundle mining.
- **Scope guard** — the operator's origin plus the in-scope estate beneath its registrable
  domain; private and loopback destinations are refused.
- **Tools** — 26 in total: nmap, nuclei (full template library), ZAP active scan, sqlmap, ffuf,
  whatweb, gobuster, a real Playwright browser, hydra, hashcat and the harness tools.
- **Severity** — the CVSS 3.1 vector is derived from the weakness; an unrecognised CWE is
  capped (`PENTEST_UNKNOWN_CWE_CEILING`, default `medium`), and repeated scanner alerts
  collapse into one finding with an instance count.
- **Chaining** — an index of findings and observations, detail on request, and premises that
  must reference real findings. The holistic review runs automatically when a run finishes
  with findings; a chain is confirmed only when a step demonstrated impact.
- **Activity console** — terminal-style: every call with its exact arguments and scope, a live
  elapsed counter, an expand toggle for full output, level filters, pause, copy and download.
- **Export** — the whole run as JSON or ZIP (events, transcript with arguments, plan, leads,
  probe ledger, directives, findings, chains, stored payloads) with a README explaining how to
  read it.
- **Troubleshoot** — a finished run can be diagnosed against the live environment; the model
  separates "target was clean" from "box could not run the tools", and allowlisted fixes can
  be applied.
- **Model choice and cost** — pick the model on the new-assessment page; the run page shows
  the model, tokens in/out and cost as they accumulate.
- **Reports** — Markdown, JSON, HTML and PDF, masked by default.

See [the pentesting engine](../operations/pentesting-engine.md).

## Asset inventory and CVE applicability

*Inventory → Assets & CVEs* (`/inventory`). The question is "do these CVEs affect us?", and
the answer is a verdict with a basis, never a bare yes.

| Tab | What it does |
|---|---|
| **Assets** | bulk **Import CSV** with a downloadable template and a per-row summary; assets of any kind (web app, API, host, service, repo, VM, container, Kubernetes, database, firewall, network device, cloud), their endpoints, technologies and declared packages; **Probe inventory** and **Sweep inventory** |
| **CVE checks** | paste or upload a CVE list, choose whether to test the uncertain candidates, read verdicts by outcome with basis and confidence, and **Test** a single candidate |
| **Corpus** | NVD / OSV / KEV imports and corpus counts |

- **Inventory is the authorisation** — adding an asset authorises testing its recorded hosts,
  and the basis is recorded on the asset.
- **Probing uses the real scanners** — a probe is queued for the pentest engine, which runs
  `nmap -sV`, `whatweb` and `nuclei` (bundled templates) and writes the results into the
  inventory. Without an engine, HTTP/TLS/banner probes run in-process, including a Host/SNI
  second pass for sites behind a CDN.
- **A CVE outside the corpus is fetched** — NVD, then OSV, then the model (marked unverified).
- **Research → check → verdict** — the model states the mechanism and the detection signals,
  the check is a Nuclei-compatible template stored once per CVE and replayed across the
  estate, and the verdict must name the deciding observation.
- **One verdict table** — declared dependency versions and observed banners produce the same
  kind of row; a bare banner never yields `applicable`, and "no version recorded" means
  unknown rather than unaffected.
- **Activity console** — the same terminal view: probing, fingerprints, CVE fetches, matches,
  tests and verdicts as they happen.

See [CVE applicability](../operations/cve-applicability.md).

## Administration

| Area | Contents |
|---|---|
| Framework Config | Standards, agents, prompt templates, CWE mappings |
| Semgrep Config | Rule sources (git repositories), enable/sync, scheduled syncs. The built-in library is loaded, enabled and synced automatically the first time the page is opened — no button to find before your first scan |
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

## Running work in parallel

Code scans and pentests are separate executors and run side by side.

**Code scans.** One worker container runs up to `WORKER_ANALYSIS_SLOTS` scans at a
time (default 3) and `WORKER_SUBMISSION_SLOTS` pre-LLM pipelines concurrently
(default 1, so a burst of submissions does not start several deterministic prescans
at once). Inside a scan, agent fan-out is bounded by `CONCURRENT_LLM_LIMIT` (default
50 per reasoning lane) and `CONCURRENT_SCANNER_LIMIT` (default 10), and each LLM
configuration's RPM/TPM budget throttles further. Raise the slot counts on a host
with memory to spare; each slot holds its own scan state.

**Pentests.** The `pentest-engine` container polls the database for queued runs and
executes **one at a time**; a run is claimed atomically, so a second engine would not
double-drive it, but running more than one engine buys nothing until that loop is
parallelised. Pentests read and write their own tables and never touch the scan
queues, so a pentest and several code scans can run together — they share the host
(CPU/RAM), Postgres, and the LLM provider's rate limits.

**Inventory probes** ride the same engine: a probe is queued as a row and the engine runs
nmap/whatweb/nuclei for it between assessments. With no engine running, the API probes
in-process instead — the console says which path ran.

## Operational features

- **Lifecycle** — `setup.sh` installs, updates, rolls back, uninstalls, purges and
  factory-resets, with a backup before anything is destroyed. See
  [Maintenance and Uninstallation](../getting-started/maintenance.md).
- **Feature flags** — every optional surface is a runtime flag, seeded by the installation
  variant and changeable under *Admin → Platform*.
- **Tenancy** — single-tenant or multi-tenant, with tenant-scoped data and credentials.
- **Audit** — scan events, LLM interactions, auth events and pentest run events are retained
  and exportable.
