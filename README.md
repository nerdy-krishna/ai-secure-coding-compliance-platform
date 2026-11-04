# SCCAP — Secure Coding Compliance and Pentesting

An open-source platform that audits your source code against OWASP frameworks, proves
what it reports, and then attacks the deployed application — on one installation, with
one login.

Two independent engines share a tenant, a user model and a reporting layer:

- **Code scanning** — deterministic SAST first (Bandit · Semgrep · Gitleaks · OSV), then
  LLM agents over the files that matter. Findings are consolidated to one root cause,
  scored with CVSS 3.1, replayed for proof, and exported as HTML, PDF, CSV or SARIF.
- **Pentesting** — an autonomous, scope-bounded agent that reads reconnaissance, writes a
  plan of hypotheses, drives real tools (nmap, nuclei, ZAP, sqlmap, ffuf, a Playwright
  browser, whatweb, gobuster, hydra, hashcat) one action at a time, remembers what it has
  done, and can inspect and repair the box it runs on. A scope ledger stops it repeating
  work, findings are chained into exploit paths, and an operator can steer it while it runs.
- **Asset inventory and CVE applicability** — the systems you own, what they run, and which
  CVEs *actually* affect them: on-demand corpus lookups, LLM-designed detection checks
  replayed across the estate, and a verdict with evidence rather than a guess.

The design rule throughout: **nothing is claimed that was not observed**. A clean report
says what was scanned and what was skipped; a finding says which scanner or agent
produced it, at which line, verified how.

## Table of contents

- [What it looks like](#what-it-looks-like)
- [Code scanning](#code-scanning)
- [Pentesting](#pentesting)
- [Asset inventory and CVE applicability](#asset-inventory-and-cve-applicability)
- [Findings, evidence and reports](#findings-evidence-and-reports)
- [Administration, tenancy and identity](#administration-tenancy-and-identity)
- [Integrations and observability](#integrations-and-observability)
- [Installation](#installation)
- [Upgrading, rolling back, uninstalling](#upgrading-rolling-back-uninstalling)
- [First run](#first-run)
- [Stack](#stack)
- [Development](#development)
- [License](#license)

## What it looks like

| Surface | What it does |
|---|---|
| **Dashboard** | Two sections — Code Scanning and Pentesting. Projects, scans/assessments, findings, tokens in/out and estimated spend, then product-specific tiles. |
| **Projects & Scans** | Every project with its latest terminal scan, risk score and severity bar. Scans open into the results page. |
| **New Scan** | Upload files, paste code, drop an archive (`.zip`/`.tar.gz`/`.rar`) or point at a GitHub/GitLab/Bitbucket repository. Choose frameworks, models, and which scanners and tools may run. |
| **Results** | Risk score, scan information, file coverage, findings tree and detail with code, triage disposition, and per-finding consolidation evidence. |
| **Pentesting** | Three pages: launch an engagement, browse projects and assessments, review history. A live cockpit per run shows the event stream, findings as they land and the browser frame. |
| **Compliance** | Per-framework coverage for the 8 bundled OWASP frameworks plus custom frameworks, with document counts from the RAG store. |
| **Security Advisor** | Framework-scoped chat grounded in ingested guidelines, with a context rail of the sources it used. |

## Code scanning

**Submission and ingestion.** Uploads, pasted code, archives and clones all pass through
one ingest manifest: paths are normalised, duplicates collapsed, per-file and total size
caps applied, and binaries, empty files and unsupported types recorded with a reason
instead of vanishing. A submission whose every file would be skipped is refused up front
with the breakdown rather than producing an empty scan.

**File classification by evidence, not by path.** Every file is classified as first-party
source, vendored library, generated artefact, runtime file, lockfile, empty or binary. The
decision is evidence-based: a hand-written module inside `build/` is still first-party, and
a `@generated` file outside it is still generated. Vendored and generated files get a
secrets scan and nothing more unless you enable **Scan vendor and generated files too**.

**Language and scanner capability in one table.** ~50 languages plus filename rules
(`Dockerfile`, `Makefile`, `Jenkinsfile`, `requirements.txt`, `go.mod`, `.env*`, `*.d.ts`)
resolve to a language and the scanners that can read it. Semgrep rule selection reads the
same table, so a Kotlin or Rust repository is covered rather than silently skipped.

**Three human gates, all optional to pass through.** A scan pauses at
`PENDING_PRESCAN_APPROVAL` with the deterministic findings, at
`PENDING_PROFILING_APPROVAL` with a profiling-cost estimate, and at
`PENDING_COST_APPROVAL` with the deep-analysis estimate. Each gate can be approved,
stopped, or left; nothing expensive runs without an explicit decision.

**Stopping is a first-class outcome.** Pressing Stop at the pre-LLM gate records
`STOPPED_BEFORE_LLM`: the deterministic findings are kept, the results page renders them
with a banner stating that no LLM review, cross-file validation or fix generation ran, and
the duration reported is the time the scan actually worked — not the time it waited for
you.

**Analysis.** Specialised agents run per file under a fixed per-configuration concurrency
pool with RPM/TPM budgets, retry with jitter and circuit breakers. Each invocation is a
durable task keyed by input hash, so a resumed scan reuses completed work. An optional
second reasoning model runs every agent twice and unions the findings.

**Consolidation and proof.** A per-file reasoning pass merges same-root-cause findings, and
a deterministic global pass merges cross-file duplicates. Every finding carries a stable
fingerprint, a CVSS 3.1 score derived from its CWE/reach/authentication, a confirmation
status from a deterministic replay (curl reproduction when one exists), and its
contributors — the raw findings and agents that argued for it, visible per finding.

**Coverage you can audit.** The results page shows how many files were scanned, a per-file
table of scanned and excluded files with the reason each was excluded, and a per-scanner,
per-input coverage ledger. A zero-finding report distinguishes "the tools looked and found
nothing" from "something did not run".

## Pentesting

Feature-gated (off by default; enabled during setup or with the `pentesting-v5` Compose
profile). Authorised black-box, grey-box and white-box assessment that never mutates the
code-scan aggregate.

- **Plan first, then act** — reconnaissance runs every discovery tool and stores each full
  payload. The model then reads it and writes a plan: hypotheses of endpoint × vulnerability
  class × the evidence that justifies them. The loop works that plan; `done` is deferred
  while hypotheses or leads are open.
- **Attack-surface discovery** — six passive subdomain indexes with retries and per-source
  timeouts, DNS brute-forcing, dangling-CNAME takeover checks, OpenAPI/Swagger/GraphQL
  discovery, and JavaScript bundle mining for endpoints, parameters, source maps and
  secrets.
- **Scope is the only limit** — the operator's origin plus the in-scope estate beneath its
  registrable domain. Private and loopback destinations are refused, for raw-TCP tools by
  resolving and refusing non-public addresses.
- **Model-in-the-loop tools** — 26 tools: nmap, nuclei (full template library), ZAP active
  scan, sqlmap, ffuf, whatweb, gobuster, a real Playwright browser, hydra, hashcat, plus the
  harness tools below.
- **A scope ledger, not a hope** — every tool call declares what it covers (host, parameter,
  template set, auth state) and what justifies a re-run. A repeat inside a covered scope is
  answered from the stored output instead of hitting the target: the agent gets the digest,
  the artefact holding the full payload, and can `read` it or send a declarative `queries`
  filter for the rows it needs. Escalating `--level` is a repeat, not progress.
- **Memory that survives a restart** — every turn is persisted; past a token budget older
  turns are compacted into a running summary while the rows stay for audit. The agent sees
  its own calls and arguments, not just their results.
- **Operator steering, live** — a brief at launch, directives during the run (with the
  agent's reply), pause-and-instruct, operator-authored targets that join the lead queue,
  and a tool policy that can disable or pin a tool mid-run.
- **Harness tools** — `check_environment`, `diagnose_tool` and `run_diagnostic` let the agent
  inspect the runtime (binaries, disk, memory, egress, a stale ZAP port) and repair it from an
  allowlist while it runs. `run_shell` adds arbitrary commands, off unless the operator ticks
  *Allow shell commands (expert)* for that run.
- **Persistent lead ledger** — every observation becomes a lead with a priority band,
  claimed as it is tested. The ledger, not the conversation, decides when a run is done, so
  pause/resume/restart never loses work.
- **Observations are findings** — ports, technologies, endpoints, parameters and leaked
  secrets are retained for chaining. The holistic review reads every finding and observation
  together and asks whether they chain into something neither proves alone; a chain is only
  `confirmed` when a step demonstrated impact.
- **Severity that means something** — every finding carries a CVSS 3.1 vector derived from
  the weakness. An unrecognised CWE is capped at `PENTEST_UNKNOWN_CWE_CEILING` (default
  medium) instead of defaulting to critical, and repeated scanner alerts collapse into one
  finding with an instance count.
- **Terminal-style activity console** — every tool call with its exact arguments and scope,
  a live elapsed counter while it runs, expandable raw output, level filters, pause and
  download. `--full` output on demand.
- **Export for review** — the whole run as JSON or ZIP: event stream, agent transcript with
  arguments, plan and verdicts, lead queue, probe ledger, directives, findings, chains and
  every stored tool payload, with a README that says how to read it.
- **Troubleshoot after the fact** — a finished run can be diagnosed: the run's own failures
  are joined with a live environment check, and the model separates "the target was clean"
  from "the box could not run the tools", with allowlisted fixes that can be applied.
- **Secret vault** — discovered credentials and keys are stored encrypted, masked
  everywhere else, revealed only on explicit audited action, and reports are masked by
  default (`&secrets=unmasked` for the full variant).
- **Per-run model choice** — pick the model on the new-assessment page; the run records it,
  and the run page shows the model, tokens and cost as they accumulate.
- **Recovery and schedules** — a heartbeat marks stale runs `interrupted` and can re-queue
  them without losing findings; a run can be cloned on an interval (1 hour to 30 days) and
  each clone reports what is new, resolved and still present versus its predecessor.

Documents: [pentesting engine](docs/docs/operations/pentesting-engine.md) and
[ADR-029](docs/adr/029-pentesting-autonomous-engine.md),
[ADR-030](docs/adr/030-assessment-memory.md),
[ADR-032](docs/adr/032-plan-first-assessment-loop.md).

## Asset inventory and CVE applicability

Answering "do these CVEs affect us?" needs an inventory, a corpus, and a rule about what
counts as proof.

- **Inventory is the authorisation** — assets of any kind (web app, API, host, service,
  repository, VM, container, Kubernetes cluster, database, firewall, network device, cloud
  account), each with endpoints, technologies and declared package versions. Adding an asset
  authorises testing its recorded hosts, and the basis is recorded.
- **Corpus offline-first** — NVD, OSV and CISA KEV imported from files, so a verdict is
  reproducible without a live API. Advisory references are stored and used.
- **A CVE that is not in the corpus is fetched, not refused** — NVD, then OSV, then the model
  (marked unverified). `unknown_cves` means nothing could resolve it.
- **Research, then a check, then a verdict** — the model reads the CVE and its references and
  states the mechanism and the detection signals; the check is a **Nuclei-compatible YAML
  template** stored once per CVE and replayed across the estate; the verdict must name the
  observation that decided it, and an unevidenced verdict is downgraded to `undetermined`.
- **Probing uses the real scanners** — a probe is queued for the pentest engine, which runs
  `nmap -sV`, `whatweb` and `nuclei` with the bundled templates, then writes the results into
  the inventory. HTTP/TLS/banner probes remain as the fallback when no engine is running,
  including a Host/SNI second pass for sites behind a CDN.
- **One verdict table** — a declared dependency version and an observed banner produce the
  same kind of row, differing in basis and confidence; a bare banner never yields
  `applicable`.

Documents: [CVE applicability](docs/docs/operations/cve-applicability.md) and
[ADR-031](docs/adr/031-cve-applicability.md).

## Findings, evidence and reports

- **Ranked, proven claims** — severity always follows the CVSS 3.1 band; a finding with no
  deterministic replay is marked `needs_review` rather than promoted.
- **One finding per root cause** — duplicates are merged with provenance
  (`sources`, `reported_by`, corroborating evidence) and marked `duplicate` with a pointer
  to the canonical row.
- **Triage** — `open`, `confirmed`, `false positive`, `remediated`, `risk accepted`, with an
  audited history per finding and bulk changes across a selection.
- **Reports** — HTML, PDF, CSV and SARIF 2.1.0 rendered from the consolidated findings,
  plus a raw **Scanner JSON** export: the unmodified per-scanner output with binary
  versions and SHA-256, for audit rather than for reading.
- **Evidence chain** — each finding records its attempt, fingerprint, exact ranges,
  coverage entries and contributing raw findings.

## Administration, tenancy and identity

- **Groups and scoped visibility** — users see their own work plus that of peers in a
  shared group; admins see everything. Every list endpoint enforces the same scope.
- **Tenants** — platform or multi-tenant operation, with tenant-scoped data, credentials
  and reports.
- **SSO and SCIM** — OIDC/SAML sign-in and directory provisioning, with an auth audit trail
  resolving usernames server-side.
- **Identity and email** — SSO, SCIM and SMTP grouped in one admin area.
- **Framework config** — standards, agents, prompt templates and CWE mappings.
- **Semgrep config** — rule sources as git repositories with on-demand and scheduled syncs;
  Semgrep runs only on ingested rules, and the submission page tells you when no rule
  covers the detected languages.
- **LLM configs, usage and spend** — per-configuration models, RPM/TPM budgets, price
  overrides, and a usage/spend centre.
- **Encrypted secrets** — LLM keys, SMTP passwords and tenant credentials are
  envelope-encrypted at rest; nothing secret is stored plaintext.
- **Platform and features** — runtime feature flags for every optional surface, with
  dependencies resolved automatically.
- **Audit** — scan events, LLM interactions, auth events and pentest run events all
  retained and exportable.

## Integrations and observability

- **MCP server** at `/mcp` — submit scans, read status and results, approve gates and ask
  the advisor from Claude Code, Cursor or any MCP client, over the same JWT auth.
- **CI policy endpoints** — coverage and finding-governance gates with SARIF output, so a
  pipeline can fail on a new high-severity finding or on degraded coverage.
- **REST API** at `/api/v1` with OpenAPI docs, plus a generated frontend client contract.
- **Observability** — `X-Correlation-ID` on every request, structured JSON logs, and an
  optional Fluentd → Loki → Grafana stack with provisioned dashboards.

## Installation

**Prerequisites:** Docker Engine with the Compose plugin, and Git. Nothing else — the UI is
built inside its image, so Node.js and Python are not host requirements. Linux hosts get
BBR and the firewall rules applied by the installer; Windows and macOS use Docker Desktop.

```bash
git clone https://github.com/nerdy-krishna/ai-secure-coding-compliance-platform.git
cd ai-secure-coding-compliance-platform
chmod +x setup.sh
./setup.sh
```

The installer is terminal-first and resumable. It checks prerequisites, asks which
**installation variant** to use, generates secrets, asks for the administrator
email/password, the LLM provider/model/key, the domain (with optional Let's Encrypt
provisioning) and, for the custom variant, the optional stacks and features. It then
writes `.env`, builds and starts the stack, runs Alembic migrations and health-checks the
API before printing the URL. On Windows run `setup.bat`.

**Variants** — *Vibe coder* (scan, chat, compliance), *Developer* (adds users, groups,
email, MCP, admin authoring), *Enterprise* (adds SSO, SCIM, multi-tenancy and the
log stack), *Custom*. The variant seeds runtime feature flags and selects the Compose
profiles; change them later under *Admin → Platform*. Pentesting is an extra opt-in asked
during setup.

Configuration bootstrap without the wizard (for pipelines):

```bash
python3 scripts/bootstrap_env_secrets.py --env-file .env
docker compose config --quiet
```

Details: [installation guide](docs/docs/getting-started/installation.md),
[configuration](docs/docs/getting-started/configuration.md) and
[maintenance & uninstallation](docs/docs/getting-started/maintenance.md).

## Upgrading, rolling back, uninstalling

`setup.sh` owns the whole lifecycle. Every destructive step names what it deletes and asks
you to type the action; `-y` skips the prompts.

| Command | Effect |
|---|---|
| `./setup.sh --update` | Pull the current branch and rebuild **only the images whose content changed** — a backend fix is seconds, not minutes. Migrates, health-checks and keeps the previous images for rollback. The database dump is skipped when no migration changed. |
| `./setup.sh --update --full` | Rebuild every image. For a changed base image, or a cache you do not trust. |
| `./setup.sh --rollback` | Return code **and** images to the state before the last `--update`. |
| `./setup.sh --uninstall` | Stop and remove the stack. Volumes (database), `.env`, `.secrets/` and certificates are **kept** — re-running `./setup.sh` brings it back. |
| `./setup.sh --purge` | Also drop the data volumes and the images built here. A `pg_dumpall` backup is written to `.purge-backups/` first. `.env`, `.secrets/` and `certbot/` survive. |
| `./setup.sh --factory-reset` | Purge plus delete `.env`, `.secrets/` and `certbot/` state — a genuinely clean install, with a fresh certificate next time. |
| `./setup.sh --repair-tls` | Re-create TLS material from `.env` when the UI reports `tls_cert_missing` or "connection closed". |

The profile menu shows the running version (`0.2.0+7d7f49af` — release plus build commit) and
whether the deployment matches the checkout; it changes on every successful update, which is
how you tell a deploy landed.

Teardown is verified rather than assumed: it force-removes containers left by an older
profile generation and the networks they keep busy, and exits non-zero if anything of the
project survives. Re-running the installer after `--uninstall` or `--purge` restores the
stack from the preserved configuration, keeping every non-placeholder secret.

## First run

1. Open the URL the installer printed and sign in with the administrator account it
   created.
2. **Semgrep rules load themselves** — opening *Admin → Semgrep Config* seeds the built-in
   library, enables the sources and starts the first sync. (Semgrep runs only on ingested
   rules, so there is no bundled fallback pack.)
3. Optional: add SMTP, extra LLM configurations, SSO/SCIM, or create user groups.
4. Submit a scan and approve the estimates as they appear.
5. For pentesting, open *Pentesting → New Pentest*, choose the model, set the scope and any
   brief, and launch. Steering is available on the run page while it works.
6. For CVE work, open *Inventory → Assets & CVEs*, add the assets, import an NVD/OSV feed in
   the Corpus tab, then check a CVE list.

## Stack

Python 3.12 · FastAPI · SQLAlchemy async + Alembic · LangGraph + LangChain · LiteLLM ·
Pydantic AI · FastMCP · WeasyPrint · Postgres 16 · RabbitMQ · Qdrant (fastembed
`all-MiniLM-L6-v2`) · React 18 + Vite + TypeScript · TanStack Query · React Router ·
Fluentd → Loki → Grafana (optional) · nmap · nuclei · ZAP · sqlmap · ffuf · whatweb ·
gobuster · Playwright · hydra · hashcat.

Full breakdown: [technology stack](docs/docs/overview/technology-stack.md).

## Development

Backend and worker commands run inside Docker, because `.env` uses Compose service
hostnames (`db`, `rabbitmq`, `qdrant`) that only resolve there.

```bash
docker compose up -d --build          # bring the stack up
docker compose logs -f app worker     # follow logs
docker compose exec app alembic upgrade head
docker compose exec app python -m ruff check src
docker compose exec app python -m pytest tests -q
npm --prefix secure-code-ui run lint
npm --prefix secure-code-ui run build
```

There is **no CI service**: workflows and the Dependabot/Renovate configs were removed, so
gates run where you run them. `AGENTS.md` holds the project-specific rules; `CONTEXT.md`
and `docs/adr/` hold the domain vocabulary and decisions.

## License

Apache License 2.0 — see [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).
