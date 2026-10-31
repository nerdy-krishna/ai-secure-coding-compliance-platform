# SCCAP — Secure Coding Compliance and Pentesting

An open-source platform that audits your source code against OWASP frameworks, proves
what it reports, and then attacks the deployed application — on one installation, with
one login.

Two independent engines share a tenant, a user model and a reporting layer:

- **Code scanning** — deterministic SAST first (Bandit · Semgrep · Gitleaks · OSV), then
  LLM agents over the files that matter. Findings are consolidated to one root cause,
  scored with CVSS 3.1, replayed for proof, and exported as HTML, PDF, CSV or SARIF.
- **Pentesting** — an autonomous, scope-bounded engine that reconnoiters the attack
  surface, drives real tools (nmap, nuclei, ZAP, sqlmap, ffuf, a Playwright browser,
  whatweb, gobuster, hydra, hashcat) through a model-in-the-loop, chains findings into
  exploit paths, and reports what it proved.

The design rule throughout: **nothing is claimed that was not observed**. A clean report
says what was scanned and what was skipped; a finding says which scanner or agent
produced it, at which line, verified how.

## Table of contents

- [What it looks like](#what-it-looks-like)
- [Code scanning](#code-scanning)
- [Pentesting](#pentesting)
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

- **Attack-surface discovery** — six passive subdomain indexes with retries and per-source
  timeouts, DNS brute-forcing, dangling-CNAME takeover checks, OpenAPI/Swagger/GraphQL
  discovery, and JavaScript bundle mining for endpoints, parameters, source maps and
  secrets.
- **Scope is the only limit** — the operator's origin plus the in-scope estate beneath its
  registrable domain. Private and loopback destinations are refused, for raw-TCP tools by
  resolving and refusing non-public addresses. There are no intensity, budget,
  qualification or duration gates.
- **Model-in-the-loop tools** — nmap, nuclei (full template library), ZAP active scan,
  sqlmap, ffuf, whatweb, gobuster, a real Playwright browser, hydra and hashcat, driven one
  turn at a time against de-duplicated probes.
- **Persistent lead ledger** — every observation becomes a lead with a priority band,
  claimed as it is tested. The ledger, not the conversation, decides when a run is done, so
  pause/resume/restart never loses work.
- **Observations are findings** — ports, technologies, endpoints, parameters and leaked
  secrets are retained for chaining; a follow-up pass chains findings into exploit paths,
  and a chain is only `confirmed` when a step demonstrated impact.
- **Secret vault** — discovered credentials and keys are stored encrypted, masked
  everywhere else, revealed only on explicit audited action, and reports are masked by
  default (`&secrets=unmasked` for the full variant).
- **Live cockpit** — event stream including prompts and tool actions, live browser frame,
  findings as they land, pause/resume/stop, and Markdown/JSON/HTML/PDF reports.
- **Recovery and schedules** — a heartbeat marks stale runs `interrupted` and can re-queue
  them without losing findings; a run can be cloned on an interval (1 hour to 30 days) and
  each clone reports what is new, resolved and still present versus its predecessor.

Documents: [pentesting engine](docs/docs/operations/pentesting-engine.md) and
[ADR-029](docs/adr/029-pentesting-autonomous-engine.md).

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
| `./setup.sh --update` | Pull the current branch, back up the database, rebuild, migrate and health-check in place. Keeps the previous images for rollback. |
| `./setup.sh --rollback` | Return code **and** images to the state before the last `--update`. |
| `./setup.sh --uninstall` | Stop and remove the stack. Volumes (database), `.env`, `.secrets/` and certificates are **kept** — re-running `./setup.sh` brings it back. |
| `./setup.sh --purge` | Also drop the data volumes and the images built here. A `pg_dumpall` backup is written to `.purge-backups/` first. `.env`, `.secrets/` and `certbot/` survive. |
| `./setup.sh --factory-reset` | Purge plus delete `.env`, `.secrets/` and `certbot/` state — a genuinely clean install, with a fresh certificate next time. |
| `./setup.sh --repair-tls` | Re-create TLS material from `.env` when the UI reports `tls_cert_missing` or "connection closed". |

Teardown is verified rather than assumed: it force-removes containers left by an older
profile generation and the networks they keep busy, and exits non-zero if anything of the
project survives. Re-running the installer after `--uninstall` or `--purge` restores the
stack from the preserved configuration, keeping every non-placeholder secret.

## First run

1. Open the URL the installer printed and sign in with the administrator account it
   created.
2. **Enable Semgrep rules** — Semgrep runs only on ingested rules, so a fresh install
   yields zero Semgrep findings until you open *Admin → Semgrep Config*, click **Load
   built-in sources**, enable one or more sources and **Sync Now**.
3. Optional: add SMTP, extra LLM configurations, SSO/SCIM, or create user groups.
4. Submit a scan and approve the estimates as they appear.
5. For pentesting, open *Pentesting → New engagement*, add the target scope and launch.

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
