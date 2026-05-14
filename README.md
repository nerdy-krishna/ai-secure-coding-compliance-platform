# SCCAP — Secure Coding & Compliance Automation Platform

An open-source, AI-powered platform that helps developers and security
teams audit code for vulnerabilities and apply intelligent
remediations. SCCAP follows an **"Audit-First, Remediate-Intelligently"**
approach: every scan runs a cheap preliminary pass, surfaces an
explicit cost estimate, and waits for your approval before spending on
the deep analysis. Remediation is a separate, opt-in step.

## Key Features

### For developers and security users
- **Live dashboard** — risk ring, severity breakdown, 14-day scan
  trend, fixes-ready counter, and monthly LLM spend, all driven by real
  data (no placeholders). Admins see a platform-wide snapshot variant.
- **Versatile submission** — upload individual files, pick a Git
  repository URL, or drop in a `.zip` / `.tar.gz` archive. The
  selective-files tree lets you exclude what you don't want analyzed.
- **Two-phase, user-approved scan** — the API publishes a job, the
  worker runs a cheap *audit* pass to estimate cost, pauses the
  LangGraph workflow with a native `interrupt()`, and waits for the UI
  to approve before the expensive deep analysis runs.
- **Intelligent remediation** — pick findings, let the multi-agent
  system generate code fixes, and download the patched codebase as a
  zip. Remediation runs incrementally with a merge agent to resolve
  file conflicts.
- **Projects page with per-project stats** — every card shows the
  latest terminal scan's risk score, severity bar, and fixes-ready
  count, no client-side heuristics.
- **Global search** — one TopNav combobox searches projects, scans,
  and findings simultaneously; scoped to what each user is allowed to
  see.
- **Security Advisor with a live context rail** — framework-scoped
  chat against your RAG-ingested guidelines, with a right-hand rail
  that surfaces the knowledge sources, referenced findings, and files
  most likely discussed.
- **Compliance page** — per-framework coverage card for each of the 3
  default OWASP frameworks (ASVS, Proactive Controls, Cheatsheets)
  plus any custom frameworks, with an AI-computed posture score.
- **Multi-provider LLM support** — OpenAI, Anthropic, and Google
  configured per slot (utility / fast / reasoning) with encrypted API
  keys stored server-side.

### For security admins
- **User Groups + scoped visibility** — an admin creates groups and
  adds users by email; a regular user sees their own scans plus any
  scan owned by a peer they share a group with. Admins see everything.
- **First-run setup wizard** — the first registered user becomes
  superuser and is routed through `/setup` to configure LLMs, SMTP,
  and system settings before the app unlocks for everyone else.
- **Admin console** — LLM configurations, user groups, users,
  frameworks (including CSV / git-URL RAG ingestion), agents, prompt
  templates, system config, SMTP, and runtime logs. A shared Admin
  sub-nav keeps every surface one click apart.
- **Semgrep Rule Ingestion** — admins configure public git repos as
  rule sources via a dedicated *Semgrep Rules* tab. Rules are stored in
  Postgres; syncs run on demand or on a configurable cron schedule.
  Semgrep runs exclusively on DB-ingested rules — no bundled pack. The
  submission page shows a live Scan Readiness panel; if no rules cover
  the detected languages, a single-step wizard prompts the admin to
  enable a source before submitting.
- **Encrypted secrets** — every LLM API key and SMTP password is
  Fernet-encrypted at rest with the installation's `ENCRYPTION_KEY`.

### Integrations and automation
- **MCP server** — the scan + advisor workflow is exposed as MCP tools
  (`sccap_submit_scan`, `sccap_get_scan_status`,
  `sccap_get_scan_result`, `sccap_approve_scan`, `sccap_apply_fixes`,
  `sccap_ask_advisor`) at `/mcp`, reusing JWT auth so Claude Code,
  Cursor, or other agentic clients can drive the platform remotely.
- **LiteLLM-backed cost ledger** — token counting and cost estimation
  go through LiteLLM's community-maintained model price map, with an
  admin override per `LLMConfiguration` row for bespoke endpoints.
  Offline-pinnable via `LITELLM_LOCAL_MODEL_COST_MAP=True`.
- **Pydantic AI structured output** — every agent returns a validated
  Pydantic model; malformed outputs trigger a typed retry loop inside
  the model call instead of a fragile regex fallback.
- **Observability** — every request gets an `X-Correlation-ID`
  attached to all logs; the stack ships Fluentd → Loki → Grafana
  dashboards out of the box.

## How It Works

1. **Submit** code (upload, Git URL, or archive) and pick frameworks +
   LLM slots.
2. **Pre-LLM scan** — deterministic SAST (Bandit · Semgrep · Gitleaks ·
   OSV) builds a repo map + dependency graph and runs first. If it
   finds anything the scan pauses at `PENDING_PRESCAN_APPROVAL` so you
   can review the deterministic findings before any code is sent to an
   LLM. Critical secrets need an explicit override to continue.
3. **Estimate** — once you continue past the prescan gate, a dry run
   produces an explicit cost estimate. The scan pauses at
   `PENDING_COST_APPROVAL`.
4. **Approve** (or cancel) in the UI. Live SSE stream surfaces the
   estimate and reconnects through token expiry; the worker resumes
   the same LangGraph thread from the checkpoint.
5. **Analyze** — triaged specialized agents run in parallel (five at a
   time under `CONCURRENT_LLM_LIMIT`) in topological dependency order.
6. **Review** findings in the Results page — both deterministic and
   LLM-emitted, tagged by source.
7. **Remediate** — select findings, apply fixes incrementally with a
   merge agent to resolve conflicts, then download the patched tree.

The full worker graph and state transitions live in
[`.agent/scanning_flow.md`](.agent/scanning_flow.md).

## Installation

### Automatic setup (recommended)

```bash
git clone https://github.com/nerdy-krishna/ai-secure-coding-compliance-platform.git
cd ai-secure-coding-compliance-platform
chmod +x setup.sh
./setup.sh
```

The interactive script checks prerequisites, generates secrets, writes
`.env`, builds + starts the compose stack, runs Alembic migrations, and
installs the UI dependencies. On Windows, run `setup.bat` from the
project root.

### Manual setup

See the [Installation Guide](docs/docs/getting-started/installation.md)
for the step-by-step path, including VPS-specific notes and
troubleshooting.

## Getting Started

1. **Open the app** at the URL the setup script printed (default
   `http://localhost`). The first account you register becomes
   superuser and is routed to `/setup`.
2. **Finish setup** — add at least one LLM configuration, optional
   SMTP, and any system settings you need. The `/setup` wizard blocks
   the rest of the app until this is done.
3. **Create user groups (optional)** — under *Admin → Groups*, grant
   teams of users visibility into each other's scans.
4. **Enable Semgrep rules (post-deploy)** — Semgrep runs exclusively
   on rules ingested from public rule repos (no bundled pack). On a
   fresh deploy Semgrep produces zero findings until an admin enables
   at least one source. Go to *Admin → Frameworks → Semgrep Rules tab*,
   click **Load built-in sources**, enable one or more sources, and
   click **Sync Now**. See
   [`docs/rule-source-ingestion.md`](docs/rule-source-ingestion.md) for
   the full operator guide.
5. **Submit a scan** from *Submit*, approve the cost estimate, and
   review findings when analysis completes.
6. **Ask the Advisor** — start a conversation from *Advisor*,
   optionally scoped to a project so the context rail surfaces the
   relevant findings and files.

## Stack

Python 3.12 + FastAPI + Poetry · SQLAlchemy async + Alembic ·
LangGraph 1.x + LangChain 1.x · LiteLLM · Pydantic AI · FastMCP ·
fastapi-users (JWT Bearer) · Postgres 16 · RabbitMQ · Qdrant
(fastembed `all-MiniLM-L6-v2`) · Fluentd → Loki → Grafana · React 18 + Vite
+ TypeScript · Ant Design · TanStack Query · React Router v7.

Full breakdown in
[`docs/docs/overview/technology-stack.md`](docs/docs/overview/technology-stack.md).

## Contributing

See [`docs/docs/development/contributing.md`](docs/docs/development/contributing.md).
Issues and PRs welcome.

## License

Licensed under the Apache License, Version 2.0. See [`LICENSE`](./LICENSE) for the full text and [`NOTICE`](./NOTICE) for attribution.
