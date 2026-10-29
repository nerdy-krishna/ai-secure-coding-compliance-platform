# SCCAP — Secure Coding & Compliance Automation Platform

An open-source, AI-powered platform that helps developers and security
teams audit code for vulnerabilities and apply intelligent
remediations. SCCAP follows an **"Audit-First, Remediate-Intelligently"**
approach: every scan runs a cheap deterministic pass, profiles each
file, surfaces explicit cost estimates, and waits for your approval at
each gate before spending on the deep analysis. Remediation is a
separate, opt-in step.

## Key Features

### For developers and security users
- **Live dashboard** — risk ring, severity breakdown, 14-day scan
  trend, fixes-ready counter, and monthly LLM spend, all driven by real
  data (no placeholders). Admins see a platform-wide snapshot variant.
- **Versatile submission** — upload individual files, pick a Git
  repository URL, or drop in a `.zip` / `.tar.gz` archive. GitHub
  repos are previewed via the GitHub API (no clone required for
  source-tree listing). The selective-files tree lets you exclude
  what you don't want analyzed.
- **Gated, user-approved scan** — the worker pauses the LangGraph
  workflow with native `interrupt()`s at up to three gates: a
  deterministic-prescan review, a profiling-cost approval, and the
  deep-analysis cost approval. Nothing expensive runs without your
  explicit OK.
- **Per-file profiler + baseline-aware routing** — before analysis,
  every file is profiled (summary, security-relevant operations,
  applicable security domains) on a cheap *utility* model, with the
  prompt grounded in the file's tree-sitter symbol index. Routing then
  unions a deterministic, human-curated **per-language baseline** of
  agents with the profiler's content picks — so an agent that should
  always run for a language can never be silently dropped — and the
  cost estimate reflects that routed set.
- **Consolidated findings** — a reasoning-model consolidation pass
  merges the raw per-agent findings into one root finding per real
  issue: it leads with the root cause and fix, lists every affected
  location, carries corroborating agents, and drops false positives
  and noise. No more duplicate rows for the same bug.
- **Opt-in cross-file validation** — enable it at submit time and each
  eligible finding is re-judged against the code that calls and feeds
  it across other files. The non-destructive verdict (`confirmed` /
  `mitigated` / `unconfirmed` + a rationale) collapses upstream-
  mitigated findings out of the default Results view and badges the
  confirmed ones — no severity is ever changed.
- **Downloadable findings report** — export any scan's findings as a
  self-contained HTML page, a CSV (one row per finding), a paginated PDF,
  or SARIF 2.1.0 for GitHub code scanning, straight from the Results page.
- **Remediation scan mode** — choose `REMEDIATE` when submitting a
  scan to have agents generate fixes during analysis, merge conflicting
  edits, verify supported patches, and produce a downloadable patched
  snapshot. Post-result selection and incremental apply are not yet
  implemented.
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
- **Compliance page** — per-framework coverage card for each of the 8
  bundled OWASP frameworks (ASVS, Proactive Controls, Cheatsheets, CWE
  Essentials, ISVS, LLM Top 10, Agentic Top 10, MASVS) plus any custom
  frameworks, with an AI-computed posture score.
- **Multi-provider LLM support** — OpenAI, Anthropic, Google, DeepSeek,
  xAI, and custom OpenAI-compatible endpoints. Each scan is configured with two slots: a *utility* (cheap)
  model for profiling and verification, and a *reasoning* (capable)
  model for analysis and consolidation, plus a per-stage temperature
  (profiler / analysis / consolidation / merge) tunable at submit
  time. API keys are Fernet-encrypted server-side.
- **Dual-reasoning-LLM scans** — optionally add a *second* reasoning
  LLM: every analysis agent then runs on both models and the findings
  union, so a vulnerability one model misses the other may catch. Each
  finding records which model(s) detected it. The second model takes
  its own analysis temperature, so "same model, two temperatures" is a
  valid diversity strategy. You can also disable the temperature
  setting entirely and let each model run at its provider default.
- **Durable tasks & resume/restart** — every analysis and consolidation
  invocation is persisted as a durable scan task keyed by input hash.
  Failed or interrupted scans can be manually **resumed** (reuses
  completed durable work) or **restarted** (discards partial
  artifacts, reruns from the original snapshot), preserving full
  audit history either way.
- **File classification & vendor/minified policy** — every submitted
  file is deterministically classified before analysis. Vendor,
  minified, and static assets skip expensive LLM profiling and full
  agent routing by default while keeping cheap SAST checks active.
  An advanced **deep vendor scan** option gives full LLM inspection
  when needed, reflected in cost and time estimates.
- **Per-config resilience controls** — scan LLM calls use a fixed
  concurrency pool per configuration, per-config RPM/TPM budgets,
  retry with jitter, and circuit breakers. Configured prompt-size caps
  reject oversized calls; automatic prompt splitting/compaction is
  planned rather than implemented.

### For security admins
- **User Groups + scoped visibility** — an admin creates groups and
  adds users by email; a regular user sees their own scans plus any
  scan owned by a peer they share a group with. Admins see everything.
- **Terminal-only first run** — `setup.sh` asks for the administrator
  email/password, the LLM provider/model/key, the Grafana administrator
  (when the log stack is on) and — for the custom variant — the feature
  set. It bootstraps the superuser, LLM configuration, CORS allowlist and
  feature flags before the UI is ever opened, so there is no second
  in-browser setup step.
- **Modular feature flags** — every optional surface (chat, compliance,
  SSO, SCIM, multi-tenancy, the log stack, …) is a runtime flag. The
  install variant seeds them; *Admin → Features* toggles them live, with
  dependencies resolved automatically. See
  [Modular Setup](docs/docs/architecture/modular-setup.md).
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

### Pentesting (opt-in, feature-gated)

A separately gated **Pentesting** bounded context adds authorized black-box,
gray-box, and white-box engagements alongside Code Scan, without ever
mutating the Code Scan aggregate:

- **Project-linked engagements** — pentest projects own their scope,
  KMS-envelope-encrypted credentials, and an immutable Code Scan snapshot
  selected through a read-only white-box bridge. Read APIs never return
  credential material.
- **Deterministic safety model** — every target interaction requires
  authorization, tenant/attempt identity, and a pinned deterministic
  scope-policy decision. A generation-fenced lease fences stale workers and
  an atomic Execution commit makes results authoritative; RabbitMQ is
  notification-only.
- **Exact-origin tracer → isolated gateway → bounded controller** — from a
  harmless public-only HTTP/TLS tracer through a pinned-egress,
  credential-minimal runner to an adaptive controller that consumes only
  committed `DecisionDelta` projections.
- **Deterministic Web/API tool pack** — a Tool Broker and relay grants drive
  nmap, nuclei, ZAP, and Playwright adapters with pinned egress, connection
  permits, and typed proposals/results.
- **Finding truth** — evidence-backed Observations become ConfirmedFindings
  only through a configured evidence predicate or independent reproduction;
  a scanner, adapter, specialist, or model can never confirm directly.
- **Cockpit, reports, and governance** — engagement/attempt/delta cockpit,
  immutable reports, redacted exports, retesting, and a governance overlay.

Pentesting is off by default and enabled through the local development
profile (`docker-compose.pentesting-local.yml`). See
`docs/docs/operations/pentesting-adaptive-controller.md`.

### Integrations and automation
- **MCP server** — the scan + advisor workflow is exposed as MCP tools
  (`sccap_submit_scan`, `sccap_get_scan_status`,
  `sccap_get_scan_result`, `sccap_approve_scan`,
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

1. **Submit** code (upload, Git URL, or archive) and pick frameworks,
   the two LLM slots (utility + reasoning), the per-stage temperatures,
   and — optionally — a second reasoning LLM, cross-file finding
   validation, or disabling the temperature setting altogether.
2. **Pre-LLM scan** — deterministic SAST (Bandit · Semgrep · Gitleaks ·
   OSV) builds a repo map + dependency graph and runs first. If it
   finds anything the scan pauses at `PENDING_PRESCAN_APPROVAL` so you
   can review the deterministic findings before any code is sent to an
   LLM. Critical secrets need an explicit override to continue.
3. **File classification** — every submitted file is deterministically
   classified (first-party source, minified bundle, known/unknown
   third-party vendor, generated asset, static asset). The resulting
   policy skips LLM profiling and full agent routing for low-value
   vendor/minified/static files by default while keeping Gitleaks active.
   An advanced **deep vendor scan** option is available at submit time
   for deeper inspection of vendor code.
4. **Profiling gate** — the scan pauses at `PENDING_PROFILING_APPROVAL`
   with a profiling-cost estimate. On approval, eligible files are
   profiled on the utility model: a summary, its security-relevant
   operations, and the security domains that apply to it.
5. **Cost gate** — a dry run, scoped to each file's routed agent set
   (the per-language baseline unioned with the profiler's picks),
   produces the deep-analysis cost and estimated processing duration.
   The scan pauses at `PENDING_COST_APPROVAL`. With a second reasoning
   LLM configured the estimate is priced on both models, broken down
   per LLM.
6. **Approve** (or cancel) each gate in the UI. A live SSE stream
   surfaces estimates and reconnects through token expiry; the worker
   resumes the same LangGraph thread from the checkpoint.
7. **Analyze** — specialized agents run in parallel under a fixed
   per-LLM-configuration concurrency pool, bound by per-config RPM/TPM
   limits and circuit breakers. Each analysis invocation is a
   **durable task** persisted in a scan-scoped task ledger — if the
   worker is interrupted, completed analysis chunks are reused on
   resume rather than re-invoked. If a second reasoning LLM was
   chosen, every agent runs on both models and the findings union.
8. **Consolidate (per-file)** — a reasoning-model pass merges
   same-root-cause findings per file into one root finding per real
   issue and drops false positives and noise. Each finding records
   which reasoning LLM(s) detected it. Per-file consolidation is also
   a durable task, reusable on resume.
9. **Global consolidation** — deterministic exact-field grouping
   merges cross-file findings that share normalized source, CWE, title,
   and remediation. Broader LLM-assisted root-cause clustering is not
   yet implemented.
10. **Cross-file validation (opt-in)** — if enabled at submit, each
    eligible finding is re-judged against its cross-file callers and
    inputs, attaching a non-destructive `confirmed` / `mitigated` /
    `unconfirmed` verdict.
11. **Review** findings in the Results page — both deterministic and
    LLM-emitted, tagged by source — and download the report as HTML,
    CSV, PDF, or SARIF 2.1.0.
12. **Remediate** — scans submitted in `REMEDIATE` mode merge generated
    fixes, verify supported patches, and save a patched tree for download.
13. **Resume or restart** — failed scans (and eligible cancelled scans
    with durable artifacts) can be manually resumed (reuses completed
    durable work) or restarted (discards partial artifacts, reruns
    from the original snapshot). Both preserve audit history.

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

The interactive script checks prerequisites, generates secrets, asks
which **installation variant** to use, writes `.env` (including
`SCCAP_VARIANT` and `COMPOSE_PROFILES`), builds + starts the compose
stack, and runs Alembic migrations. The UI is built inside its Docker
image — Node.js is not a host prerequisite. On Windows, run `setup.bat`
from the project root. Re-running either installer after an upgrade preserves
every non-placeholder secret and safely adds newly required values.

For a non-interactive upgrade, repair the existing file before the first
Compose command:

```bash
python3 scripts/bootstrap_env_secrets.py --env-file .env
docker compose config --quiet
```

The bootstrap writes `.env` atomically, applies mode `0600` where POSIX modes
are available, and reports only how many values changed; it never prints
generated values.

### Installation variants

`setup.sh` asks which packaging variant to install:

- **Vibe coder** — scan, chat, and compliance only; a single superuser.
- **Developer** — adds multi-user accounts, groups, email, the MCP
  surface, and admin authoring.
- **Enterprise** — every feature, including SSO, SCIM, multi-tenancy,
  and the log stack.
- **Custom** — pick the optional container stacks in `setup.sh`, then the
  individual features in `setup.sh`.

The variant seeds a set of runtime feature flags and selects which
optional container stacks boot (`COMPOSE_PROFILES`). Change features
later under *Admin → Features*. See
[Modular Setup](docs/docs/architecture/modular-setup.md).

### Manual setup

See the [Installation Guide](docs/docs/getting-started/installation.md)
for the step-by-step path, including VPS-specific notes and
troubleshooting.

### Upgrading, uninstalling and clean reinstalls

`setup.sh` takes no arguments for a normal install. It also manages teardown,
and offers the same choices as a menu when it detects an existing installation:

```bash
./setup.sh                    # install, upgrade, or re-run setup
./setup.sh --uninstall        # stop and remove the stack; data, .env, keys
                              # and certificates are kept
./setup.sh --purge            # also drop data volumes and the images built
                              # from this checkout; a pg_dumpall backup is
                              # written to .purge-backups/ first
./setup.sh --factory-reset    # purge plus delete .env, .secrets/ and certbot/
                              # — a true clean install (fresh certificate)
```

Add `-y` to skip the confirmation prompts (each level asks you to type the
action name, and `--purge`/`--factory-reset` are not recoverable without the
backup). Re-running `./setup.sh` after `--uninstall` or `--purge` brings the
stack back using the preserved configuration.

Ownership is handled for you: `.env` and `.setup-stage` end up owned by the
operating user (with `0600`/`0700` modes) even when the script runs under
`sudo`, while container-writable paths (Let's Encrypt state, the pentest
result-signing key) are handed to the UIDs the containers run as.

## Getting Started

1. **Log in** at the URL the setup script printed (default
   `http://localhost`) with the administrator email and password you gave
   the terminal installer. The superuser, default LLM configuration and
   feature flags were already created during setup.
2. **Optional afterwards** — add SMTP, extra LLM configurations or adjust
   system settings under *Admin*.
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
WeasyPrint (PDF reports) · fastapi-users (JWT Bearer) · Postgres 16 ·
RabbitMQ · Qdrant (fastembed `all-MiniLM-L6-v2`) · Fluentd → Loki →
Grafana · React 18 + Vite + TypeScript · custom SCCAP UI primitives · TanStack Query ·
React Router v7 · nmap / nuclei / ZAP / Playwright (pentesting tool pack).

Full breakdown in
[`docs/docs/overview/technology-stack.md`](docs/docs/overview/technology-stack.md).

## Contributing

See [`docs/docs/development/contributing.md`](docs/docs/development/contributing.md).
Issues and PRs welcome.

## License

Licensed under the Apache License, Version 2.0. See [`LICENSE`](./LICENSE) for the full text and [`NOTICE`](./NOTICE) for attribution.
