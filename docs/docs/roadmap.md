---
sidebar_position: 8
title: Production Status and Roadmap
---

# Production status and roadmap

This is the **single source of truth** for what SCCAP has implemented and what
remains pending. Operational runbooks explain *how* to deploy and qualify a
subsystem; they do not restate status. If an operational page and this page
disagree, this page is stale — fix it here.

!!! warning "Verification level"
    "Implemented" below means the module, migration, endpoint, test, or CI job
    **exists in the tree**. It does not mean the path has been demonstrated
    end-to-end in a running deployment. Where a boundary is only partially built,
    it is listed under *Pending* rather than claimed here.

## Current baseline

SCCAP runs a FastAPI API, PostgreSQL persistence, a RabbitMQ worker with outbox-only
publishing, LangGraph scan orchestration, deterministic scanners (Semgrep, Bandit,
Gitleaks, OSV-Scanner), AI analysis and remediation, a React operator UI, SSE scan
events, and downloadable HTML/CSV/PDF/SARIF reports.

| Area | Implemented |
| --- | --- |
| Durable orchestration | Atomic submission/approval/decline/resume/restart; outbox sweeper as sole publisher; one declared transition policy over all status writers; failed/cancelled recovery sweepers |
| Deterministic scanning | Semgrep, Bandit, Gitleaks, OSV-Scanner; native reports with runtime/config digests and exact rule hashes; OSV replayed from a dated offline snapshot (`infrastructure/scanners/osv_offline_replay.py`, `docker-compose.osv-offline.yml`) |
| Scan attempts | Immutable attempt identifier per run/retry; per-attempt tool version, rule-set and config digests, exit status and failure reason |
| Coverage | `scanner_coverage_entries` manifest separating clean from `planned`/`skipped`/`failed`/`timeout`/`unsupported`/`truncated`; terminal outcomes carry reason, finding count, native-evidence availability and provenance; policy evaluation plus append-only waivers |
| Evidence | Encrypted immutable object storage, per-object digests, versioning, retention and legal hold, tamper-evident governance records, orphan reconciliation |
| Findings | Evidence-first governance record with source ranges, attempt, evidence/coverage ids, provenance, consolidation lineage; `new`/`unchanged`/`reintroduced`/`fixed` baselines; versioned blocking policy gates and waivers; portfolio trend |
| Live activity | Versioned scan events (`schema_version`, `activity_kind`, `attempt_id`); monotonic cursor with `Last-Event-ID` / `last_event_id` / `cursor` reconnect; cancellation phases with requested-versus-observed states |
| Identity and tenancy | SAML/OIDC, SCIM, passkeys; server-side `AuthSession` with idle and absolute expiry, revocation, credential-generation replay detection, device (user-agent) visibility; `RoleAssignment` tenant roles; enforced separation of duties (`off`/`critical`); forced tenant RLS with non-owner runtime roles |
| Rule foundry | Governed AI-to-static promotion: candidate generation, fixture validation, precision/recall scoring, reviewer approval, versioned registry, shadow deployment, rollback |
| Integrations | Signed SIEM delivery, Jira ticket identity, CI policy endpoints and SARIF output |
| Operations | Kubernetes 1.30+ Helm chart with KEDA queue autoscaling; OTLP traces/metrics with W3C correlation; Prometheus rules and SLOs; backup/restore and degradation runbooks |
| Local gates | Backend ruff/black + pytest, frontend test+lint+build with deterministic bundle budgets, generated OpenAPI drift (`check:api`), Poetry lock drift, Bandit, pip-audit, Gitleaks, and a Postgres+RabbitMQ+worker integration run covering gate resume and outbox recovery — all invoked from the operator shell; the repository has no CI service |

### Pentesting engine

Replaced wholesale (ADR-029). The controller,
qualification, signed-task and work-ledger stack described by ADR-013 to ADR-028
was deleted; ADR-029 is authoritative.

| Area | Implemented |
| --- | --- |
| Run orchestration | One engine container polling PostgreSQL; no broker, outbox, signed task, lease or checkpointer; one run at a time; pause/resume/stop honoured inside in-flight model calls and subprocesses |
| Reconnaissance | Evasive 1 s-spaced pass: HTTP probe, technology fingerprint, TLS, nmap top-1000, directory crawl |
| Attack-surface discovery | Subdomain enumeration across six passive indexes plus rate-limited DNS brute-force and dangling-CNAME takeover checks; vhost and S3-bucket enumeration (gobuster); OpenAPI/Swagger parsing; GraphQL introspection; JavaScript bundle mining for endpoints, parameters, source maps and secrets |
| Scanner coverage | Every installed scanner is a tool: nmap, nuclei, ZAP, sqlmap, ffuf, gobuster (vhost/DNS/S3), whatweb product/version fingerprinting, hydra credential attacks, hashcat hash cracking, plus the Playwright browser |
| Scope | Registrable-domain derivation, in-scope subdomains accepted, everything else refused; private/loopback destinations refused |
| Model loop | Structured `NextAction` per turn (1–4 parallel tool calls, claimed leads, new leads, negative conclusions); normalised probe de-duplication; stuck-loop detection |
| Lead ledger | Persistent `pentest_leads` queue with priority bands; claims on test; failed probes returned to the queue; `done` refused while testable leads remain |
| Findings | Weaknesses and surface observations both persisted (`category`); no finding discarded for being non-exploitable |
| Captured credentials | Encrypted `pentest_secrets` vault scoped to tenant + run + row; masked everywhere else (`AKIA…MPLE`, `••••••••`); explicit reveal/copy that is counted, timestamped and recorded as a run event; reports default to masked with an explicit unmasked variant |
| Finding quality | CVSS 3.1 vector + base score derived deterministically with severity from the score band; cross-tool consolidation with provenance and audit-retained duplicates; per-finding PoC replay recording `exploitable`/`not_exploitable`/`needs_review` plus the exact reproducing request |
| Recovery and re-scans | Heartbeat per running run; stale runs are reclaimed as `interrupted` (at startup and by watchdog), restart re-queues with findings/leads/recon reused; schedules clone a run template on an interval and each scheduled run is diffed against its predecessor (new/resolved/persisting) |
| Exploit chaining | Iterative loop: hypothesis → one tested step → observed result → advance/confirm/abandon; `confirmed` requires demonstrated impact; each chain stores its steps and a runnable PoC, is attached to the findings it links, and is rendered in every report |
| Reporting | Markdown, JSON, HTML, PDF with an observations appendix |
| UI | Live event stream including prompts and tool actions, findings as they land, lead queue, live browser frame, controls, report downloads |

## Pending

### Release blockers

- **Pentest engine not yet exercised on a live target.** The engine replaced the
  controller stack; discovery, the lead queue,
  observation persistence and the chain pass are implemented and unit-verified, but
  no full assessment against a real target has been run on a deployed installation
  since the replacement.
- **Non-owner forced-RLS qualification.** The qualification lane proves query
  scope, not enforced row-level security under a non-owner runtime role.
- **Precommit crash/cancellation persistence.** Native cancellation retains only
  an in-memory reservation; whole-assessment precommit crash and cancellation
  recovery still require fault-injection tests.
- **Real-broker and middleware coverage in the product lane.** The worker/product
  qualification lane omits real RabbitMQ delivery/recovery, HTTP login/CSRF
  middleware, and a real cockpit browser.

### Trustworthy scanning and evidence

- Harden SAML/OIDC and SCIM against signed metadata, key rotation, domain
  ownership, group/role mapping, just-in-time policy, deprovisioning, and
  provider conformance suites.
- Enforce two-person approval for high-cost scans. Separation of duties is
  enforced for role combinations; the high-cost scan gate is not yet covered.
- Extend database-level isolation beyond forced RLS to the remaining background
  and export paths.
- Evaluate a backend-for-frontend / HttpOnly access-token model to remove the
  current local-storage exposure.
- **Test-Validated Remediation** ([details](user-guide/unit-test-integration.md))
  is not implemented: SCCAP does not yet run the project's existing test suite
  against an AI-generated fix before applying it, so fixes that break tests can
  still be proposed.

### Frontend and integration maturity

- Complete accessibility, keyboard, responsive and design-token audits; continue
  splitting large routes and visualizations to hold the bundle budgets.
- Service accounts and OAuth scopes, signed webhooks, GitHub/GitLab/Azure
  DevOps/Bitbucket CI templates, and expanded ticketing surfaces.

### Enterprise operations

- Complete KMS/secret-manager rotation, SBOM and signed-image provenance gates,
  and repeatable offline scanner-data updates.
- Define and drill RPO/RTO, regional and tenant retention, legal-hold, data
  export/deletion, and disaster recovery.
- Performance-test large repositories, concurrent tenants, event replay,
  artifact downloads and degraded dependencies before an enterprise release.

## Retired claims

Earlier revisions of this page listed the following as pending. They are
implemented; the entries are kept only so the change is traceable.

- OSV live advisory lookup → replaced by the dated offline snapshot.
- Scan-attempt identifier, coverage manifest, and encrypted object storage for
  reports and exports.
- Versioned event schema with cursor-based reconnect.
- Server-side session inventory, revocation, idle/absolute lifetime, device
  visibility.
- "Two-person approval is informational only" → separation of duties is enforced.
- AI-to-static rule foundry.
- Evidence-first finding pages, baselines, policy gates, waivers, portfolio trend.
- OpenTelemetry traces/metrics/log correlation and Kubernetes worker pooling.

Two long-standing claims were also checked and found stale: documentation build
and generated-OpenAPI drift used to be enforced by GitHub Actions (`docs.yml`,
`ci.yml` `check:api`), which are no longer part of this repository — run
`npm --prefix secure-code-ui run check:api` before merging — and the product roadmap no longer depends on
`.scratch/pentesting-full-vision/GAP_REGISTER.md`, which was superseded by the
committed ADRs.

## Exit criteria for an enterprise pilot

A pilot should not begin until the release blockers above are closed, no known
cross-tenant access path remains, cancellation and session-longevity SLOs pass
under load, every scanner outcome has auditable evidence, backup/restore has been
demonstrated, and the supported SSO/SCIM provider matrix passes automated
conformance tests.
