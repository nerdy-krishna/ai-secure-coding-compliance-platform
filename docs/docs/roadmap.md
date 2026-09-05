---
sidebar_position: 8
title: Production Roadmap
---

# Production roadmap

This roadmap starts from the application as it exists today. It separates
release blockers from scale and enterprise work; an item listed here is not a
claim that it is already implemented.

## Current baseline

SCCAP already has a FastAPI API, PostgreSQL persistence, a RabbitMQ worker,
LangGraph scan orchestration, deterministic scanners (Semgrep, Bandit,
Gitleaks, and OSV-Scanner), AI analysis/remediation, a React operator UI, SSE
scan events, downloadable HTML/CSV/PDF/SARIF reports, scanner-native JSON,
finding dispositions, user groups, SAML/OIDC SSO, SCIM, passkeys, and an
administrative audit surface.

The `ai-pentester` integration also contains the Pentesting execution path,
operator cockpit, immutable reporting/export, governance overlay, and
fresh-retest workflow. A committed development profile enables explicitly
allowlisted internal fixtures for frontend-driven assessments and ordinary
report downloads. External vault providers, blind-callback receivers,
recipient-encrypted evidence packages, and SIEM delivery are optional future
enterprise integrations; their absence is not a blocker for the core local
product path. Arbitrary target expansion remains out of scope.

The remaining work is primarily correctness under failure, durable evidence,
operator visibility, tenant enforcement, and repeatable enterprise operation.

The API already uses one atomic, outbox-only transaction for submission, approval/decline, resume,
and restart. Cancellation commits its terminal status and event atomically. One declared transition
policy now guards all scan-status writers, and graph checkpoints carry explicit completed-stage
state for resume. The frontend OpenAPI contract is generated and drift-gated in CI. Deterministic
scanner artifacts now append native reports with verified runtime/config digests, exact Semgrep
rule hashes and resolved source commits; bounded provenance is visible in results and exports.

## P0 — release blockers

- Add integration tests around PostgreSQL, RabbitMQ, LangGraph pause/resume,
  cancellation races, report downloads, token refresh, and tenant visibility.
  Keep pure unit tests only for important policy boundaries.
- Keep the implemented frontend OpenAPI generation/drift gate green as endpoint contracts evolve.
- Replace OSV's current live advisory lookup with a dated, hashed offline snapshot. Scanner
  binaries/configs and per-scan Semgrep rules/source commits are already verified and retained;
  OSV is deliberately shown as degraded until the advisory input is equally reproducible.
- Run authenticated browser regressions for login/refresh/logout, submission,
  approval, live activity, cancellation, results, and all report downloads.

## P1 — trustworthy scanning and evidence

### Scan attempts and reports

- Give every run/retry an immutable scan-attempt identifier. Record tool
  version, rule-set digest, configuration digest, selected/skipped files,
  timestamps, exit status, and failure reason per scanner.
- Store native reports and generated exports in encrypted object storage rather
  than growing PostgreSQL rows. Preserve digests, retention policy, tenant,
  attempt, legal-hold state, and a tamper-evident audit record.
- Distinguish a clean scan from skipped coverage, tool failure, parse failure,
  timeout, and truncated output. Surface that coverage manifest in the UI and
  exports.

### Live activity and cancellation

- Version the event schema. Each event needs a sequence/cursor, scan attempt,
  stage, task, event type (`started`, `progress`, `completed`, `failed`,
  `cancel_requested`, `cancel_observed`), safe structured details, and timing.
- Build an operator activity console with stage/scanner/agent filters, progress
  counts, durations, retries, degraded work, approval pauses, and a detail
  drawer. Reconnect from the last cursor without duplicating entries.
- Propagate cancellation into process groups and LLM-provider requests, define
  a cancellation latency SLO, and show requested versus observed cancellation.

### Identity, authorization, and tenancy

- Harden the existing SAML/OIDC and SCIM implementations with signed metadata,
  key rotation, domain ownership, group/role mapping, just-in-time policy,
  deprovisioning tests, and identity-provider conformance suites.
- Replace the coarse user/superuser model with tenant roles and separation of
  duties. Enforce two-person approval for high-cost scans; the existing flag is
  informational only.
- Centralize tenant predicates and add database-level isolation where feasible.
  Every list, export, event stream, artifact, search, and background task must
  prove its tenant scope.
- Add server-side session inventory, refresh-token rotation/reuse detection,
  revocation, idle/absolute lifetime, device visibility, and administrator
  termination. Evaluate a backend-for-frontend/HttpOnly access-token model to
  remove the current local-storage exposure.

## P2 — AI-to-static rule foundry

AI findings must not be promoted directly into production scanner rules. The
learning loop should be reviewable and measurable:

1. Start from a confirmed AI-only finding with stable evidence, CWE, root
   cause, data-flow facts, language, framework, and preconditions.
2. Produce a candidate Semgrep rule (prefer taint mode when appropriate) plus
   vulnerable, fixed, and negative fixtures. Secret-pattern candidates may
   target Gitleaks; dependency issues belong in an advisory feed rather than a
   regex rule.
3. Validate candidates in an isolated sandbox against the fixtures and a
   representative clean/vulnerable corpus. Measure precision, recall,
   performance, duplicate rate, and rule churn.
4. Require security-reviewer approval and a signed, versioned registry entry.
   Scope rules to tenant, technology, and language; deploy first in shadow mode.
5. Promote only after quality thresholds and observed telemetry. Support rapid
   rollback, expiry, supersession, and feedback from false positives, false
   negatives, and remediation regressions.

Semantic findings that cannot be represented faithfully should remain AI
checks or move to a purpose-built data-flow analyzer. Never weaken a finding
into a broad regex merely to claim scanner learning. Treat repository content
as untrusted prompt input and prevent generated rules from executing arbitrary
code or being promoted autonomously.

## P2 — frontend and integration maturity

- Make finding pages evidence-first: source ranges, trace, scanner/AI
  provenance, rule version, triage history, remediation diff, verification,
  and stable lineage identifiers.
- Add baselines and “new/fixed/unchanged” PR views, policy gates, waivers, and
  portfolio trend/drill-down views.
- Complete accessibility, keyboard, responsive, and design-token audits. Split
  large routes and visualizations to reduce the current main bundle.
- Add service accounts/OAuth scopes, signed webhooks, GitHub/GitLab/Azure
  DevOps/Bitbucket CI templates, SARIF upload, ticketing, and SIEM integrations.

## P2/P3 — enterprise operations

- Package stateless APIs and specialized worker pools for Kubernetes with
  queue-based autoscaling, disruption budgets, safe migrations, and staged
  rollout/rollback.
- Add OpenTelemetry traces/metrics/log correlation, SLO dashboards, alerts,
  queue/backlog and provider-budget controls, and documented incident runbooks.
- Use a secrets manager/KMS with rotation; produce SBOMs, signed images,
  provenance, vulnerability gates, and repeatable offline scanner-data updates.
- Define backup/restore drills, RPO/RTO, regional/tenant retention, legal hold,
  data export/deletion, and disaster recovery.
- Performance-test large repositories, concurrent tenants, event replay,
  artifact downloads, and degraded dependencies before an enterprise release.

## Exit criteria for an enterprise pilot

An enterprise pilot should not begin until P0 is complete, no known cross-
tenant access path remains, cancellation and session-longevity SLOs pass under
load, every scanner outcome has auditable evidence, backup/restore has been
demonstrated, and the supported SSO/SCIM provider matrix passes automated
conformance tests.
