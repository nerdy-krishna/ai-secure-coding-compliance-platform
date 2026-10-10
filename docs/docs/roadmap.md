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
| CI gates | Backend ruff/black, frontend test+lint+build with deterministic bundle budgets, authenticated Playwright lifecycle, generated OpenAPI drift (`check:api`), Poetry lock drift, Bandit, pip-audit, Gitleaks, and a Postgres+RabbitMQ+worker integration job covering gate resume and outbox recovery |

### Pentesting integration

Foundations 0–3 and Capabilities 4–13 are implemented: bounded-context contracts,
exact-origin tracer, durable execution and evidence commit, deterministic scope
gateway, adaptive controller, initial Web/API tool pack, identity-aware
verification, white-box Code Scan integration, canonical test catalog and
coverage, reversible mutations with cleanup, asynchronous callback correlation,
the private-network execution runner contract, the operator cockpit with
reports/governance/retesting, the target-agnostic iterative local loop, and the
threat-model/business-invariant workflow.

Of the 21 registered capability profiles, 19 now carry a successor adapter
(`graphql_observe.v1`, `realtime_observe.v1`, `active_validation.v1`,
`authorization_readonly.v1`, `file_upload_validation.v1`,
`codescan_source_facts.v2`, and the passive native pack). The remaining two are
listed under *Pending* below.

See [capability activation](operations/pentesting-capability-activation.md) for
deployment overlays and [local audit qualification](operations/pentesting-local-audit-qualification.md)
for qualification lanes.

## Pending

### Release blockers

- **No demonstrated end-to-end engagement.** The 2026-09-12 black-box run against
  the Juice Shop fixture blocked at `PENTEST_PROFILE_UNAVAILABLE` before any
  model call, because the controller container had `PENTEST_CAPABILITY5_ENABLED=false`
  while the API had `true`. The Compose overlays now set the flag consistently on
  both services, but the path has **not** been re-run. Readiness reporting,
  `model_blocked` not propagating to engagement state, retries that do not
  increment `retry_count`, and the ambiguous bootstrap request count all remain
  unverified.
- **Non-owner forced-RLS qualification.** The qualification lane proves query
  scope, not enforced row-level security under a non-owner runtime role.
- **Precommit crash/cancellation persistence.** Native cancellation retains only
  an in-memory reservation; whole-assessment precommit crash and cancellation
  recovery still require fault-injection tests.
- **Real-broker and middleware coverage in the product lane.** The worker/product
  qualification lane omits real RabbitMQ delivery/recovery, HTTP login/CSRF
  middleware, and a real cockpit browser.

### Pentest capability activation

- **`authentication` and `session_management` profiles** have no Capability 4
  successor. They resolve through C6/C7 runtime health
  (`services/profile_registry.py`), so they stay unselectable until that runtime
  is deployed and reports qualified health.
- **Step rehydration.** V3 refuses prior advanced work with
  `committed_step_rehydration_required` rather than restoring verified receipts
  and budget; whole-attempt recovery is not implemented.
- **Prerequisite-state replay.** Authenticated and prerequisite-state DOM replay
  remains unqualified; `auth_kind` is not an exact identity binding.
- **OAST/C11 end-to-end delivery.** The reviewed payload bundle and correlation
  bridge exist, but delivery consumers for the full technique set are not wired
  into the adaptive loop.
- **C10 execution in the product path.** Mutation and cleanup ledgers with
  restoration predicates exist; routing product state-changing work through them
  is gated on intensity and not yet exercised end to end.
- **Operation × identity scheduling.** Complete scheduling across every canonical
  operation and brokered identity is unfinished.
- **Arbitrary native profile qualification.** Only the enumerated adapters are
  qualified; there is no general qualification path for new native profiles.
- **Capability 12 runner.** The control-plane contract, network profiles and
  scope evaluation exist (ADR-027); the customer-hosted runner lifecycle
  (enrollment, rotation, revocation, spool, remote kill) is not demonstrated.
- **Live model calls in qualification.** The product lane disables live model
  calls, so provider behaviour and cost are unqualified there.

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
- GraphQL and realtime profiles lacking adapters.
- Injection lacking a general active adapter mapping.
- Threat modelling being entirely absent (closed by ADR-026).
- State-changing tests being hard-rejected (now intensity-gated).

Two long-standing claims were also checked and found stale: documentation build
and generated-OpenAPI drift **are** CI gates (`docs.yml`,
`ci.yml` `check:api`), and the product roadmap no longer depends on
`.scratch/pentesting-full-vision/GAP_REGISTER.md`, which was superseded by the
committed ADRs.

## Exit criteria for an enterprise pilot

A pilot should not begin until the release blockers above are closed, no known
cross-tenant access path remains, cancellation and session-longevity SLOs pass
under load, every scanner outcome has auditable evidence, backup/restore has been
demonstrated, and the supported SSO/SCIM provider matrix passes automated
conformance tests.
