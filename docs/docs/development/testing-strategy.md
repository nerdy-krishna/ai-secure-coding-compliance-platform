---
sidebar_position: 3
title: Verification Strategy
---

# Verification strategy

## Current baseline

The inherited backend, frontend, browser, and prompt-evaluation suites were removed on
2026-08-22. They had become a mixture of useful checks, placeholder tests, implementation-coupled
mocks, and claims that no longer matched production behavior. SCCAP is rebuilding verification
around observed defects and stable domain interfaces rather than restoring a target test count.

The backend replacement checks now cover refresh-cookie issuance/expiry, SCIM schema
generation, scan-detail peer/tenant visibility, cooperative cancellation, cost-approval policy,
native-report size/outcome bounds, CVSS severity boundaries, stable Semgrep language selection,
scanner runtime/config digest verification and immutable Semgrep ruleset/source snapshots,
the PostgreSQL scan-submission commit/rollback boundary, atomic approval/decline/resume/restart,
cancellation, terminal-state race rejection, checkpointed stage markers, public refresh sessions,
tenant-scoped result access, native scanner-report downloads, and HTML/CSV/PDF/SARIF exports. A
real RabbitMQ/worker scenario covers outbox recovery and terminal cancellation; a deterministic
provider drives all three approval gates on one LangGraph thread. Three focused Vitest checks also
protect successful, failed, and user-stopped scan-progress projections after the authenticated
browser audit exposed false 100% completion. Passing these checks still does **not** prove every
tenant-scoped endpoint, arbitrary end-to-end scan correctness, event-stream reliability, or all
browser behavior.

## Always-run checks

Backend and worker commands run inside Docker because the application configuration uses Compose
service hostnames.

```bash
docker compose config
docker compose build app worker
docker compose exec app alembic upgrade head
docker compose exec app python -m unittest discover -s /app/tests/auth -v
docker compose exec app python -m unittest discover -s /app/tests/risk -v
docker compose exec app python -m unittest discover -s /app/tests/scanners -v
docker compose exec app python -m unittest discover -s /app/tests/workflows -v

# Opt-in, real PostgreSQL + public FastAPI integration layer. The Compose API
# and database must already be running; the environment flag prevents this
# layer from being pulled accidentally into a fast unit run.
docker compose exec \
  -e SCCAP_RUN_INTEGRATION=1 \
  -e SCCAP_INTEGRATION_BASE_URL=http://127.0.0.1:8000 \
  app python -m unittest discover -s /app/tests/integration -v
docker compose exec app python -m ruff check src tests
docker compose exec app python -m black --check src tests

npm --prefix secure-code-ui run lint
npm --prefix secure-code-ui test
npm --prefix secure-code-ui run build

# With the Compose API running on :8000. This regenerates the committed
# contract and fails if the working tree differs afterward.
SCCAP_OPENAPI_URL=http://127.0.0.1:8000/openapi.json \
npm --prefix secure-code-ui run check:api

# Requires a disposable UI/API Compose stack. The Playwright global fixture
# creates its own superuser, LLM config, framework, projects, scans, events,
# approval gates, finding, and scanner artifact, then deletes that exact
# ownership boundary in global teardown. Do not run a worker in this topology:
# submissions and approval decisions must remain parked and deterministic.
SCCAP_BROWSER_BASE_URL=http://127.0.0.1 \
SCCAP_BROWSER_EMAIL=browser-ci@example.com \
SCCAP_BROWSER_PASSWORD='V7!BrowserRefresh-CI-2026' \
npm --prefix secure-code-ui run test:browser

cd docs && mkdocs build --strict
```

The worker-image scanner smoke is container-specific because host binaries are irrelevant:

```bash
docker run --rm --entrypoint python \
  -e PYTHONPATH=/app/src \
  -v "$PWD/tests:/app/tests:ro" \
  sccap-worker:test -m tests.scanners.scanner_toolchain_smoke
```

CI supplies the required application configuration variables. The smoke check fails on any runtime
version, binary digest, or Gitleaks-config mismatch and permits only OSV's explicitly documented
`advisory_snapshot_identifier_unavailable` degraded reason.

The CI workflow gives backend unit contracts and real-infrastructure integration tests separate
jobs. The integration job starts a clean PostgreSQL, RabbitMQ, Qdrant, API, and worker stack,
runs migrations through the normal API entrypoint, executes the opt-in integration package, and
then stops RabbitMQ, submits a scan through the public HTTP API, restarts the broker, and proves the
durable outbox reaches the real worker before cancelling the fixture scan. The outage scenario is
intentionally CI-orchestrated; do not run its phases against a shared developer stack. While the
broker is paused, CI also exercises public resume/restart transactions without racing dispatch. CI
removes its volumes afterward. A deterministic OpenAI-compatible fixture drives the prescan,
profiling, and analysis-cost gates without a paid provider; the scenario asserts that checkpoint
counts advance under the same scan/thread id at every pause.

The separate browser job starts a clean API/UI stack without a worker. It proves password login,
single-flight concurrent 401 refresh with cookie rotation, canonical submission routing, profiling
and analysis approval gates, cursor-bearing SSE reconnect and replay de-duplication, cancellation
requested/observed/completed persistence, cancelled and completed terminal projections, and HTML,
PDF, CSV, SARIF, and native scanner-evidence downloads. Its global fixture creates and safely removes
all owned rows. On failure, screenshots, video, and traces are retained for seven days only after a
fail-closed sanitizer removes fixture credentials, submitted-source markers, bearer tokens, refresh
cookies, and JWTs. An optional `workflow_dispatch` live-provider
job is off by default and never runs on pushes or pull requests. When explicitly enabled, it makes
exactly one structured OpenAI Responses API call, caps output at 400 tokens, refuses the call when
the pinned LiteLLM cost map estimates more than USD 0.01, and verifies a known SQL injection is
classified as CWE-89. It requires the repository `OPENAI_API_KEY` secret; the selected model must
exist in the pinned LiteLLM map or preflight fails before network access. The backend-integration
job also generates the frontend contract from the running API and rejects an uncommitted
`api-generated.ts` diff. The strict documentation build runs in the separate Docs workflow.

## OpenAPI contract workflow

`secure-code-ui/src/shared/types/api-generated.ts` is committed build input. Never edit it by
hand. After changing a route, request model, response model, or nullability:

```bash
docker compose up -d app
SCCAP_OPENAPI_URL=http://127.0.0.1:8000/openapi.json \
npm --prefix secure-code-ui run generate:api
git diff -- secure-code-ui/src/shared/types/api-generated.ts
npm --prefix secure-code-ui run build
```

Review the generated diff alongside the backend change, including success, validation-error, and
nullable response shapes, then commit it. `check:api` repeats generation and uses `git diff
--exit-code` as the drift gate. The scan submission, result, and report query boundaries derive
their request/response types from concrete generated OpenAPI operations. Free-form JSON fields are
narrowed once in `shared/lib/scanContract.ts` before rendering; pages must not recreate endpoint
response interfaces.

## Requirements for replacement tests

A new test must protect at least one of these:

1. A reproduced user-visible defect at the interface where it actually occurs.
2. A security or tenancy invariant that could expose another user's data or secrets.
3. A scan-lifecycle contract involving status, event, approval, cancellation, resume, or restart.
4. A durable persistence contract involving tasks, snapshots, findings, or artifacts.
5. A frontend/backend request or event contract used by a real page.
6. A scanner parser contract using a representative native report fixture.
7. A migration or deployment path whose failure would prevent startup or recovery.

Avoid tests that only assert a mock was called, duplicate type checking, pin private function
structure, or pass without exercising the production call chain.

## Preferred layers

- **Domain tests:** fast deterministic checks for pure policies such as classification, risk, and
  status projection.
- **Database integration tests:** real Postgres transactions for tenancy, outbox, task ledger,
  lifecycle, and idempotency behavior.
- **Scanner contract tests:** real native JSON/SARIF fixtures through the production parser.
- **Worker integration tests:** RabbitMQ + Postgres + LangGraph checkpoints for approval,
  cancellation, resume, and restart.
- **Browser tests:** a running Compose stack for login refresh, submission, live activity,
  cancellation, results, and downloads.
- **LLM evaluations:** versioned prompts and adversarial cases with deterministic structural gates;
  live-model evaluation is opt-in and must have an explicit cost ceiling.

## Bug-fix loop

For a reported defect, first build a deterministic reproduction at the correct interface. Turn that
reproduction into a failing test, apply the fix, prove the test passes, and rerun the original user
scenario. If no reliable seam exists, record that architectural limitation rather than adding a
shallow test that gives false confidence.
