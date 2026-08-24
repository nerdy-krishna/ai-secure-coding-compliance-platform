# Usage and budget center

The authenticated `/usage` page is the read surface for SCCAP's canonical LLM
usage ledger and durable budget counters. It covers scans, Security Advisor
chat, and RAG preprocessing without reading retained prompts, responses, source
contents, or provider secrets.

## Visibility

Every query resolves one active tenant before it reaches the repository and
keeps the mandatory `tenant_id` predicate even for platform operators.
PostgreSQL row-level security remains a second boundary.

| Caller | Visible usage |
| --- | --- |
| Normal user | Their own canonical events and allowances only |
| Group owner | Users in groups where their membership role is `owner` |
| Tenant-wide auditor or administrator | The explicitly selected tenant |
| Platform owner | One tenant after password/reason-bound tenant entry |

An ordinary group member does not inherit peer spend visibility from scan
sharing. Account and group filters outside the resolved scope return `404`, so
the endpoint cannot be used as an identifier-existence oracle.

## Accounting vocabulary

Summary cards report actual and estimated cost, variance, input/output/total,
cache-read/cache-write/reasoning tokens, upstream requests, cache-hit rate, and
held capacity. Amounts are PostgreSQL `NUMERIC` values and API decimals; JSON
clients receive decimal strings rather than binary floating-point values.

The UI and exports preserve these states:

- `exact`: priced from the immutable request price snapshot;
- `estimated`: a pre-call estimate, never presented as actual spend;
- `unknown`: usage exists but no complete price can be proven; it is never
  displayed as zero;
- `reconciled`: provider evidence resolved a previously uncertain amount;
- `held`: capacity reserved before a potentially billable provider request.

The provider reconciliation summary is shown independently to callers with
`audit.read`. Reconciliation evidence does not expose provider credentials or
raw billing payloads in the usage ledger drilldown.

## API

The authenticated base path is `/api/v1/usage`.

| Method and path | Purpose |
| --- | --- |
| `GET /summary` | Exact totals and selected visibility scope |
| `GET /trends?interval=day` | UTC hour/day/week/month rollups |
| `GET /breakdowns?dimension=stage` | Paginated operation/project/scan/stage/agent/provider/model/account/group rollups |
| `GET /events` | Cursor-paginated attribution-only canonical events |
| `GET /budgets` | Effective policies, spent/held/remaining capacity, warnings, and recent scan denials |
| `GET /export?format=csv` | The same event filters as the UI in CSV or JSON |
| `POST /policy-preview` | `tenant.policy.manage` preview of strictest matching precedence |

Common filters are `from_at`, `to_at`, `user_id`, `group_id`, `project_id`,
`scan_id`, `operation_kind`, `operation_id`, `stage`, `agent_name`, `provider`,
`model`, `llm_config_id`, and `cost_status`. Windows are half-open UTC
intervals, default to 30 days, and are bounded to 366 days. Event pages contain
at most 200 rows. Exports contain at most 10,000 rows; narrow the same filters
when the API returns `413`.

CSV and JSON deliberately omit `idempotency_key`, prompt context, raw response,
parsed output, file paths, provider response IDs, and price-snapshot metadata.
They contain the exact decimal amount and accounting state shown by the UI.

## Policy administration

Users with `tenant.policy.manage` can preview, create, schedule, time-bound, and
disable policies from the same page. Preview resolves tenant, group, and user
matches and reports the strictest finite cap for every dimension before a
write. The write continues through `/api/v1/admin/usage-budgets`, which appends
an immutable policy version and an authorization audit event. Critical-mode
temporary overrides continue to require a distinct approved actor.

## Performance and operations

Aggregation executes in PostgreSQL against the tenant, timestamp, attribution,
operation, scan, model-configuration, and stage indexes installed with the
canonical ledger. Queries are date-bounded, breakdowns are database-grouped and
paginated, group arrays are expanded through a correlated lateral operation,
and event pagination uses `(created_at, id)` rather than an unbounded offset.
These controls keep the current production retention window responsive without
a second source of truth.

Do not add a materialized usage table until measured query latency requires it.
If one becomes necessary, refresh it from immutable `llm_usage_events` and
budget reservations, carry `tenant_id` and RLS, preserve exact numeric types,
and retain a ledger watermark so operators can prove rollup completeness.

Monitor:

- p95 latency and rows scanned for summary and breakdown endpoints;
- the ratio of `unknown` and `accounting_unknown` states;
- old held reservations and hard-limit denials;
- reconciliation coverage and unresolved variance;
- export `413` frequency, which indicates filters or retention need tuning.
