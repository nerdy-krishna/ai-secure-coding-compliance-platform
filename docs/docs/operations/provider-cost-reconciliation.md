# Provider cost reconciliation

SCCAP can compare its immutable LLM usage ledger with a provider's read-only
organization usage API. The connector is optional: a deployment without billing
credentials does not contact a provider and all reconciliation endpoints report
`not_configured` or `never_run`.

## Safety boundary

- Create a dedicated provider credential with organization usage- and costs-read
  access only. The connector records those endpoint checks as verified only after
  both reads succeed; it never calls a model or provider write endpoint.
- Credentials are Fernet-encrypted in `provider_billing_connectors` and are never
  returned by the API. Project and API-key identifiers in evidence are one-way
  opaque hashes.
- Connectors default to disabled. Enabling one schedules bounded polling; manual
  runs require an idempotency key and a window no longer than 31 days.
- Provider results never update `llm_usage_events`, `llm_usage_requests`, line
  items, or price snapshots. User-visible canonical totals therefore do not move
  silently after reconciliation.

## Comparison and evidence

Every run normalizes the UTC window, provider/model, project and API-key
attribution, service tier, batch flag, token categories, and USD currency before
comparison. The common comparison key uses dimensions available on both sides;
project/key attribution remains opaque evidence where the SCCAP ledger cannot
prove the provider identifier.

The absolute micro-USD and percentage tolerances are both evaluated; the larger
allowance applies to a dimension. Evidence is classified as:

- `missing_event`
- `duplicate_event`
- `token_category_mismatch`
- `price_catalog_mismatch`
- `provider_adjustment_credit`
- `timing_lag`
- `unresolved`
- `matched`

Runs, normalized evidence, and provider adjustment records are append-only.
Credits and timing-lag entries are explicitly classified adjustments rather than
canonical spend. Missing, duplicate, category, price, and unresolved evidence
contribute to the unresolved amount. Any discrepancy creates a durable operator
alert in `provider_reconciliation_alert_outbox`; provider outages create a failed
run and an error alert without partial evidence.

## Usage-center API contract

All routes are tenant-scoped under `/api/v1/admin/usage-reconciliation`.
Read routes require `audit.read`; connector changes and manual execution require
`tenant.policy.manage`.

| Route | Purpose |
| --- | --- |
| `GET /summary` | Last reconciliation time, coverage, variance, unresolved amount and run ID. |
| `GET /runs?cursor=&limit=` | Cursor-paginated immutable run history. |
| `GET /runs/{run_id}` | One run. |
| `GET /runs/{run_id}/evidence?cursor=&limit=` | Cursor-paginated dimension evidence. |
| `GET /connectors` | Redacted connector metadata; never returns credentials. |
| `POST /connectors` | Create a disabled-by-default encrypted connector. |
| `PUT /connectors/{connector_id}` | Rotate the credential and change schedule/tolerances. |
| `POST /connectors/{connector_id}/runs` | Execute a bounded read-only window with `X-Idempotency-Key`. |

The usage center should render `not_configured`, `never_run`, `completed`, and
`failed` states and must not add reconciliation variance to canonical spend.

## Operations

The API lifespan starts `provider-reconciliation-sweeper`, which checks due
enabled connectors once per minute. Polling is serialized per scheduled tick and
provider pagination is capped at 100 pages; repeated or cyclic cursors fail the
run. Investigate pending/failed alert-outbox rows, failed runs, and stale
`next_run_at` values before rotating credentials. Disabling a connector stops new
provider I/O while preserving all historical evidence.
