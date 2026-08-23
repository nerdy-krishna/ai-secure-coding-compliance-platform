# Usage budget enforcement

SCCAP enforces model usage at the shared `LLMClient` boundary before any
potentially billable provider request. Policies and counters are tenant-owned,
reservations are durable across API and worker processes, and actual usage is
settled from the canonical LLM usage ledger.

## Policy model

A policy has one scope, one window, and one or more hard-cap dimensions.

| Field | Supported values |
| --- | --- |
| Scope | `tenant`, `group`, `user` |
| Window | `request`, `scan`, UTC calendar `day`, UTC calendar `month` |
| Dimensions | input, output, total, uncached input, and billable tokens; USD; upstream requests |
| Filters | optional LLM configuration and canonical ledger stage |

Every matching policy is charged. For a user in multiple groups, every
matching group counter applies and the smallest remaining allowance wins;
policies never add capacity to each other. Group membership is snapshotted
when the hold is created. Day and month windows are half-open UTC intervals
with no rollover.

Policies are immutable versions. Replacing or disabling a policy appends a new
version, so existing counters and audit evidence keep their original terms.
The default soft thresholds are 80% and 95%. `token_only` handling for an
unknown price is valid only when the same policy includes a finite token cap.

## Admission and settlement

The budget lifecycle is:

1. Count the fully rendered prompt and calculate a conservative, calibrated
   upper estimate.
2. Lock all matching policy counters in deterministic order.
3. Atomically increase `held` only if every cap can admit the estimate.
4. Invoke the provider.
5. Settle the hold from the immutable `llm_usage_events` entry, moving actual
   usage to `spent` and recording any estimate overrun.

A failure before provider invocation releases the hold. Once provider
invocation has started, missing accounting is conserved as
`accounting_unknown`; SCCAP does not release that capacity or replay the
provider call. Expired orphan holds may be released only when no canonical
usage event exists for the reservation key.

Scan profiling and analysis approvals reserve parent envelopes for the current
scan attempt. Per-call child reservations draw down those envelopes without
double-counting scan/day/month capacity, while request-window policies are
always checked directly. Cancellation, decline, failure, completion, and
budget exhaustion release unused envelope capacity idempotently.

## Denials and warnings

Hard-cap admission failure returns HTTP `429` with stable code
`budget_hard_limit_exceeded`. The privacy-safe detail names the policy, scope,
window, dimension, remaining allowance, requested amount, and calendar reset
when applicable. An unpriceable request under a monetary policy fails closed
with `budget_price_unknown`, unless the applicable policy explicitly permits
the finite token-only behavior above.

An in-flight request is allowed to finish and settle. A scan denied at its next
billable boundary preserves partial findings and usage, releases unused holds,
and enters terminal status `BUDGET_EXHAUSTED`; it is never reported as a
successful completion or silently retried.

Threshold crossings are deduplicated per policy version, counter, dimension,
and percentage. They produce durable threshold-event and notification-outbox
rows for tenant administrators and security approvers; user-scoped policies
also target the affected user.

## Administration API

The tenant-scoped base path is `/api/v1/admin/usage-budgets`.

| Method and path | Permission | Purpose |
| --- | --- | --- |
| `GET /policies` | `audit.read` | Current policies; `include_disabled=true` returns version history |
| `POST /policies` | `tenant.policy.manage` | Create a policy |
| `PUT /policies/{id}` | `tenant.policy.manage` | Append a replacement version |
| `POST /policies/{id}/disable` | `tenant.policy.manage` | Append a disabled version |
| `GET /counters` | `audit.read` | Current held/spent windows |
| `GET /reservations` | `audit.read` | Reservation and settlement state |
| `GET /threshold-events` | `audit.read` | Deduplicated soft-limit crossings |
| `GET /overrides` | `audit.read` | Active or historical additive overrides |
| `POST /override-requests` | `tenant.policy.manage` | Request critical-mode distinct-actor approval |
| `POST /overrides` | `tenant.policy.manage` | Create an approved additive allowance |

Every query is tenant-filtered and protected by database row-level security.
Platform operators must explicitly enter a tenant. Service principals can
consume policy capacity but cannot manage policies or overrides.

Overrides are additive, bound to one policy version and existing window, and
expire at the earlier of 24 hours or the window end. They cannot rewrite spent
usage or bypass unrelated applicable policies. In separation-of-duties
`critical` mode, the exact payload requires approval from a distinct actor
who also has `tenant.policy.manage`.

## Migration and operations

Migration `9e17fa3b5c24` seeds every existing tenant with an enabled `$100`
tenant/scan USD policy, preserving the former global scan-estimate ceiling.
New tenants receive the same deterministic default lazily at their first scan
budget gate. The former `$1` per-file cost rejection is removed; the 80-call
and 50-finding per-file execution guards remain. The RAG preprocessing job's
`$25` aggregate compatibility guard also remains, while every RAG model call
is independently subject to request/day/month policies.

Operational checks:

- Monitor held reservations older than their expiry before running the orphan
  release sweep.
- Reconcile `usage_budget_settlements` with `llm_usage_events`; investigate
  `accounting_unknown` rather than manually releasing it.
- Consume `usage_budget_notification_outbox` idempotently and mark delivery;
  threshold events remain the audit source of truth.
- Roll back enforcement by appending disabled policy versions. Do not edit or
  delete policy, override, settlement, or threshold history.

