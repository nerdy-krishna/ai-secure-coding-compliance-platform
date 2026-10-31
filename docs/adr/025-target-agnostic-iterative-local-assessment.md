# ADR-025: Target-agnostic iterative local assessment loop

- Status: superseded by ADR-029
- Superseded by: [ADR-029](029-pentesting-autonomous-engine.md) — the controller, qualification, signed-task and work-ledger stack described here was deleted; pentesting is now one autonomous engine. This record is kept as history and does not describe the current codebase.
- Date: 2026-09-05

## Context

The development product runner initially demonstrated Web validation with
fixture-specific routes and a fixed two-wave model interaction. That shape did
not preserve the Capability 4 design intent: the model should reassess newly
committed safe evidence until it concludes that no useful authorized action
remains, while deterministic code retains scope, execution, budget, and finding
authority. Fixture routes also prevented the same reviewed behavior from
working against another explicitly allowlisted local application.

## Decision

The original local runner performs target-agnostic discovery of exact-origin GET
form and query parameter names from bounded HTTP and browser observations. A
reviewed differential adapter may apply fixed control, quote-bearing, and inert
custom-element probes to those parameters. The model can select only the
adapter identifier; it cannot provide a payload, method, destination, command,
credential, or finding outcome. Evidence excludes parameter values, response
bodies, tokens, raw exceptions, and executable script behavior. It retains
only bounded response metadata, digests, and closed signal families.

After baseline discovery, a pinned model receives an allowlisted secret-free
projection and selects up to two still-untried authorized capabilities. The
same process repeats after each completed selection. The loop ends when the
model explicitly returns no tools and a completion reason, when invalid or
unavailable model output leaves remaining work untried, or when the fixed
round/duration policy terminates it. A model outage no longer silently selects
a deterministic baseline. Every model call is idempotently
audited and every decision is policy-validated. With no model, deterministic
completion remains available.

Differential observations are parsed fail-closed by the Capability 6 bridge.
Only internally consistent confirmed signals can create candidates, and only
registered deterministic predicates plus the findings authority can verify and
promote them. Missing headers and generic HTTP metadata remain independent of
fixture-specific paths. The local execution profile remains development-only
and exact-origin allowlisted.

## Additive read-only gray-box path

The product may bind a second project-owned encrypted credential. Both exact
revision/fingerprint references participate in the signed task and create
idempotency digest. The local `authorization_readonly` tool uses separate HTTP
sessions, bounded form/API authentication, and exact-origin GET comparisons.
Optional owner-only path declarations supply operator expectations; discovered
links alone do not prove privacy. Matching stable representations may become
C6 candidates, never automatically confirmed findings. Independent verification
still requires the qualified broker/verification path, not local session slots.
This adds no production C7 readiness, new queue, or database migration.

The local options parser accepts current browser policy fields. Unsupported
nonempty engagement constraints fail closed before local admission; empty
optional fields remain inert. See
[local read-only authorization operations](../docs/operations/pentesting-readonly-authorization.md)
for supported inputs, evidence semantics, deployment order, and limitations.

## Additive browser/discovery qualification

Credential-bearing Playwright runs retain their anonymous crawl and DOM canary,
then add bounded isolated browser sessions. Protected per-role baselines, native
cookie expiry, hash-only response/DOM observations and fixed-role HTML/JSON/OpenAPI
provenance are recorded without exporting sessions. Discovered privacy remains
unknown; documented operations are not live tests or finding authority.

Worker and C6 readers share the legacy/current local execution-options validator.
Postcommit reconciliation preserves its original scope-checked audit on broker
redelivery, without skipping C6 authority validation. Historical C6 catalog replay
seeds only its pinned release entries and still rejects changed/missing digests.

The disposable paired tracer exercises real broker delivery, worker/Chromium,
encrypted/versioned evidence, C6 candidates, scoped summaries and postcommit
redelivery. This does not qualify product HTTP authentication/UI, precommit crash
recovery, non-owner RLS, SSO or C7 verification. Existing live feature flags remain
unchanged; pending qualification is not permission to disable a feature.

## Additive durable local work accounting

The V2 worker persists untried tool work before benchmark execution, then admits
running units under its active lease fence before target interaction. Discovered
GET-parameter SQLi/XSS tests have separate operation/technique/bundle keys.
Already-admitted work cannot automatically replay. Model planning reads durable
pending admission; local scheduling still operates in bounded tool batches.

Terminal ledger effects are part of the digest-bound staged execution commit,
not a postcommit projection. Recovery preserves this payload across JSON staging;
legacy empty payloads retain their original digest. Ledger effects, evidence,
DecisionDelta and terminal projections commit atomically. Unresolved work cannot
be reported as a successful result, but does not discard collected evidence.
Recovery settles uncertain running work as inconclusive while preserving untried
work. A prerequisite check can establish inapplicability after admission.

The scoped summary API and cockpit expose work counts as execution accounting,
not security coverage. This is not yet a unified operation-level C4 execution
loop: tools still batch operations and intermediate observations are staged
until the final execution commit. C10/C11 execution and safety gates are unchanged;
rendering OAST payloads is explicitly inconclusive.

## Audit remediation: discovery evidence, coverage and request accounting

C6 accepts the historical HTTP-probe v1 shapes and the explicit additive shape
with `validation_candidates` plus `operation_inventory`. The latter is checked
against a closed, bounded, value-free discovery contract and the committed
origin; unknown fields and malformed metadata remain errors. Single and merged
web-validation v4 artifacts retain SQLi, XSS and traversal, while historical v3
remains separately readable. Exact aggregate duplicates are idempotent;
conflicting rows and overflow are errors, not silently discarded evidence.

New operation keys use `sccap.pentest.operation-inventory-key.v3`: auth context,
transport, content type, parameter shape and prerequisite state participate.
Historical v1/v2 keys remain integrity-checked on reads; stored rows and evidence
are not rewritten. Anonymous stateless GET/query evidence cannot cover an
unknown/authenticated, protocol-specific or state-bound operation. A pass
requires evidence for every applicable category × parameter. Missing checks stay
applicable; blocked/inconclusive siblings remain blocked; a candidate maps to
`failed` inventory coverage, **not** a confirmed vulnerability. An auth-context
kind is not a brokered identity handle; complete identity-specific scheduling
is still pending; the bounded anonymous v3 extension below does not grant it.

The local Nmap profile is connect-only (`-sT`, without service detection or NSE).
Port-table service labels are hints, not verified versions. Nuclei reserves the
three-request upper bound of the digest-pinned single-GET template pack before
launch; redirects, retries, updates and Interactsh are disabled. Failed/uncertain
native sends retain the reservation. Its count is explicitly labeled a reserved
upper bound, not measured traffic. V2 summaries/commit budgets use pre-egress
allowance debits, including redirects and uncertain sends; the root bootstrap is
counted once separately. Python-proxied ZAP has no extra blanket debit.

See [local audit qualification](../docs/operations/pentesting-local-audit-qualification.md)
for real producer/worker/persistence checks and the remaining qualification
boundaries. These fixes do not complete canonical-operation scheduling, OAST
execution, workflow cleanup, or production readiness.

## Versioned canonical-operation scheduling and fresh-document DOM checks

New product submissions default to local `work_scheduler_version="v3"`; explicit
v2 and historical task readers remain available. This is a local scheduler
version, not Foundation 3 runner authority. V3 derives requirements from the
canonical discovery inventory, including OpenAPI operations without legacy URL
candidates. Work keys bind the canonical operation, parameter/test, anonymous
identity (or unresolved identity), technique and reviewed bundle. Each step is
admitted and evidence-committed under the worker lease before successor work is
considered; C6 still reads only the final canonical aggregate.

Only anonymous, stateless, single-query-parameter GET operations use the existing
SQLi, reflected-XSS and traversal adapters. Required or malformed OpenAPI security
and credential-bearing HTTP discovery do not establish an anonymous identity.
Authenticated, state-bound, non-GET, typed/protocol and unsupported technique
requirements are recorded as blocked, not omitted. Expansion is bounded to 64
requirements with an explicit overflow blocker. Missing checks cannot become a
coverage pass. Inventory categories are local requirements, not a claim of full
C9 catalog execution.

The v3 advisory model selects exactly one matching work ID/tool pair from a
bounded window of up to 16 admitted choices. It cannot invent a work ID, supply
payloads or change authority. Invalid/unavailable output leaves work unresolved;
deterministic scheduling is available only when no model is configured. New
web-validation v5 evidence binds each candidate to its canonical operation and
input. C6 validates those bindings and the existing technique/bundle predicates;
v3/v4 evidence readers retain their separate contracts. Coverage does not borrow
v5 evidence across same-path operations with different keys.

A fresh in-memory v3 run refuses prior advanced work until verified receipt and
budget rehydration exists. This is fail-closed recovery, not resume qualification.
It does not replace the formal C4 controller or enable C7, C10 or C11 execution.

DOM fragment canaries now start a fresh document at the discovered URL, retaining
path and query, through the existing request gate. Navigating via `about:blank`
avoids an extra target request while ensuring startup scripts run. The original
digest-pinned vulnerable/clean fixture and a redirected-document fixture both
exercise the real Chromium sink without weakening the assertions. This does not
qualify authenticated or prerequisite-state replay.

Revision `d1312690dfa1` expands Engagement `completion_reason` from 32 to 64
characters: the existing deterministic blocked/inconclusive reason otherwise
rolls back the atomic result. It does not rewrite history; narrowing downgrade
is refused. Deploy the migration and v3-capable worker/C6 readers before admitting
new v3 product tasks. Old application code can read the widened column.

## Consequences

- The runner works against any explicitly configured local fixture origin; no
  production path or reviewed template encodes one fixture's application routes.
- The LLM conversation is a repeated advisory assessment loop instead of a
  fixed pair of turns, with explicit completion visible in activity history.
- Safety bounds remain deterministic: closed tools, exact origins, reviewed
  probes, bounded evidence, duration/round limits, and separate finding truth.
- This ADR does not make the local runner an unrestricted production scanner or
  supersede the formal Capability 4 controller's committed `DecisionDelta`
  authority model.
