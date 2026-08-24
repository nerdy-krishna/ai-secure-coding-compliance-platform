# Evidence-first findings and policy gates

SCCAP freezes a governance record for every final finding before an attempt is finalized. The
record is append-only and carries the exact source ranges, attempt, immutable evidence-object and
scanner-coverage identifiers, source/rule/model provenance, consolidation lineage, dataflow context,
and remediation verification state. Deleting an owning scan or finding leaves a tenant-scoped
tombstone instead of rewriting the evidence.

## Baseline semantics

The worker compares each completed scan with the immediately preceding completed scan for the same
project. A versioned fingerprint uses producer identity, normalized repository path, rule/CVE/CWE,
and the normalized vulnerable snippet. Scan-local UUIDs, presentation text, and line numbers are
excluded, so harmless line drift does not create a new issue.

| State | Meaning |
| --- | --- |
| `new` | The fingerprint has never appeared in an earlier project scan. |
| `unchanged` | The fingerprint exists in the immediately preceding completed scan. |
| `reintroduced` | It is absent from the preceding scan but appeared in older project history. |
| `fixed` | It existed in the preceding scan and is absent now. The record points to its predecessor. |

The Results page, HTML/PDF/CSV/SARIF exports, and portfolio trend endpoint read these persisted
records. They do not independently recalculate classification.

## Policy gates

Finding gate policies are immutable, monotonically versioned tenant records. A policy selects the
minimum severity and confidence that block, whether deterministic scanner coverage must be
complete, whether waivers are accepted, and the minimum time a waiver must remain valid.

Every evaluation stores the exact policy version, coverage result, blocking fingerprints, and
accepted waiver fingerprints. Evaluations are append-only, so reevaluation after granting or
revoking a waiver preserves both decisions. A failing gate does not rewrite scan truth or discard
partial evidence.

## Waiver lifecycle

Direct grants require `waiver.approve`. Every grant contains the authenticated actor, a bounded
reason, scope (`finding`, `fingerprint`, or `project`), exact fingerprint, and timezone-aware expiry
no more than one year in the future. Grant, revoke, and elapsed-expiry events are append-only.
Expired and revoked grants never satisfy policy. Expiry is effective from the timestamp itself;
the next governance read or evaluation idempotently materializes the corresponding `expired` audit
event.

## API and visibility

All reads require the active tenant and normal self/group/tenant visibility scope. Resources outside
that scope return `404`. PostgreSQL forced RLS and tenant-reference triggers provide a second
boundary.

| Endpoint | Purpose |
| --- | --- |
| `GET /api/v1/finding-governance/scans/{scan_id}/findings` | Baseline counts, evidence detail, and latest gate result. |
| `GET /api/v1/finding-governance/scans/{scan_id}/findings/{finding_id}` | One finding's evidence detail. |
| `GET/POST /api/v1/finding-governance/policy` | Read or create the next policy version. |
| `POST /api/v1/finding-governance/scans/{scan_id}/evaluate` | Append a gate reevaluation. |
| `POST /api/v1/finding-governance/scans/{scan_id}/findings/{finding_id}/waivers` | Grant an expiring waiver. |
| `POST /api/v1/finding-governance/waivers/{waiver_id}/revoke` | Append a revocation. |
| `GET /api/v1/finding-governance/waivers/{waiver_id}` | Read the complete waiver audit history. |
| `GET /api/v1/finding-governance/portfolio/trends?days=90` | Visibility-scoped persisted trend buckets. |

## Operations and rollback

Migration `b7e19c4d2a60` creates five RLS-protected governance tables and follows provider
reconciliation revision `a8f2c7d91e44`. Apply it inside Compose with
`docker compose exec app alembic upgrade head`.

Before rollback, export governance evidence required by retention or legal-hold policy. Downgrade
removes lineage, policy evaluations and versions, waivers, and their audit events. Scan and finding
tables are unchanged.
