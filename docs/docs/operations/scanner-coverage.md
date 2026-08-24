# Scanner coverage manifests

SCCAP records deterministic scanner coverage separately from findings. A scan with zero findings is
only clean when every planned scanner/input entry is `clean` or `completed`. Any `planned`,
`skipped`, `failed`, `timeout`, `unsupported`, or `truncated` entry makes coverage degraded.

## Durable model

`scanner_coverage_entries` contains one row for each scanner/input pair in the current immutable scan
attempt. Bandit, Semgrep, and Gitleaks use repository-relative input paths; OSV uses the
`<repository>` input because it evaluates dependency manifests as one repository operation. Inputs
without a supported deterministic scanner receive an explicit `registry / unsupported` row.

Planning is persisted before scanner subprocesses start. Terminal outcomes then record the reason,
finding count, native-evidence availability, provenance status, and timestamps. A worker crash can
therefore leave a visible `planned` entry instead of silently converting unfinished work to clean.

Native `scanner_reports` evidence includes the coverage-entry IDs represented by each scanner report.
Scanner findings store the same IDs. Consolidation unions these IDs when several raw findings become
one normalized finding, preserving coverage lineage through report generation.

## Operator surfaces

- `GET /api/v1/scans/{scan_id}/scanner-coverage` returns the current attempt manifest.
- `GET /api/v1/scans/{scan_id}/result` embeds the same manifest.
- Results UI, HTML, PDF, CSV, and SARIF reports show coverage independently from findings.
- Scanner JSON downloads include `coverage_entry_ids` beside native reports.

Legacy scans without coverage records are shown as `unavailable`, never inferred clean.

## Policy evaluation and waivers

Authorized scan approvers can evaluate specified states with
`POST /api/v1/scans/{scan_id}/scanner-coverage/policy`:

```json
{
  "failing_states": ["failed", "timeout", "truncated"],
  "waive": false,
  "audit_reason": "Release policy requires complete deterministic coverage."
}
```

Matching entries produce `fail`; no matches produce `pass`. Setting `waive: true` produces `waived`
only when degraded entries match. Every decision is append-only, includes the exact matching entry
IDs and actor, and emits a `COVERAGE_POLICY` decision event with the audit reason. A waiver changes
the policy outcome; it never changes the underlying coverage rows or labels them clean.

## Operations and rollback

Coverage tables use forced tenant RLS. Database triggers reject scan, attempt, actor, and finding
lineage references outside the active tenant. Restart creates a new attempt and therefore a new
manifest; earlier attempts remain attributable.

Apply migrations inside Docker:

```bash
docker compose exec app alembic upgrade head
```

Rollback of revision `d4e71a9c6b20` removes the manifest, decisions, and finding lineage columns. Do
not downgrade after relying on coverage policy evidence without first exporting the affected audit
records.
