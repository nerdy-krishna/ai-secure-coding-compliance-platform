# Semgrep Rule Ingestion — Operator Guide

SCCAP runs Semgrep exclusively on rules stored in Postgres. There is no bundled rule pack. On a fresh deployment Semgrep produces zero findings until an admin enables at least one source and syncs it.

---

## Quick start

1. Log in as superuser and go to **Admin → Frameworks → Semgrep Rules** tab.
2. Click **Load built-in sources** — this upserts 16 curated community sources (all disabled by default).
3. Toggle **Enabled** on the sources you want.
4. Click **Sync Now** on each enabled source and wait for the status to turn green.
5. Submit a scan — Semgrep will now run against the ingested rules.

---

## How rule selection works

At scan time the prescan node:

1. Detects the languages present in the submitted files (by file extension).
2. Queries `semgrep_rules` for rules where:
   - `source.enabled = true`
   - `rule.enabled = true`
   - `rule.license_spdx IN (semgrep_ingestion.allowed_licenses)`
   - `rule.languages && detected_languages` (Postgres array overlap)
   - optionally `rule.technology && detected_technologies OR rule.technology = '{}'`
3. Writes matching rules to a temp directory and passes `--config <dir>` to Semgrep.
4. If 0 rules match, Semgrep is silently skipped — the scan still completes via Bandit, Gitleaks, and OSV-Scanner.

---

## System settings

All settings live in `system_configurations` and are editable at **Admin → Frameworks → Semgrep Rules → Settings**:

| Key | Default | Description |
|-----|---------|-------------|
| `semgrep_ingestion.allowed_licenses` | `["MIT","Apache-2.0","BSD-2-Clause","BSD-3-Clause"]` | Only rules whose `license_spdx` is in this list are selected for scans. Add or remove SPDX identifiers to adjust. |
| `semgrep_ingestion.max_rules_per_scan` | `5000` | Hard cap on rules passed to a single Semgrep invocation. Prevents runaway memory usage on very broad rule sets. |
| `semgrep_ingestion.workdir` | `/tmp/semgrep_repos` | Base path for git clones. Must be writable by the app container. Mount a persistent volume here to avoid re-cloning on every restart. |
| `semgrep_ingestion.global_enabled` | `true` | Kill switch — set to `false` to skip Semgrep across all scans without changing source config. |
| `semgrep_ingestion.sweep_interval_seconds` | `900` | How often the background sweeper checks for sources whose `sync_cron` is due. Changing this takes effect on the next sweeper tick without restart. |

---

## Source configuration

Every source attribute is editable through the UI (Edit button on a source row):

| Field | Notes |
|-------|-------|
| **Repo URL** | HTTPS URL of the git repository containing rules. Update if the upstream repo moves. |
| **Branch** | Branch to clone/pull. Default: `main`. |
| **Subpath** | Relative path within the repo to scan for rule YAMLs. Leave blank to scan the entire repo. |
| **Sync cron** | Standard cron expression for automatic re-syncs (e.g. `0 3 * * 0` = Sunday 03:00 UTC). Only respected when **Auto-sync** is enabled. |
| **Enabled** | Whether rules from this source are included in scans. Toggling takes effect on the next scan. |
| **Auto-sync** | Whether the background sweeper should re-sync this source on its cron schedule. |
| **License SPDX** | The SPDX identifier for this source's license. Rules are only selected when the source license is in `allowed_licenses`. |

---

## Sync lifecycle

Each sync run:

1. Acquires a Postgres advisory lock (one concurrent sync per source).
2. `git clone --depth 1 <repo_url>` into `<workdir>/<slug>/`, or `git fetch + reset --hard` if already cloned.
3. Walks all `*.yaml` / `*.yml` files (skipping `*.test.yaml`).
4. Validates each file with `semgrep --validate` (30 s timeout).
5. Parses rule entries, computes `sha256` content hashes.
6. Upserts rules by `namespaced_id` (skips if `content_hash` unchanged).
7. Deletes rules whose `namespaced_id` was not seen in this sync (safety guard: won't delete if the parse produced 0 valid rules).
8. Updates `source.rule_count`, `last_synced_at`, `last_sync_status`.

Sync history (started/finished timestamps, rules added/updated/removed/invalid, error message) is viewable from the **View Runs** drawer.

A sync run that fails mid-way does not leave the source in a broken state — partial upserts persist, and the next sync reconciles the remainder.

---

## Background sweeper

`semgrep_sync_sweeper.py` runs on the API container alongside the outbox and prescan-approval sweepers. Each tick it:

- Loads the current `sweep_interval_seconds` from the DB (so admin changes take effect without restart).
- Selects sources with `enabled = true` and `auto_sync = true`.
- Evaluates each source's `sync_cron` against `last_synced_at` using `croniter`.
- Fires `asyncio.create_task(run_sync(..., triggered_by="cron"))` for each due source.

Stuck runs (status `running` at startup, meaning the previous process was killed mid-sync) are automatically reset to `failed` when the API starts.

---

## License implications

Rules are selected only when their `license_spdx` appears in `allowed_licenses`. The default list (`MIT`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`) covers the majority of community rule repos. Before enabling a source with a different license:

1. Review the license in the source's repository.
2. Add the SPDX identifier to `allowed_licenses` via the Settings card.
3. Consult your legal team if deploying in a commercial or regulated context.

GPL-licensed rule sets are **excluded by default** — they may impose copyleft obligations on any tool that distributes derived works.

---

## Semgrep CLI version compatibility

Rules are written for specific Semgrep pattern operators. A mismatch between the rule's target Semgrep version and the installed binary can produce validation failures or incorrect findings.

- Check the installed version: `docker compose exec app semgrep --version`
- If a community source starts failing validation, check the source's changelog for breaking pattern-syntax changes.
- The Semgrep binary version is pinned in `Dockerfile` and managed by `renovate.json` (custom-managers regex). Review the Renovate PR before merging a major version bump.

---

## Scan Readiness Panel

The submission page shows a **Scan Readiness** panel (right-side sticky card) with:

- **Frameworks** — chips for each available framework; amber warning if none are configured.
- **Semgrep Rule Sources** — counts of enabled+synced sources and total rules; links to the admin tab.

If you submit files whose detected languages have no matching rules, a **Scan Coverage** wizard appears before the scan is submitted. Superusers can enable and sync a source from within the wizard. Non-superusers see a prompt to contact their admin. Both can skip the wizard — Semgrep will simply be omitted from that scan.

---

## Troubleshooting

**`last_sync_status = "failed"` on a source**
- Open **View Runs** and read the `error` column of the latest run.
- Common causes: network timeout reaching the git host, `semgrep --validate` failure on a malformed rule, disk full at `workdir`.

**0 rules after a successful sync**
- The source may use a non-`MIT`/`Apache` license — check `license_spdx` and `allowed_licenses`.
- The rules may not cover the languages in your scans. Check `rule.languages` via the **View Rules** drawer.
- `global_enabled` may be set to `false`.

**Semgrep skipped on every scan even after syncing**
- Confirm the source is `enabled = true` in the source table.
- Confirm the scan's files use an extension that maps to a covered language (`.py` → python, `.js` → javascript, etc.).
- Check `semgrep_ingestion.max_rules_per_scan` hasn't been set to 0.
- Check `semgrep_ingestion.global_enabled` is `true`.
