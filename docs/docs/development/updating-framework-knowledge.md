---
sidebar_position: 5
title: Updating Framework Knowledge
---

# Updating Framework Knowledge

Every framework's knowledge base lives in the `security_guidelines`
Qdrant collection (replaced ChromaDB per ADR-008), tagged with
`framework_name` metadata. Admins can refresh a framework (replace
its docs) or add new frameworks. Both paths go through the same
ingestion pipeline.

## Ingest modes

### CSV (ASVS-style frameworks)

1. Go to **Admin → Frameworks** → click the target framework →
   **Ingest docs** → **CSV**.
2. Upload a CSV with the columns:
   - `control_id`
   - `title`
   - `content`
   - `framework_name` (should match the framework's name)
3. Hit **Start ingestion**. A `rag_jobs` row tracks progress.
4. The pipeline chunks long `content` values, embeds each chunk,
   and writes to Qdrant with the framework metadata intact.

### Git URL (Proactive Controls, Cheatsheets, most custom)

1. Go to **Admin → Frameworks** → click the target framework →
   **Ingest docs** → **Git URL**.
2. Paste a public Git URL (the repo where the framework's docs
   live).
3. Hit **Start ingestion**. `rag_preprocessor_service` clones the
   repo, walks markdown files, chunks them, embeds, and writes.

## What re-ingestion does

Re-ingesting a framework **replaces** its existing docs:

1. Delete every Qdrant point tagged with that `framework_name`.
2. Insert the freshly ingested ones.
3. Bump the framework's `updated_at` column.

Result: it's idempotent. Re-running the same ingestion leaves the
collection in the same shape.

## Adding a brand-new framework

**Admin → Frameworks → New framework**:

1. Short lowercase `name` (becomes the metadata tag).
2. Description (shown on the framework card).
3. Optionally run ingestion now — or leave empty and ingest later.
4. Map the agents that should run when a scan picks this
   framework.

## Background job + status

Ingestion runs in-process for now (no separate worker container).
The UI shows a spinner + the `rag_jobs` row's progress percentage.
Large Git repos (hundreds of files) can take a couple of minutes.

## Bundled corpora

Five frameworks ship their enriched RAG corpus inside the repository
rather than fetching it from an upstream Git repo:

- **OWASP ASVS** — 345 verification requirements across 17 chapters.
- **CWE Essentials** — 78 entries (one per CWE) across 14 concern-areas,
  grounded in the MITRE CWE Top 25 (2025).
- **OWASP ISVS** — 50 entries across 7 concern-areas, grounded in the
  OWASP IoT Security Verification Standard.
- **OWASP Proactive Controls** — 95 entries across the 10 controls.
- **OWASP Cheatsheets** — 112 entries across 10 domains.

For all five, the framework, its agents, and their prompt templates are
created automatically by the seed (and by the data migration for
existing deployments).

**The RAG corpus auto-ingests on app startup.** The corpora ship in the
repo already authored in the `**Vulnerability Pattern**` /
`**Secure Pattern**` layout the scan agents parse, so they are ingested
through the *raw* path — no LLM enrichment, no cost, no operator action.
The app lifespan runs the ingest once for any bundled framework whose
collection is still empty; subsequent boots leave a populated framework
untouched. Documents are tagged `scan_ready=True` and carry the metadata
facet the framework's agents filter retrieval on — `concern_area` for
CWE Essentials and ISVS, `control_family` for ASVS.

## Hybrid retrieval (dense + sparse)

Retrieval fuses a dense semantic vector (MiniLM-L6-v2) with a sparse
BM25 term-match vector via Reciprocal Rank Fusion, so exact security
terms (SSRF, XXE, ReDoS) that dense embeddings blur are still surfaced.
Each Qdrant collection therefore carries a named dense vector plus a
BM25 sparse vector.

**Upgrading from a pre-hybrid deployment:** the first boot on this
version detects the legacy single-vector collections and recreates them
with the hybrid layout — existing points are dropped. The bundled
corpora (ASVS, CWE Essentials, ISVS) re-ingest automatically on that
same startup. Any **admin-uploaded** content (Git-URL or CSV
frameworks) must be re-ingested manually afterwards from
**Admin → Frameworks → Ingest docs**, or it will be missing until
re-ingested.

To re-ingest manually (after editing a corpus, or to force a refresh):

```
docker compose exec app python scripts/ingest_bundled_corpora.py
```

This is idempotent — it replaces a framework's documents rather than
duplicating them.

The corpus CSVs are **generated**, never hand-edited. All five are
rendered from hand-authored enriched YAML by the same harness,
`scripts/build_enriched_corpus.py`:

- `asvs_corpus.csv` — from per-chapter YAML under
  `src/app/data/asvs_corpus/` (one file per ASVS chapter).
- `cwe_essentials_corpus.csv` — from per-concern-area YAML under
  `src/app/data/cwe_essentials_corpus/` (one file per concern-area,
  one entry per CWE).
- `isvs_corpus.csv` — from per-concern-area YAML under
  `src/app/data/isvs_corpus/`.
- `proactive_controls_corpus.csv` — from per-control YAML under
  `src/app/data/proactive_controls_corpus/` (one file per C1-C10).
- `cheatsheets_corpus.csv` — from per-domain YAML under
  `src/app/data/cheatsheets_corpus/`.

Each entry carries a security rule, vulnerability/secure pattern
descriptions, and per-language code samples. Edit the YAML, then
regenerate with
`python scripts/build_enriched_corpus.py --framework <name> --write`.
The authoring format is locked by `asvs_corpus/_ENRICHMENT_SPEC.md`.

Until a corpus is ingested, a scan against the framework still
completes — its agents simply produce findings without RAG citations.
After ingestion the findings carry concern-area-grounded references.

**Edition + refresh path.** Each corpus is pinned to an edition: ASVS
to **5.0.0**, CWE Essentials to the **CWE Top 25 (2025)**, ISVS to
**OWASP ISVS 1.0**. Adopting a newer edition is a deliberate action —
update the per-domain YAML, run
`build_enriched_corpus.py --framework <name> --write`, and re-ingest
with the command above.

## Sanity-checking

After ingestion, open **Admin → RAG** (or the framework card on the
Compliance page) to see the new document count. Start a chat
session scoped to the framework and ask a targeted question —
the Advisor should pull the fresh docs into the prompt.

## Removing a framework

Deleting a framework row from **Admin → Frameworks**:

- Removes the framework from the submit picker + Compliance grid.
- **Leaves** existing `scans.frameworks` tags in place (history
  survives).
- **Leaves** the Qdrant docs — the orphan `framework_name` points
  get filtered out of future retrievals since no session selects
  that framework anymore. Run **Admin → RAG → Prune orphans** to
  fully clean up.
