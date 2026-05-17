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

## CWE Essentials (bundled corpus)

CWE Essentials is the one framework that ships its own RAG corpus in
the repository — it is *bundled*, not fetched from an upstream Git
repo. The framework, its 14 concern-area agents, and their prompt
templates are created automatically by the seed (and by the data
migration for existing deployments); only the RAG corpus is a
deliberate post-deploy step.

To populate it:

1. The corpus CSV lives at
   `src/app/data/cwe_essentials_corpus.csv`. It is generated from the
   per-concern-area markdown under
   `src/app/data/cwe_essentials_corpus/` — edit the markdown, never
   the CSV, then regenerate with
   `python scripts/build_cwe_corpus.py --write`.
2. Go to **Admin → Frameworks → CWE Essentials → Ingest docs →
   CSV** and upload `cwe_essentials_corpus.csv`.
3. The CSV carries an `id`, a `document` column, and a
   `concern_area` column. `concern_area` is the metadata facet each
   CWE Essentials agent filters retrieval on, so it must reach the
   vector store — keep it intact.
4. Ingest with **scan-ready** enabled so the corpus is visible to
   server-side scans (not only the Advisor chat).

Until the corpus is ingested, a CWE Essentials scan still completes —
its agents simply produce findings without RAG citations. After
ingestion the findings carry concern-area-grounded references.

**Edition + refresh path.** The corpus is pinned to the **CWE Top 25
(2025)** edition (recorded in each markdown file's frontmatter). MITRE
republishes the Top 25 annually; adopting a new edition is a deliberate
action — update the concern-area markdown, bump the `edition`
frontmatter, run `build_cwe_corpus.py --write`, and re-ingest.

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
