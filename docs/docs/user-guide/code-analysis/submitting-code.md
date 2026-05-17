---
sidebar_position: 1
title: Submitting Code
---

# Submitting Code

The **Submit** page handles every path that gets code into SCCAP.
Navigate there from the TopNav or via a primary CTA on the
Dashboard.

## Submission methods

Pick exactly one on the top of the page:

1. **File upload** — drag-and-drop files or browse. Useful for quick
   one-off reviews.
2. **Git repository** — paste a public Git URL. Click **Preview** to
   clone the repo into a temp dir, walk analyzable files, and
   populate the selective-files tree. The preview is destroyed after
   the walk — the full clone happens again inside the worker at
   scan time.
3. **Archive upload** — `.zip` or `.tar.gz`. Similar preview flow;
   the contents are extracted into the file tree for pruning.

## Selective-files tree

The tree under the submission method lets you check / uncheck paths
before estimation runs. Folders toggle their entire subtree. The
backend receives the full list of uploaded files but only runs the
scan on the checked paths — useful to exclude `node_modules/`,
`.venv/`, auto-generated test fixtures, etc.

## Choose frameworks

Multi-select. The default set is auto-checked if the user has never
saved preferences:

- **OWASP ASVS** — Application Security Verification Standard.
- **OWASP Proactive Controls**.
- **OWASP Cheatsheets**.

Custom frameworks (added by an admin under **Admin → Frameworks**)
appear below the defaults.

## Pick LLM slots

Two slots:

- **Utility** — a cheap model. Drives the per-file profiler and
  fix-snippet verification.
- **Reasoning** — a capable model. Drives the per-file analysis,
  finding consolidation, and the remediation merge agent.

You can use the same `LLMConfiguration` for both; the UI defaults
both to the first registered config, and a submitted utility slot
falls back to the reasoning config when omitted.

## Submit → estimate → approve

After you click **Start scan**:

1. The scan enters `QUEUED`. The UI navigates to the
   **Scanning in progress** page with a live SSE status stream.
2. The worker runs the **audit pass**: builds a repo map, bundles
   dependencies, tokenizes every prompt set, prices them via
   LiteLLM, and lands at `PENDING_COST_APPROVAL`. The page shows an
   estimate modal — tokens + USD — with **Approve** and **Cancel**.
3. On **Approve** the worker resumes the paused LangGraph thread and
   runs the deep analysis. The UI flips to a progress rail showing
   each pipeline stage.
4. On **Cancel** the scan is terminal at `CANCELLED`; the
   checkpointer state is preserved for admin inspection.

## After the scan completes

- Status flips to `COMPLETED` (or `REMEDIATION_COMPLETED` for
  remediation scans).
- The Results page (`/analysis/results/{scan_id}`) shows per-file
  findings, the SARIF viewer, and CTAs to apply fixes or download
  the Executive Summary PDF.
- The Dashboard + Projects page stats refresh on the next page
  load.

## Tips

- **Re-submitting** the same repo under the same project name reuses
  the project row; every scan row is immutable, so history survives.
- **Selective-files** is the biggest cost lever — pruning
  `node_modules/` before clicking Start can cut the estimate by
  >80%.
- **Selective framework scans** cost less. Running against all
  installed frameworks pulls more RAG context into every agent
  prompt than most scans need.
