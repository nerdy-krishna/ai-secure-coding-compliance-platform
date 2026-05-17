---
sidebar_position: 2
title: Supported Frameworks
---

# Supported Frameworks

SCCAP ships with three baseline OWASP frameworks. The auto-seed
service (`default_seed_service.seed_defaults`) inserts them on a
fresh install; admins can re-seed them at any time via
**Admin → Frameworks → Restore defaults**.

## Defaults

### OWASP ASVS (`asvs`)

Application Security Verification Standard — the most comprehensive
of the three. Best for audit-style scans where you want every
control checked.

- **Ingestion mode**: CSV. The admin uploads a CSV with one row per
  requirement and the columns `control_id`, `title`, `content`,
  `framework_name`.
- **Typical use**: compliance reports, full-coverage audits.
- **RAG scope**: hundreds of rows; chunked into a few hundred
  vector-store entries.

### OWASP Proactive Controls (`proactive_controls`)

Developer-focused C1–C10 practices. Excellent chat context for the
Advisor.

- **Ingestion mode**: Git URL. The admin pastes the repo URL; the
  `rag_preprocessor_service` clones the tree, walks markdown, and
  chunks.
- **Typical use**: code-review guidance, secure-coding Q&A.

### OWASP Cheatsheets (`cheatsheets`)

Topic-specific guidance (SQL injection, XSS, JWT, session, etc.).
Great for on-demand retrieval in the Advisor.

- **Ingestion mode**: Git URL (same pipeline as Proactive Controls).
- **Typical use**: ad-hoc questions, snippet generation.

### CWE Essentials (`cwe_essentials`)

The MITRE CWE Top 25 Most Dangerous Software Weaknesses (2025
edition) plus selected related CWE-699 entries, organised into 14
concern-areas (memory safety, injection, authorization, concurrency,
and more). Covers non-web / systems code (C, C++, Rust, Go, OS
components, native programs) that the web-centric ASVS does not.
Opt-in; select it at scan time for systems / native codebases.

- **Ingestion mode**: CSV — the corpus is *bundled* with the
  platform at `src/app/data/cwe_essentials_corpus.csv`. Upload it via
  **Admin → Frameworks → CWE Essentials → Ingest docs → CSV** with
  scan-ready enabled. See
  [Updating Framework Knowledge](../development/updating-framework-knowledge.md)
  for the step-by-step.
- **Pinned edition**: CWE Top 25 (2025); the corpus is refreshed
  deliberately when MITRE republishes the list.
- **Typical use**: weakness-class audits of native / systems code.

### OWASP ISVS (`isvs`)

The OWASP IoT Security Verification Standard, organised into 7
concern-areas — secure development & provisioning, the device
application & data protection, firmware integrity & secure boot,
software-platform hardening, communication transport & cryptography,
pairing & network exposure, and the hardware platform. Covers
firmware, hardware, and device-communication concerns that neither
ASVS nor CWE Essentials address. Opt-in; select it at scan time for
IoT / embedded / connected-device codebases.

- **Ingestion mode**: CSV — the corpus is *bundled* with the platform
  at `src/app/data/isvs_corpus.csv` (content grounded in the OWASP
  ISVS standard). Upload it via **Admin → Frameworks → OWASP ISVS →
  Ingest docs → CSV** with scan-ready enabled. See
  [Updating Framework Knowledge](../development/updating-framework-knowledge.md)
  for the step-by-step.
- **Pinned edition**: OWASP ISVS 1.0.
- **Typical use**: security audits of IoT / embedded device code.

## Adding a custom framework

Admins navigate to **Admin → Frameworks → New framework**:

1. **Name** — short, lowercase, no spaces. Becomes the
   `framework_name` metadata on every RAG document + the
   `Scan.frameworks` tag used by the Compliance page.
2. **Description** — shown on the framework card.
3. **Ingestion** — pick CSV or Git URL. You can skip ingestion now
   and add docs later from **Admin → RAG**.
4. **Agent mapping** — check the agents that should run when a
   scan is tagged with this framework. The scan dispatcher
   respects this mapping per framework → finding-type combination.

## How frameworks interact with scans

At scan time, the submit UI shows every framework in the
`frameworks` table (defaults + custom) in the picker. The user's
selection goes into `Scan.frameworks` (JSONB array). The worker:

1. Passes the framework list into the `dependency_aware_analysis_orchestrator`.
2. The orchestrator dispatches each finding-type agent whose
   framework mapping includes at least one of the selected
   frameworks.
3. The chat agent, for sessions tied to the same project,
   retrieves RAG context scoped to the same frameworks.
4. The Compliance page aggregates `findings.scan_id → scans.frameworks`
   so every card reflects the right subset.

## Re-ingesting or removing a framework

- **Re-ingest**: re-upload the CSV or re-paste the Git URL. The
  existing framework documents are deleted from the Qdrant
  collection before the new ones land — it's idempotent.
- **Remove**: delete the framework row. Existing scans keep their
  tags (for historical rollup), but the framework disappears from
  the Compliance grid and the submit picker.

See
[Updating Framework Knowledge](../development/updating-framework-knowledge.md)
for the detailed step-by-step for re-ingestion.
