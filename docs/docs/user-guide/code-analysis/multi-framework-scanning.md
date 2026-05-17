---
sidebar_position: 4
title: Multi-Framework Scanning
---

# Multi-Framework Scanning

Every scan can be tagged with one or more security frameworks. The
tag controls:

- Which **RAG context** is fed into the chat agent / advisor for
  sessions associated with the scan's project.
- How **Compliance page stats** roll up (findings are matched to
  frameworks via the `Scan.frameworks` JSONB column).

## Picking frameworks at submit time

The framework picker on the Submit page is a multi-select. SCCAP
ships with eight **bundled** OWASP frameworks; admins can add more
via **Admin → Frameworks**. See
[Supported Frameworks](../../security-frameworks/supported-frameworks.md)
for the full list + ingestion modes.

Bundled set:

- **OWASP ASVS** — application security verification controls.
  Best for comprehensive auditing.
- **OWASP Proactive Controls** (C1–C10) — developer-focused
  practices. Great chat context.
- **OWASP Cheatsheets** — topic-specific guidance (SQL injection,
  XSS, JWT, etc.).
- **CWE Essentials** — the MITRE CWE Top 25, for systems / native code.
- **OWASP ISVS** — IoT Security Verification Standard.
- **OWASP LLM Top 10** — weakness classes for LLM-integrated apps.
- **OWASP Agentic Top 10** — weakness classes for autonomous-agent apps.
- **OWASP MASVS** — Mobile Application Security Verification Standard.

## Framework tagging vs. RAG retrieval

A scan can be tagged with frameworks that don't have RAG documents
ingested yet — the tag still lets the Compliance page count findings
against the framework, but the chat agent won't pull context for it.
The Compliance page flags frameworks in this state with a
"Not configured" chip and (for admins) a shortcut to ingest the
knowledge base.

## Mixing default + custom frameworks

You can tag a single scan with any combination — one default (e.g.
ASVS) + one custom (e.g. your internal "SecureSDLC-2025"). The
orchestrator walks all tagged frameworks and dispatches the
appropriate specialized agents per framework → finding-type
combination. Duplicate findings across frameworks are deduped in
`correlate_findings`.

## Compliance posture per framework

The Compliance page shows one card per framework (default + custom).
Each card carries:

- RAG document count
- Total matched findings (across every scan tagged with this
  framework)
- Open findings (matched minus applied-in-remediation)
- Posture score (same heuristic as the Dashboard)
- Last-scanned timestamp

## Adding a custom framework

Admins go to **Admin → Frameworks → New framework**:

1. Give it a short name (lowercase, no spaces — becomes the
   `framework_name` metadata on RAG documents).
2. Optionally ingest docs from a Git URL or CSV now, or leave it
   empty and ingest later.
3. Map the agents that should run when the framework is selected
   (subset of the agents registered under **Admin → Agents**).

See [Updating Framework Knowledge](../../development/updating-framework-knowledge.md)
for the detailed ingestion walkthrough.
