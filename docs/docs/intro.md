---
sidebar_position: 1
slug: /
title: Introduction
---

# Welcome to the SCCAP!

The SCCAP is an open-source, AI-powered platform meticulously designed to empower developers and security teams in the crucial task of building and maintaining secure software. We are driven by the mission to proactively embed security into the software development lifecycle.

## The Challenge We Address

In today's fast-paced development environment, ensuring code security from the outset can be challenging. Traditional reactive approaches often identify vulnerabilities late in the cycle, leading to costly rework and increased risk. The SCCAP aims to shift security left, making it an integral and accessible part of development from day one.

## What We Offer: Core Capabilities

SCCAP integrates a multi-agent LLM pipeline with curated security
knowledge bases. The platform is organized around three surfaces:

### For developers and security users

* **Live dashboard** — a real risk ring, five-bucket severity bar, 14-day scan trend sparkline, fixes-ready counter, and monthly LLM spend. Admins see a platform-wide snapshot variant.
* **Two-phase, user-approved scan** — every scan runs a cheap audit pass first, estimates cost via LiteLLM's model-price map, pauses the LangGraph workflow with a native `interrupt()`, and waits for your `/approve` before the deep analysis runs.
* **Versatile submission** — file uploads, Git repository URLs, or archive uploads (`.zip` / `.tar.gz`). An interactive file tree lets you include or exclude paths before estimation.
* **Multi-framework scanning** — pick any combination of the 3 default OWASP frameworks (ASVS, Proactive Controls, Cheatsheets) plus custom frameworks ingested from CSV or Git URLs.
* **Intelligent, incremental remediation** — choose findings, let specialized agents generate fixes, merge via a dedicated conflict-resolution agent, and download the patched tree.
* **Per-project stats on the Projects page** — each card shows the latest terminal scan's risk score, severity bar, and fixes-ready count, no client-side heuristics.
* **Global search** — one TopNav combobox across projects, scans, and findings, always scoped to what the current user is allowed to see.
* **Security Advisor with live context rail** — framework-scoped chat backed by RAG retrieval, with a right-hand rail that surfaces the knowledge sources, referenced findings, and files most likely discussed.

### For security admins

* **User Groups + scoped visibility** — admins create groups and add members by email; regular users see their own scans plus any scan owned by a peer they share a group with; admins see everything.
* **First-run setup wizard** — the first registered account becomes superuser and is routed through `/setup` before the rest of the app unlocks.
* **Unified Admin console** — LLM configurations, user groups, users, frameworks (with CSV / git-URL RAG ingestion), agents, prompt templates, SMTP, system config, and runtime logs. A shared sub-nav keeps every surface one click apart.
* **Encrypted secrets** — every LLM API key and SMTP password is Fernet-encrypted at rest with the installation's `ENCRYPTION_KEY`.

### Integrations and automation

* **MCP server** — the scan + advisor workflow is exposed as MCP tools at `/mcp`, reusing JWT auth so Claude Code, Cursor, or other agentic clients can drive the platform remotely.
* **LiteLLM-backed cost ledger** — token counting and cost estimation go through LiteLLM's community-maintained model price map, with a per-`LLMConfiguration` admin override for bespoke endpoints. Offline-pinnable via `LITELLM_LOCAL_MODEL_COST_MAP=True`.
* **Pydantic AI structured output** — every agent returns a validated Pydantic model; malformed outputs trigger a typed retry loop instead of regex fallbacks.
* **Observability** — every request gets an `X-Correlation-ID` attached to all logs; the stack ships Fluentd → Loki → Grafana dashboards out of the box.

## Our Vision & Guiding Principles

* **Comprehensive & Open Source**: We are committed to building a "full scope from day 1" platform, released under an open-source license to foster community collaboration and transparency.
* **Multi-Methodology Integration**: The platform incorporates a hybrid approach using Large Language Models (differentiated for thinking vs. code-writing), specialized security tools (SAST, SCA), dynamic Tree-sitter queries, and comprehensive Retrieval Augmented Generation (RAG) over multiple security frameworks.
* **User-Centric Design**: We aim for a user-friendly experience through intuitive chat interfaces and a detailed code analysis portal.
* **Community Driven**: We believe in the power of community to build and enhance tools that benefit everyone. We encourage contributions and feedback.

## Who Is This For?

* **Developers**: Write more secure code efficiently with AI-assisted guidance and generation.
* **Security Teams**: Streamline code reviews, enforce security standards, and gain deeper insights into application security posture.
* **DevSecOps Engineers**: Integrate automated security analysis seamlessly into CI/CD pipelines.
* **Organizations**: Reduce the risk of security breaches and ensure compliance with various standards.
* **Students & Educators**: Learn and teach secure coding practices with a practical, hands-on tool.

## Dive In!

This documentation will guide you through every aspect of the SCCAP.

* **New to the platform?** Start with our [**Installation Guide**](./getting-started/installation.md) to get your local instance up and running.
* **Want to see it in action?** Check out the [**User Guide**](./user-guide/index.md) for tutorials on our key features.
* **Interested in contributing?** Head over to our [**Development Guide**](./development/contributing.md).

We're excited to have you join us on this journey to make software more secure!