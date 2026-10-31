---
sidebar_position: 1
slug: /
title: About SCCAP
---

# About SCCAP

**SCCAP — Secure Coding Compliance and Pentesting** — is an open-source platform that
audits source code against OWASP frameworks, proves each finding it reports, and then
attacks the deployed application. It runs as one installation with one login, on Docker
Compose, from a single host.

It exists because the two halves of application security are usually sold separately and
disagree with each other. A SAST report says "this pattern is unsafe"; a pentest report says
"this endpoint is exploitable". SCCAP keeps both in one place, on one data model, with the
same evidence discipline: everything it claims, it can point at.

## Two engines, one platform

**Code scanning** answers *what is wrong in the code and how do we fix it*. Deterministic
scanners run first — Bandit, Semgrep, Gitleaks and OSV — because they are cheap, fast and
reproducible. Then LLM agents analyse the files that deserve it, per file, against the
frameworks you selected. Every finding is consolidated to one root cause, scored with
CVSS 3.1, and attached to the exact source it refers to.

**Pentesting** answers *what can actually be reached and exploited*. An autonomous engine
discovers the attack surface beneath the origin you authorise, then drives real tools —
nmap, nuclei, ZAP, sqlmap, ffuf, a Playwright browser, whatweb, gobuster, hydra, hashcat —
one turn at a time through a model that sees every result and adapts. Findings are chained
into exploit paths, and a chain is only confirmed when a step demonstrated impact.

Both share the tenant model, the user and group visibility rules, encrypted credential
storage, the audit trail and the reporting layer.

## How the platform earns its claims

- **Nothing is hidden.** A zero-finding scan states what was scanned, what was skipped and
  why. The coverage ledger is per scanner and per input; the file table lists every scanned
  and excluded file with a reason code.
- **Nothing is overstated.** Severity follows the CVSS band computed from the weakness, not
  from a model's mood. A finding with no deterministic replay is marked `needs_review` and
  stays there. A scan stopped before the LLM phase is reported as
  `STOPPED_BEFORE_LLM` — not as complete, not as failed.
- **Nothing is lost.** Findings survive consolidation as contributors, survive a stop as
  results, survive a crash through the run heartbeat, and survive a rescan through a diff
  that says what is new, resolved and still open.
- **Secrets stay secret.** Discovered credentials are encrypted at rest, masked in the UI
  until revealed by an explicit audited action, and masked in reports unless the unmasked
  variant is requested deliberately.

## The scanning pipeline

1. **Submit** — files, pasted code, an archive, or a repository URL. One ingest manifest
   normalises paths, enforces caps and refuses a submission that would scan nothing.
2. **Classify** — every file is identified by evidence as first-party source, vendored,
   generated, runtime, lockfile, empty or binary.
3. **Pre-LLM scan** — deterministic scanners run over the eligible files. The scan pauses
   so you can read their findings before any code is sent to a model.
4. **Profile** — eligible files are profiled on a cheap utility model: what the file does,
   which security-relevant operations it performs, which domains apply.
5. **Estimate** — a dry run scoped to each file's routed agents produces a cost and duration
   estimate. The scan pauses again for your decision.
6. **Analyse** — specialised agents run under per-configuration concurrency, RPM/TPM and
   circuit-breaker limits. Every invocation is a durable task.
7. **Consolidate** — per-file, then cross-file. Duplicates become contributors, not noise.
8. **Validate** — optionally re-judged against cross-file callers and inputs.
9. **Report** — HTML, PDF, CSV, SARIF 2.1.0, or the raw scanner JSON for audit.

Each pause is a real decision point: approve, stop, or walk away and come back. Stopping
keeps everything the scanners already found.

## Who it is for

- **Developers** who want to know what is wrong with the change in front of them, with the
  code and a fix, not a PDF a week later.
- **Security engineers** who need findings that survive scrutiny — provenance, CVSS, replay
  evidence, and a clear statement of what was not covered.
- **Pentesters** who want reconnaissance, tooling and reporting automated without handing
  over scope control.
- **Compliance owners** who need per-framework coverage and an auditable trail of who
  approved what.
- **Operators** who want one Compose stack on one host, with upgrade, rollback and teardown
  that behave predictably.

## Principles

- **Deterministic before generative.** Cheap, reproducible tools first; models only where
  they add judgement.
- **Evidence over assertion.** Coverage, provenance, replay, lineage — the platform is built
  to be argued with.
- **Operator control.** Gates before spend, an explicit scope for pentesting, and a
  lifecycle you can reverse.
- **Open source, Apache 2.0.** Read it, run it, change it.

## Start here

- New to the platform? [Installation guide](./getting-started/installation.md).
- Running it day to day? [Maintenance and uninstallation](./getting-started/maintenance.md).
- Want the feature tour? [Platform features](./overview/features.md).
- Pentesting in detail? [Pentesting engine](./operations/pentesting-engine.md).
- Contributing? [Development guide](./development/contributing.md).
