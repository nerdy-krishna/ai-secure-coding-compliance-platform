---
sidebar_position: 2
title: Secure Code Generation
---

# Secure Code Generation

The Security Advisor is a general-purpose chat surface — the same
framework-scoped RAG and the same agent pipeline described in
[Guideline-backed Q&A](./guideline-provision.md) cover code
generation, refactors, and code reviews.

## Use cases

- **Snippet generation** — "give me a parameterized query helper in
  Python that plays well with SQLAlchemy" while the session is
  scoped to OWASP Cheatsheets. The RAG injection pulls the
  SQL-injection cheatsheet so the generated helper follows the
  project's preferred pattern.
- **Refactor advice** — paste a snippet with an identified
  vulnerability, ask the advisor for a safer refactor, and get a
  diff-style suggestion.
- **Framework-aware code review** — link the session to a project
  so the right-rail surfaces the referenced findings; ask the
  advisor to walk through remediation priorities.

## Prompt patterns that work well

- Start with a concrete artifact or file location (even a
  pseudocode sketch); purely abstract questions get generic
  answers.
- Tell the advisor which language / framework the code targets —
  framework-scoped RAG helps but doesn't know your runtime.
- Use quick-reply chips as starting points, then refine.

## Caveats

- **Generated code is a suggestion, not a guarantee.** The Advisor
  is not a compiler / SAST tool; it's an LLM with curated context.
  Run a real SCCAP scan against the output before shipping.
- **Sessions are not shared.** Each Advisor session is owned by the
  creator. Groups only affect scan visibility — chat history stays
  private.
- **Context length**. Long sessions eventually exceed the model's
  window; `chat_service.post_message_to_session` compacts history
  transparently when needed, but you may notice the model
  "forgetting" very early turns in a very long conversation.

## Linking back to a scan

If the Advisor gives you a patch you want to apply, the cleanest
path is:

1. Copy the patch into your working copy.
2. Run a fresh SCCAP scan against the updated code (Submit page).
3. Review the new posture on the Projects + Dashboard pages.

For AI-suggested fixes produced by specialized agents during a scan,
use the
[Managing Findings](../code-analysis/managing-findings.md) flow
instead — SCCAP plans those against exact source ranges, rejects conflicts
for manual review, and promotes accepted patches during REMEDIATE scans.
