# ADR-005: Self-hosted, fail-open LLM observability

- Status: accepted, opt-in
- Last verified: 2026-08-22

## Context

Parallel agent calls are difficult to diagnose from flat application logs. At
the same time, customer source and prompts cannot be sent to an unapproved SaaS
observability tenant.

## Decision

Support self-hosted Langfuse for hierarchical LLM traces and correlate it with
SCCAP logs through the request/scan correlation ID. Instrumentation is disabled
by default, validates its configured destination, never becomes authoritative
for scan cost, and fails open so an observability outage cannot fail a scan.

## Consequences

Opted-in operators gain prompt, completion, token, latency, and model trace data.
They also operate additional stateful services and must apply retention, access,
tenant-isolation, and offboarding controls. Langfuse's separate identity boundary
does not replace SCCAP audit events or the user-visible live-activity stream.
