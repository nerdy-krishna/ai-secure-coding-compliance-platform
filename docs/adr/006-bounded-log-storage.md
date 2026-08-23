# ADR-006: Bounded operational log storage

- Status: accepted
- Last verified: 2026-08-22

## Context

SCCAP is commonly self-hosted on a single Docker host. Unbounded container logs,
Fluentd buffering, or Loki retention can exhaust that host and take the scanning,
database, and evidence surfaces down together.

## Decision

Bound storage at each logging layer: configure per-container rotation, cap the
Fluentd disk buffer, apply finite Loki retention, and expose disk pressure to the
operator. Security-relevant application logs continue through the centralized
pipeline. Under sustained downstream failure, preserving host availability takes
precedence over unbounded buffering; any resulting loss must be observable.

## Consequences

One noisy or disconnected service cannot consume disk indefinitely. Operators
must choose retention that meets their regulatory obligations, monitor buffer
overflow and disk alerts, and export incident evidence before it ages out. These
operational logs complement, but do not replace, durable database audit records.
