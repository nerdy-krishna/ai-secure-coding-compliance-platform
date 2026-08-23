# ADR-004: Unified CVSS-weighted risk scoring

- Status: accepted
- Last verified: 2026-08-22

## Context

Worker, dashboard, and compliance views previously calculated risk differently,
despite findings already carrying CVSS scores and vectors.

## Decision

`compute_cvss_aggregate` is the single scoring function. For each finding it uses
the parsed CVSS v3 vector, then numeric CVSS score, then a severity fallback. The
aggregate is the greater of the highest individual score and the severity-weighted
average, capped at 10.0. Dashboard and compliance posture derive from that value.

## Consequences

All surfaces share one risk story and legacy findings still score sensibly. The
`Scan.risk_score` integer column loses fractional precision, and historical rows
retain their old stored score until explicitly recalculated. Risk labels must be
derived from the aggregate; any fixed label is a presentation bug, not part of
this decision.
