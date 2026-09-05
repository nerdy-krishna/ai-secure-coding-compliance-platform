# ADR-025: Target-agnostic iterative local assessment loop

- Status: accepted
- Date: 2026-09-05

## Context

The development product runner initially demonstrated Web validation with
fixture-specific routes and a fixed two-wave model interaction. That shape did
not preserve the Capability 4 design intent: the model should reassess newly
committed safe evidence until it concludes that no useful authorized action
remains, while deterministic code retains scope, execution, budget, and finding
authority. Fixture routes also prevented the same reviewed behavior from
working against another explicitly allowlisted local application.

## Decision

The local runner now performs target-agnostic discovery of exact-origin GET
form and query parameter names from bounded HTTP and browser observations. A
reviewed differential adapter may apply fixed control, quote-bearing, and inert
custom-element probes to those parameters. The model can select only the
adapter identifier; it cannot provide a payload, method, destination, command,
credential, or finding outcome. Evidence excludes parameter values, response
bodies, tokens, raw exceptions, and executable script behavior. It retains
only bounded response metadata, digests, and closed signal families.

After baseline discovery, a pinned model receives an allowlisted secret-free
projection and selects up to two still-untried authorized capabilities. The
same process repeats after each completed selection. The loop ends when the
model explicitly returns no tools and a completion reason, when deterministic
fallback completes the inventory after invalid/unavailable output, or when the
fixed round/duration policy terminates it. Every model call is idempotently
audited and every decision is policy-validated. With no model, deterministic
completion remains available.

Differential observations are parsed fail-closed by the Capability 6 bridge.
Only internally consistent confirmed signals can create candidates, and only
registered deterministic predicates plus the findings authority can verify and
promote them. Missing headers and generic HTTP metadata remain independent of
fixture-specific paths. The local execution profile remains development-only
and exact-origin allowlisted.

## Consequences

- The runner works against any explicitly configured local fixture origin; no
  production path or reviewed template encodes one fixture's application routes.
- The LLM conversation is a repeated advisory assessment loop instead of a
  fixed pair of turns, with explicit completion visible in activity history.
- Safety bounds remain deterministic: closed tools, exact origins, reviewed
  probes, bounded evidence, duration/round limits, and separate finding truth.
- This ADR does not make the local runner an unrestricted production scanner or
  supersede the formal Capability 4 controller's committed `DecisionDelta`
  authority model.
