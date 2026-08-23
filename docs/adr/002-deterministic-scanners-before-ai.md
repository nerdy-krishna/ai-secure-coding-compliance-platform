# ADR-002: Deterministic scanners before AI analysis

- Status: accepted
- Last verified: 2026-08-22

## Context

Sending every file directly to an LLM is expensive and risks exposing secrets
that deterministic tools could detect first. Scanner results also provide useful
ground truth and provenance for later analysis.

## Decision

Run Bandit, Semgrep, Gitleaks, and OSV-Scanner before LLM analysis over bounded,
sandboxed staging input. Persist normalized findings with source provenance and
persist the CycloneDX SBOM emitted by OSV-Scanner. Persist validated native scanner
JSON and exact hash-verified Semgrep rule bodies in an encrypted, versioned,
attempt-scoped evidence object with a 5 MiB bound per native scanner payload.
If findings exist, pause for
operator approval. A critical secret requires an explicit override before any
customer code proceeds to configured LLM or observability destinations.

Scanner-derived context is untrusted input and must remain clearly delimited in
agent prompts. Scanner failures are surfaced as coverage warnings rather than
silently presented as a clean scan.

## Consequences

Operators see deterministic evidence before incurring AI cost, and consolidated
findings can preserve their origins. The worker image is larger and prescan adds
latency. Native scanner output is downloaded through the visibility-scoped API,
which decrypts the exact object version and verifies its digests. Legacy JSONB
artifacts remain readable during migration but integrity failures never fall back.
