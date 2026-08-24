# Governed AI rule foundry

The rule foundry converts a human-confirmed AI-only finding into a reviewed, signed,
tenant-scoped deterministic rule when the finding is faithfully representable. It does not ingest
existing deterministic scanner findings, and it does not mutate global Semgrep source packs.

## Representation and native registries

A candidate is static only when its predicate is bounded, requires neither hidden runtime state nor
project-specific names, and is one of:

- AST or taint/source-sink: Semgrep candidate registry
- secret pattern: Gitleaks candidate registry
- dependency advisory: OSV-compatible candidate registry

Anything else remains an `ai_dataflow` candidate with a durable non-representable reason. The
candidate preserves CWE, severity, source/sink/data-flow evidence, canonical finding identity,
scan/attempt identity, and finding-lineage evidence.

## Authority and lifecycle

The stable permissions are `rule.candidate.create`, `rule.candidate.review`, and `rule.promote`.
Critical tenant separation of duties requires different creator, reviewer, and promoter users. Even
with SoD off, a creator/reviewer cannot self-promote.

The lifecycle is:

1. Create from a human-confirmed AI finding.
2. Run server-controlled quality evaluation during independent review.
3. Canonicalize and KMS-sign an immutable version.
4. Start tenant-scoped shadow execution.
5. Promote only after the shadow gate, or rollback to the prior signed version.

A later review creates a new version. Its shadow deployment carries the prior operational version;
promotion replaces it and rollback restores it. Events and shadow observations are append-only.
Unpromoted candidates expire after 30 days. Shadow deployments become review-required after 90
days. A system-scoped sweeper enforces both deadlines every 15 minutes across all tenants without
depending on UI/API traffic. Promoted versions do not auto-expire. Each promoted-pack runtime
failure degrades the current scan's coverage and appends one idempotent, source-free event per
candidate and distinct scan. Three distinct failed scans in 24 hours mark the deployment
review-required; one transient failure does not. The prior verified promoted version remains
operational while review is pending.

## Exact quality gates

Metrics are computed by SCCAP's native-tool sandbox and cannot be supplied by the API client. A
review passes only with:

- 100% vulnerable detection and 100% fixed/negative cleanliness
- zero duplicate stable identities
- identical output hashes across three runs
- at least one performance and one churn fixture, with all churn identities stable
- candidate median runtime no more than 2x the server baseline
- p95 per-file runtime below 500 ms
- at least 100 shadow-eligible files and no more than 1% unexpected matches

Gitleaks fixtures live in a dedicated source directory; the generated candidate configuration and
report remain outside the scan root so they cannot self-match.

## Signing and runtime safety

Set `RULE_FOUNDRY_KMS_KEY_ID` and optional `RULE_FOUNDRY_KMS_REGION` on both API and worker. The
signed canonical envelope binds tenant/candidate identity, native rule, fixtures, computed metrics,
lineage, and reviewer decision. Runtime selection recomputes SHA-256 from the stored canonical
payload, constant-time compares it with the stored digest, then verifies the KMS signature. Missing
KMS configuration, digest mismatch, invalid signature, tenant mismatch, or lineage mismatch skips
the version; it never falls back to unsigned content.

Promoted Semgrep and Gitleaks rules execute separately from global packs and retain native `source`
plus `foundry.<candidate_id>.<version_id>` rule provenance. Promoted OSV candidates match only exact
reviewed versions in the retained CycloneDX BOM. Shadow executions never create findings or affect
policy. They record only tenant/scan/attempt/deployment identity and capped eligible/unexpected
counts. Observation persistence is failure-isolated from scan execution.

Both API and worker images include the same pinned, hash-verified Gitleaks binary because review
quality evaluation occurs in the API process. Rebuild both images when changing the pinned version
or architecture checksum, then run native positive and negative fixture smoke tests.

## API and UI

The tenant-scoped endpoints are under
`/api/v1/admin/rule-sources/foundry/candidates`. They support paginated list, create, read, review,
shadow, promote, rollback, review-required, and expiry operations. Read access requires one of the
foundry capabilities or `audit.read`; every mutation checks its specific stable permission.

The Rule Sources administration page keeps global Semgrep sources and the tenant Rule Foundry in
separate panels. Candidate cards display native registry, representability, lifecycle state, signed
version, deployment state, shadow denominator/matches, expiry/review dates, and permission-gated
actions. An empty or unavailable observation set is not presented as a successful quality result.
