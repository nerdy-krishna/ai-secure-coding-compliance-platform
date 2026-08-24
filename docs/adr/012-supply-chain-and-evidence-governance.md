# ADR-012: KMS-first supply chain and cross-store evidence governance

**Status:** Accepted
**Date:** 2026-08-24

## Context

SCCAP evidence spans PostgreSQL, a versioned object store, Qdrant, and observability systems. A
database-only retention or deletion action can therefore produce a false completion claim. Releases
also need independently verifiable dependencies, provenance, and signatures in public and private
delivery environments.

## Decision

- Production secret and evidence envelopes use AWS KMS. Local KEKs exist only for development and
  injected tests. New data uses the primary key; old key identifiers remain decryptable during a
  bounded rotation window and successful reads lazily rewrap only the DEK. AWS rotation uses
  `ReEncrypt`, so plaintext DEKs do not enter application memory.
- Release images publish deterministic CycloneDX 1.6 and SLSA provenance v1 predicates. Cosign uses
  GitHub OIDC keyless signing for public releases and a workload-identity-authorized KMS URI for
  private releases.
- Restricted-egress updates are deterministic tar archives containing all three mandatory
  components: scanner runtimes, governed rules, and advisory data. A KMS signature covers the
  canonical manifest. Activation uses immutable release directories and an atomic `current`
  symlink; rollback selects the prior verified digest.
- Retention defaults are transactional/audit/evidence/vector 365 days, LLM/logs 30 days, and backup
  35 days. Transactional and audit tenant overrides are rejected until their durable tenant-aware
  sweepers exist; evidence/vector/backup retention may be lengthened, while LLM/log retention may
  be shortened or lengthened within the 1–3650 day deployment bound. Effective overrides are
  snapshotted into governance operations and applied to future writes. An active
  tenant/project/scan/attempt/evidence legal hold overrides every deletion path, including a broad
  deletion whose descendants contain a narrower hold.
- Export and deletion use one durable operation plus four per-store actions. Store calls are
  idempotent by operation UUID, leased for crash recovery, separately applied and verified, and only
  then summarized in a KMS-signed export manifest or deletion tombstone.
- A restore is acceptable only when the runtime role cannot bypass RLS; forced tenant policies and
  same/cross-tenant probes pass; outbox and checkpoint state is resumable; connector/policy state is
  structurally valid; and manifest, object, and governance signatures verify.

## Consequences

Cross-store deletion is deliberately asynchronous. A provider outage leaves visible durable work,
not a false success. Operators must retain old KMS decrypt permissions until lazy rotation coverage
is complete. Private Cosign signing requires a runner with workload identity authorized for the KMS
key; long-lived cloud credentials are not stored in GitHub or SCCAP.
