# ADR-007: Immutable scan-attempt evidence storage

- Status: accepted
- Last verified: 2026-08-23

## Context

Resumed and restarted scans previously shared a scan-scoped JSONB artifact namespace. Large reports
could be overwritten or ambiguously attributed, and PostgreSQL alone did not provide independent
retention, legal-hold, versioned deletion, or envelope-key controls.

## Decision

Use a dedicated private S3-compatible evidence store (dedicated MinIO locally) and a stable
`ScanAttempt` identity. Resume keeps the attempt; restart creates a sequenced child. Evidence is
encrypted client-side with AES-256-GCM and a random per-object data key. Production wraps data keys
with an AWS KMS key; local development wraps them with a separate KEK.

PostgreSQL stores immutable object metadata and append-only hash-chained manifests. Metadata binds
tenant, scan, attempt, media type, exact object version, plaintext/ciphertext digests, authenticated
encryption context, producer, actor, timestamps, retention, and legal-hold state. Final terminal
roots are appended, not updated. Application downloads authorize visibility before exact-version
retrieval and verify authentication plus both digests.

Deletion is audited and two phase. Legal holds reject scheduling and owner deletion. The sweeper
deletes the exact version, removes its wrapped key, and preserves governance tombstones. Migration
uses expand/verify/contract: dual-read and optional dual-write, resumable backfill, verification,
then a later contraction. A verified object is authoritative; corruption never falls back to JSONB.

## Consequences

Retries are idempotent and changed payloads append generations. Earlier attempts survive restart
without ambiguity, and historical Semgrep rule bodies can support deterministic replay. Operations
must provision a private bucket and KMS policy, monitor deletion retries/orphans, preserve KMS key
access for the retention window, and complete migration verification before disabling legacy writes.
