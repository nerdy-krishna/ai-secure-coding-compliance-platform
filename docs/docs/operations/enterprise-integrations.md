# Enterprise integrations

SCCAP enterprise integrations use tenant-owned service principals, encrypted credentials, explicit
feature grants, and a durable delivery outbox. GitHub App, Jira Cloud, and signed SIEM webhooks are
native connectors. GitLab, Azure DevOps, and Bitbucket use the authenticated CI submission contract
and the templates in `templates/ci/`.

## Outbound destination policy

Jira and SIEM hosts must be present as exact hostnames in the deployment-owned
`INTEGRATION_OUTBOUND_ALLOWED_HOSTS` JSON array. Tenant connector configuration may select a listed
host but cannot add one. `api.github.com` and the bounded archive hop `codeload.github.com` are fixed
built-ins.

Every outbound request resolves once, rejects any unsafe answer, connects to that exact IP, and
retains the original hostname for HTTP `Host`, TLS SNI, and certificate verification. Redirects are
disabled except for one GitHub archive redirect to `codeload.github.com`; the installation token is
not forwarded. Environment proxy discovery is disabled for this transport.

Private/on-prem SIEM destinations require an operator-owned exact hostname-to-IP mapping in
`INTEGRATION_OUTBOUND_HOST_PINS`. Pins bypass DNS. Loopback, link-local, multicast, unspecified, and
reserved addresses are always rejected. Increment `INTEGRATION_OUTBOUND_POLICY_REVISION` whenever
the operator policy changes. New connector rows snapshot that revision and a content fingerprint;
connector replacement/revocation and its actor remain auditable.

## Principals and grants

Create connectors under **Admin → Integrations**. Secrets are accepted only on create and persist as
Fernet ciphertext; read APIs return a fingerprint, never plaintext. Non-secret connector
configuration is validated against an exact schema for its connector kind; unknown keys, secret
aliases, and unbounded nested mappings are rejected rather than redacted and persisted. Grant
scopes are likewise exact and bounded. Grant only the required feature:

- GitHub source: `repository_contents_read`; SARIF: `security_events_write`; inbound metadata:
  `webhook_metadata_read`.
- Jira: `ticket_sync` with explicit `waived_status`, `reopen_status`, and transition IDs in
  `status_mapping`.
- SIEM: `siem_emit`.

GitHub installation tokens request only the permission for the current operation. Revoking one
grant immediately blocks that feature and dead-letters only its pending delivery class; revoking a
principal revokes every grant and dead-letters all of its pending delivery work.

## Signed SIEM delivery

The `sccap.integration.v1` JSON envelope contains stable event and idempotency IDs, immutable
`occurred_at`, a per-attempt `sent_at`, attempt-specific nonce, and metadata-only payload. The
`X-SCCAP-Signature` header is HMAC-SHA256 over the timestamp and exact canonical body. Consumers
must validate the five-minute timestamp window, reject a repeated nonce, bind an idempotency key to
one payload, and treat a later attempt with the same idempotency key as an idempotent redelivery.

Failures retry with bounded exponential delay. Expired worker leases are reclaimed; exhausted work
moves to the DLQ with append-only delivery evidence. Admins can explicitly retry a DLQ row after the
connector/grant is repaired.

## Jira ticket identity

Ticket identity is `(integration principal, canonical finding root)`. SCCAP searches by a stable
canonical label and serializes creation, so retries and concurrent status events reuse the same
ticket. Waiver grant/revoke/expiry events enter the durable outbox. Expiry reopens the existing
ticket, clears its waiver deadline, and appends history rather than creating another issue.

## CI and persisted policy

Copy the relevant file from `templates/ci/` and keep `SCCAP_TOKEN` in the provider's protected secret
store. The `trusted_context` request field is an assertion for provenance, not an authentication
boundary. The actual boundary is the CI provider withholding `SCCAP_TOKEN` from forks and other
untrusted jobs; those jobs must skip before the secret is attached. The helper script submits an
archive tied to a full 40-hex SHA-1 or 64-hex SHA-256 object ID, polls the persisted scan policy, and
downloads SARIF. Exit code `1` means the persisted policy outcome is `fail`; connectivity, timeout,
or a terminal scan without policy evidence returns `2` and is never represented as a policy failure.

The authenticated endpoints are:

- `POST /api/v1/integrations/ci/submissions`
- `GET /api/v1/integrations/ci/scans/{scan_id}/policy`
- `GET /api/v1/scans/{scan_id}/report?format=sarif`

The unauthenticated GitHub provider webhook is mounted separately at
`/api/v1/integrations/webhooks/github/{tenant_id}/{principal_id}`. It performs connector lookup,
native signature validation, replay binding, and metadata redaction; it is not part of the admin or
CI router.
