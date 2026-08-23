---
title: Identity and Session Recovery
---

# Identity and Session Recovery

Use this runbook for browser-session compromise, IdP/SCIM outages, federation
key rollover, or tenant-domain verification failures. Preserve
`auth_audit_events`; identity deletion intentionally does not erase those
append-only identifiers.

## Suspected browser-session theft or reuse

1. Inspect the user's active sessions in **Security Settings**, or use the
   same-tenant administrator session endpoint.
2. Revoke the affected session. For an uncertain blast radius, revoke all of
   the user's sessions and reset the password or provider link.
3. Confirm the row has `revoked_at` and a reason. A replayed prior credential
   generation should record `credential_reuse` and a failed rotation audit
   outcome.
4. Search authentication audit records by user, session, provider, tenant, and
   correlation ID. Network values are keyed hashes and device values are coarse
   labels; do not expect plaintext IPs or full user-agent strings.

Do not clear only the browser cookie. Server-side revocation is the security
boundary and must commit before the response expires client storage.

## IdP outage

- Existing unexpired local sessions continue until their idle/absolute limit,
  unless the provider is configured to bind refresh to the IdP token expiry.
- Never disable issuer, audience, signature, lifetime, domain, or session checks
  to restore access.
- The designated master administrator retains the password-login escape hatch
  from forced SSO. Test that account during provider onboarding and key changes.
- Deleting a provider revokes all sessions minted through it.

## OIDC key rotation and logout

- Publish the new signing key in JWKS before using it. An unknown `kid` causes
  one bounded JWKS refresh; an unknown key after refresh is rejected.
- Discovery `issuer` must exactly match the configured issuer. Discovery and
  JWKS endpoints must remain public HTTPS targets.
- Configure the IdP back-channel logout URL as
  `/api/v1/auth/sso/{name}/backchannel-logout`. Logout JWTs must be signed,
  typed `logout+jwt`, recent, and carry the required event plus `sid` or `sub`.
  Replayed `jti` values are rejected.

## SAML certificate rollover and logout

- Add the new IdP certificate to `idp_x509_cert_rollover` before cutover. Up to
  three overlap certificates are accepted. Remove the retired certificate
  after the IdP rollover window.
- `sign_requests=true` requires the SP certificate and private key. Metadata,
  AuthnRequests, LogoutRequests, and LogoutResponses are signed accordingly.
- Keep the IdP SLO URL pointed at `/api/v1/auth/sso/{name}/slo`. Invalid or
  replayed signed messages must not revoke sessions.

## Tenant domain verification

1. Create a challenge under
   `/api/v1/admin/tenants/{tenant_id}/domains`.
2. Publish the returned value at
   `_sccap-domain-verification.<domain>` as a DNS TXT record.
3. Call the challenge's `/verify` endpoint. The one-time token is stored only
   as a hash.
4. Only after verification, add the domain to `allowed_email_domains`; forced
   domains must be a subset. Automatic/approval JIT requires at least one
   verified domain.

Deleting a verified domain immediately stops automatic routing and new
link/JIT decisions for that domain. Existing explicitly linked identities can
still authenticate until their provider or sessions are revoked.

## SCIM deprovisioning

`PUT`, `PATCH active=false`, and `DELETE` must leave the user inactive and
revoke all browser sessions in the same transaction. SCIM PATCH accepts a JSON
boolean or the interoperable strings `"true"`/`"false"`; other values are
rejected. Repeat delivery is safe and should leave access terminated.

If SCIM is unavailable, use the administrator user-deactivation and session
revoke-all operations, then reconcile the directory after service recovery.

## Deployment verification

Run migrations and the identity suites inside Docker:

```bash
docker compose exec app alembic upgrade head
docker compose exec app python -m unittest discover -s /app/tests -v
```

After changing browser auth, also run the frontend unit/build/lint gates and
the focused authentication browser project. Keep explicit Bearer API/MCP
clients separate from the browser-cookie contract during rollback; never
restore the retired SPA `localStorage.accessToken` path.
