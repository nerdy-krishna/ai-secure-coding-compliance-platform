---
sidebar_position: 1
title: Authentication
---

# Authentication

SCCAP separates browser and automation authentication. Browsers use an opaque,
server-side session in an HttpOnly cookie; API, MCP, and CI clients may use a
short-lived JWT Bearer access token. Public self-registration is not mounted: the
first-run `/setup` flow creates the initial superuser, and superusers create
later local accounts from **Admin → Users**.

## Login

```http
POST /api/v1/auth/login
Content-Type: application/x-www-form-urlencoded

username=user@example.com&password=...
```

The response retains `{ "access_token": "...", "token_type": "bearer" }` for
non-browser compatibility. The SPA does not persist or send that token. It uses
the opaque `__Host-SCCAPSession` cookie (`SCCAPSessionDev` only in the explicit
HTTP local profile), which is `Secure`, `HttpOnly`, `SameSite=Strict`, and scoped
to `/`. Token and session responses are marked `Cache-Control: no-store`.

Browser sessions default to a 60-minute inactivity deadline and a 24-hour
absolute deadline. Activity can move only the inactivity deadline. Every
password, OIDC, SAML, and WebAuthn login creates the same server-side session
record, including authentication method, provider, privacy-reduced device
metadata, current credential generation, and revocation state.

## Refresh

```http
POST /api/v1/auth/refresh
Cookie: SecureCodePlatformRefresh=...
```

There is no request body. Cookie-authenticated unsafe requests require the exact
configured Origin and an `X-CSRF-Token` obtained from
`GET /api/v1/auth/session/csrf`. Refresh rotates the opaque credential generation
with a database lock. Reuse of a prior generation revokes that session family;
inactive users, idle/absolute expiry, and expired bound IdP sessions return
`401`.

Session inventory and revocation endpoints are:

- `GET /api/v1/auth/sessions`
- `DELETE /api/v1/auth/sessions/{session_id}`
- `POST /api/v1/auth/sessions/revoke-others`
- same-tenant administrator variants under
  `/api/v1/admin/users/{user_id}/sessions`

Tenants may set a per-user concurrent-session limit. The default enforcement
mode is `deny_new`; `revoke_oldest` must be selected explicitly.

## Logout

```http
POST /api/v1/auth/session/logout
Cookie: __Host-SCCAPSession=...
Origin: https://app.example.com
X-CSRF-Token: ...
```

Logout first revokes the server-side row, then expires browser cookies and asks
the browser to clear cache, cookies, and storage. Bearer clients continue to use
`POST /api/v1/auth/logout`.

## Password reset

SMTP must be configured:

1. `POST /api/v1/auth/forgot-password` with the account email.
2. The backend emails a short-lived reset token.
3. `POST /api/v1/auth/reset-password` with `{ token, password }`.

## Admin-created users

Superusers create accounts through `POST /api/v1/admin/users`. When SMTP is
configured, the new user receives a password-setup/reset link.

## SSO, passkeys, and SCIM

- OIDC: `/api/v1/auth/sso/{name}/login`, `/{name}/callback`, and signed
  `POST /{name}/backchannel-logout`.
- SAML: `/api/v1/auth/sso/{name}/login`, `/{name}/acs`, `/{name}/metadata`,
  and signed GET/POST `/{name}/slo`.
- Passkeys: `/api/v1/auth/webauthn/{register,login}/{begin,finish}` plus the
  authenticated credentials endpoints.
- SCIM 2.0: `/scim/v2`; administrator token management is under
  `/api/v1/admin/scim/tokens`.

OIDC discovery is pinned to the configured HTTPS issuer and public endpoints;
algorithms are allowlisted and an unknown `kid` refreshes JWKS once. SAML strict
mode requires signed messages/assertions and an SP signing keypair, with up to
three temporary IdP rollover certificates. SAML assertions and federation
logout message IDs are claimed once in PostgreSQL to prevent replay.

Before an administrator can add a domain to an SSO provider or enable JIT, the
tenant must prove DNS ownership through the TXT challenge endpoints under
`/api/v1/admin/tenants/{tenant_id}/domains`. JIT users and group mappings remain
tenant-bound and cannot grant superuser status. SCIM `active=false`, identity
replacement, and deletion revoke active browser sessions in the same database
transaction.

## Setup gate

Until first-run setup finishes, the UI reads `/api/v1/setup/status` and routes
the operator to `/setup`. The setup endpoint creates the initial configuration
and user rather than relying on a public registration route.

## MCP authentication

The `/mcp` surface accepts the same Bearer access JWT through SCCAP's token
verifier. Expired tokens return `401`; a browser session can obtain a new access
token through `/api/v1/auth/refresh`.
