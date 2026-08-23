---
sidebar_position: 1
title: Authentication
---

# Authentication

SCCAP uses fastapi-users with a JWT Bearer access token and a custom
HttpOnly refresh cookie. Public self-registration is not mounted: the
first-run `/setup` flow creates the initial superuser, and superusers create
later local accounts from **Admin → Users**.

## Login

```http
POST /api/v1/auth/login
Content-Type: application/x-www-form-urlencoded

username=user@example.com&password=...
```

The JSON body contains `{ "access_token": "...", "token_type": "bearer" }`.
The response also issues `SecureCodePlatformRefresh` as an HttpOnly,
SameSite=Strict cookie. It is Secure in normal deployments; the explicit
HTTP-only local-development profile disables Secure so localhost refresh can
work. Token responses are marked `Cache-Control: no-store`.

Access tokens default to 60 minutes (`ACCESS_TOKEN_LIFETIME_SECONDS`). Refresh
tokens default to seven days, but one login session has a 24-hour absolute
ceiling by default (`SESSION_ABSOLUTE_LIFETIME_SECONDS`).

## Refresh

```http
POST /api/v1/auth/refresh
Cookie: SecureCodePlatformRefresh=...
```

There is no request body and browser JavaScript cannot read the cookie. A valid
request returns a new access token and rotates the refresh cookie while
preserving the login session's original issue time. Inactive users, expired or
wrong-type tokens, an exceeded absolute lifetime, and an expired bound IdP
session are rejected with `401`.

The current refresh JWT is stateless: rotation does not yet provide one-time
reuse detection or a server-side device/session inventory. Those controls are
tracked in the production roadmap.

## Logout

```http
POST /api/v1/auth/logout
Authorization: Bearer <access_token>
```

Logout expires the refresh cookie, returns no-store headers, and asks the
browser to clear cache, cookies, and storage. The UI also cancels its proactive
refresh timer and clears the access token.

## Password reset

SMTP must be configured:

1. `POST /api/v1/auth/forgot-password` with the account email.
2. The backend emails a short-lived reset token.
3. `POST /api/v1/auth/reset-password` with `{ token, password }`.

## Admin-created users

Superusers create accounts through `POST /api/v1/admin/users`. When SMTP is
configured, the new user receives a password-setup/reset link.

## SSO, passkeys, and SCIM

- OIDC: `/api/v1/auth/sso/{name}/login` and `/{name}/callback`.
- SAML: `/api/v1/auth/sso/{name}/login`, `/{name}/acs`, and `/{name}/metadata`.
- Passkeys: `/api/v1/auth/webauthn/{register,login}/{begin,finish}` plus the
  authenticated credentials endpoints.
- SCIM 2.0: `/scim/v2`; administrator token management is under
  `/api/v1/admin/scim/tokens`.

## Setup gate

Until first-run setup finishes, the UI reads `/api/v1/setup/status` and routes
the operator to `/setup`. The setup endpoint creates the initial configuration
and user rather than relying on a public registration route.

## MCP authentication

The `/mcp` surface accepts the same Bearer access JWT through SCCAP's token
verifier. Expired tokens return `401`; a browser session can obtain a new access
token through `/api/v1/auth/refresh`.
