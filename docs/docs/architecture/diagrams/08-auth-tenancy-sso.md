# 08 — Auth, SSO, SCIM, RBAC, Multi-tenancy

Every identity surface SCCAP exposes: password login, OIDC, SAML 2.0, WebAuthn passkeys, SCIM 2.0 provisioning, JWT token lifecycle, multi-tenant scoping, and group-based visibility.

---

## 1. Authentication surfaces (high-level)

```mermaid
flowchart LR
    subgraph Surfaces["End-user login surfaces"]
      Pwd["Password<br/>POST /auth/login"]:::edge
      OIDC["OIDC<br/>GET /auth/sso/authorize<br/>GET /auth/sso/callback"]:::edge
      SAML["SAML 2.0<br/>(same endpoints, protocol auto-detect)"]:::edge
      Pass["WebAuthn passkey<br/>/auth/webauthn/{begin,finish}-*"]:::edge
      Refresh["Refresh<br/>POST /auth/refresh"]:::edge
      Logout["Logout<br/>POST /auth/logout"]:::edge
    end

    subgraph Backend
      direction TB
      FU["fastapi-users<br/>UserManager<br/>CustomCookieJWTStrategy"]:::app
      Httpx["httpx-oauth (OIDC PKCE)<br/>discovery + JWKS + id_token verify"]:::app
      Saml["python3-saml<br/>signed assertion · ACS URL"]:::app
      WA["py_webauthn<br/>attestation + assertion + counter"]:::app
      JIT["JIT provisioning<br/>provisioning.py<br/>(allowed_email_domains, jit_policy)"]:::app
      Audit["auth audit middleware<br/>audit.py"]:::app
      DB[("Postgres<br/>user · oauth_accounts · saml_subjects<br/>webauthn_credentials · sso_providers<br/>auth_audit_events · scim_tokens · tenants<br/>user_groups · user_group_memberships")]:::data
    end

    Pwd --> FU
    OIDC --> Httpx --> JIT --> FU
    SAML --> Saml --> JIT --> FU
    Pass --> WA --> FU
    Refresh --> FU
    Logout --> FU
    FU --> DB
    Httpx -- audit --> Audit
    Saml -- audit --> Audit
    WA -- audit --> Audit
    Pwd -- audit --> Audit
    Audit --> DB

    classDef edge fill:#e0f2fe,stroke:#0369a1,color:#082f49;
    classDef app  fill:#e0e7ff,stroke:#4338ca,color:#1e1b4b;
    classDef data fill:#dcfce7,stroke:#15803d,color:#052e16;
```

---

## 2. OIDC SSO sequence (browser-side PKCE)

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant SPA as React SPA
    participant API as FastAPI /auth/sso
    participant IDP as OIDC IdP<br/>(Okta/Auth0/Entra/Google)
    participant DB as Postgres

    U->>SPA: click "Sign in with <provider>"
    SPA->>API: GET /auth/sso/authorize?provider_id=<id>
    API->>DB: load sso_providers row (encrypted config)
    API->>API: build PKCE: code_verifier, code_challenge<br/>state, nonce
    API-->>SPA: 302 to IdP authorize URL
    SPA->>IDP: GET /authorize (PKCE-S256)
    U->>IDP: authenticate · consent
    IDP-->>SPA: 302 to /auth/sso/callback?code=…&state=…
    SPA->>API: GET /auth/sso/callback (browser follows redirect)
    API->>IDP: POST /token (PKCE verifier, code)
    IDP-->>API: id_token (JWT) + access_token
    API->>API: verify id_token (RS256 via JWKS, iss, aud, exp, nonce)
    API->>DB: resolve user via oauth_accounts(provider_id, account_id)
    alt user exists
      API->>DB: update last_seen
    else first time
      API->>API: JIT decision<br/>(email domain ∈ allowed_email_domains, jit_policy)
      alt auto-create
        API->>DB: INSERT user + INSERT oauth_accounts
      else needs approval
        API->>DB: INSERT auth_audit_events (jit_pending)<br/>return 403
      end
    end
    API->>DB: INSERT auth_audit_events (sso_login_success, ip, ua, provider_id)
    API-->>SPA: 302 to /auth/sso/complete#access_token=<jwt>&exp=…
    SPA->>SPA: SsoCallbackPage extracts token from fragment<br/>loginWithAccessToken(jwt)
    SPA->>SPA: localStorage.setItem("accessToken", jwt)
    SPA->>SPA: schedule proactive refresh
```

---

## 3. JWT lifecycle (access + refresh)

```mermaid
flowchart LR
    subgraph Mint["Mint tokens"]
      A1["POST /auth/login (form)"]:::edge
      A2["POST /auth/sso/callback"]:::edge
      A3["POST /auth/webauthn/finish-assertion"]:::edge
    end

    subgraph Tokens
      AT["Access JWT<br/>HS/RS256 · exp = ACCESS_TOKEN_LIFETIME_SECONDS (60 min default)<br/>aud=api · claims: sub, tenant_id, is_superuser"]:::secret
      RT["Refresh JWT<br/>HttpOnly + Secure + SameSite=strict cookie<br/>exp = REFRESH_TOKEN_LIFETIME_SECONDS (7 d default)<br/>absolute cap = SESSION_ABSOLUTE_LIFETIME_SECONDS (24 h)"]:::secret
      SSE["SSE stream token<br/>aud=sse:scan-stream · 60 s TTL<br/>bound to scan_id"]:::secret
    end

    subgraph Use
      Axios["axios req interceptor<br/>Authorization: Bearer <AT>"]:::app
      Refresh["axios resp 401 →<br/>POST /auth/refresh (cookie auto-sent)<br/>+ proactive refresh 5 min before exp"]:::app
      Logout["POST /auth/logout<br/>clears localStorage + cookie"]:::app
    end

    A1 & A2 & A3 --> AT
    A1 & A2 & A3 --> RT
    AT --> Axios
    Axios -- "401" --> Refresh -- "new AT" --> Axios
    AT --> SSE
    Logout -- "clears" --> AT
    Logout -- "clears" --> RT

    classDef edge fill:#e0f2fe,stroke:#0369a1,color:#082f49;
    classDef app  fill:#e0e7ff,stroke:#4338ca,color:#1e1b4b;
    classDef secret fill:#fee2e2,stroke:#b91c1c,color:#450a0a;
```

---

## 4. Multi-tenancy & visibility scoping

```mermaid
flowchart TB
    Tenants[("tenants(id, name, created_at)")]:::data
    User[("user(id, email, tenant_id, is_superuser, …)")]:::data
    Groups[("user_groups · user_group_memberships")]:::data
    Project[("projects(tenant_id, user_id, name UNIQUE per user)")]:::data
    Scan[("scans(tenant_id, project_id, user_id, …)")]:::data
    Finding[("findings(tenant_id, scan_id, …)")]:::data
    Chat[("chat_sessions(tenant_id, user_id, …)")]:::data
    Dep["FastAPI dependencies:<br/>get_current_user_tenant_id()<br/>get_visible_user_ids()<br/>(user + group peers)"]:::app
    Routers["Every list/read endpoint<br/>(scans, projects, findings, chat, llm_logs, …)"]:::app

    Tenants --> User
    User --> Groups
    User --> Project --> Scan --> Finding
    User --> Chat
    Routers --> Dep
    Dep -- "tenant_id = current_user.tenant_id<br/>user_id IN visible_user_ids" --> Project
    Dep -- same filter --> Scan
    Dep -- same filter --> Finding
    Dep -- same filter --> Chat

    classDef app  fill:#e0e7ff,stroke:#4338ca,color:#1e1b4b;
    classDef data fill:#dcfce7,stroke:#15803d,color:#052e16;
```

---

## 5. SCIM 2.0 provisioning

```mermaid
sequenceDiagram
    autonumber
    participant IDM as External IAM (Okta / OneLogin / Entra)
    participant API as FastAPI /api/v1/scim
    participant DB as Postgres

    IDM->>API: GET /Users?filter=userName eq "alice@x"<br/>Authorization: Bearer <scim_token>
    API->>DB: validate scim_tokens row (active, not revoked)
    API->>DB: SELECT user WHERE email = 'alice@x'
    API-->>IDM: 200 { Resources: [{id, userName, emails, active, …}] }

    IDM->>API: POST /Users { ... }
    API->>DB: INSERT user (tenant scoped via token)
    API-->>IDM: 201 { id, userName, ... }

    IDM->>API: PATCH /Users/{id} { Operations: [...] }
    API->>DB: apply Add/Replace/Remove
    API-->>IDM: 200

    IDM->>API: DELETE /Users/{id}
    API->>DB: soft-delete (is_active = false) or hard delete
    API-->>IDM: 204

    IDM->>API: POST /Groups · PATCH /Groups/{id} (members)
    API->>DB: insert/delete user_group_memberships
    API-->>IDM: 200 / 204
```

---

## Legend

### Authentication mechanisms

| Mechanism            | Library              | Endpoints                                                                                            | Persistence                           |
|----------------------|----------------------|------------------------------------------------------------------------------------------------------|---------------------------------------|
| Password             | fastapi-users + passlib bcrypt | `POST /auth/login`, `POST /auth/register`, `POST /auth/forgot-password`, `POST /auth/reset-password` | `user.hashed_password`                |
| OIDC                 | httpx-oauth          | `GET /auth/sso/authorize`, `GET /auth/sso/callback` (provider auto-detected)                          | `oauth_accounts(provider_id, account_id, account_email)` |
| SAML 2.0             | python3-saml         | Same callback path (provider's metadata decides)                                                     | `saml_subjects(provider_id, name_id, subject)`           |
| WebAuthn (FIDO2)     | py_webauthn          | `/auth/webauthn/begin-registration`, `/auth/webauthn/finish-registration`, `/auth/webauthn/begin-assertion`, `/auth/webauthn/finish-assertion` | `webauthn_credentials(credential_id, public_key, sign_count, transports[])` |
| SCIM 2.0             | (hand-rolled)        | `/api/v1/scim/{Users,Groups,Schemas,…}`                                                              | `scim_tokens(active, last_used)`      |

### Token shapes

| Token            | Where                                  | TTL                                                                  | Audience            |
|------------------|----------------------------------------|----------------------------------------------------------------------|---------------------|
| Access JWT       | `localStorage.accessToken` + `Authorization: Bearer` | `ACCESS_TOKEN_LIFETIME_SECONDS` (default 3600 s)                  | `api`               |
| Refresh JWT      | HttpOnly + Secure + SameSite cookie    | `REFRESH_TOKEN_LIFETIME_SECONDS` (default 604 800 s) capped by `SESSION_ABSOLUTE_LIFETIME_SECONDS` (default 86 400 s, max 7 d) | `refresh` |
| SSE stream token | URL query param `?access_token=…`      | 60 seconds                                                           | `sse:scan-stream`   |
| SCIM bearer      | `Authorization: Bearer <token>`        | No expiry (rotatable; revocable via admin UI)                        | `scim`              |
| Passkey assertion challenge | Server-issued per attempt    | 60 s                                                                 | n/a                 |

### Refresh logic (client side, `apiClient.ts` + `AuthProvider.tsx`)

- **Proactive**: `PROACTIVE_LEAD_MS = 5 × 60 × 1000` — schedules a refresh 5 minutes before the access JWT's `exp`.
- **Reactive**: Axios response interceptor catches `401`, calls `refreshAccessToken()`, retries the original request.
- **Single-flight**: a module-level `refreshInFlight: Promise<string> | null` ensures only one refresh runs at a time.
- **Circuit breaker**: 3 consecutive refresh failures → 30 s blackout; further calls go straight to `/login`.
- **Cross-tab sync**: `storage` event listener + 5 s polling re-reads `accessToken` so multiple tabs stay aligned.

### Multi-tenancy scoping

Every privileged list/read endpoint depends on:

| Dependency                  | What it does                                                                          |
|-----------------------------|---------------------------------------------------------------------------------------|
| `get_current_user()`        | Resolves the JWT to a `User` row                                                      |
| `get_current_user_tenant_id()` | Returns `current_user.tenant_id` (or `DEFAULT_TENANT` for legacy rows)             |
| `get_visible_user_ids()`    | `{current_user.id} ∪ {user_ids in any user_group the user belongs to}`               |

Filters applied at the repository layer:

```sql
WHERE tenant_id = :tenant_id
  AND user_id   IN :visible_user_ids
```

Admins (`is_superuser=true`) bypass these filters; the auth audit middleware records the bypass for every privileged operation.

### Multi-tenancy tables

| Table                     | Tenant column        | Notes                                                                 |
|---------------------------|----------------------|-----------------------------------------------------------------------|
| `user`                    | `tenant_id` (nullable, backfilled `default`) | Tenant scope established at sign-up / JIT provisioning  |
| `projects`                | `tenant_id`          | Inherited from creator user                                           |
| `scans`                   | `tenant_id` (indexed) | Inherited from project                                                |
| `findings`                | `tenant_id`          | Inherited from scan (faster filtering than joining)                   |
| `chat_sessions`           | `tenant_id`          | Inherited from creator                                                |
| `llm_interactions`        | `tenant_id`          | Inherited from scan / chat session                                    |

### Master admin protection (M6)

A configurable `security.master_admin_user_id` system config key designates the bootstrap admin. The user-management endpoints refuse to:

- Demote the master admin (`is_superuser = false`)
- Deactivate the master admin (`is_active = false`)
- Delete the master admin

…even when called by another superuser. This prevents an admin lock-out.

### SSO provider table (`sso_providers`)

| Column                   | Notes                                                              |
|--------------------------|--------------------------------------------------------------------|
| `protocol`               | CHECK constraint: `oidc`, `saml`, `ldap`                           |
| `enabled`                | UI toggle                                                          |
| `config`                 | Fernet-encrypted JSONB. Secret fields (`client_secret`, `sp_private_key`) are redacted in API responses |
| `allowed_email_domains`  | Array of domains permitted to auto-create via JIT                  |
| `force_for_domains`      | Array; if matched, password login is rejected (`/auth/login-guard`)|
| `jit_policy`             | `auto` · `approve` · `deny`                                        |

PATCH accepts the sentinel `"<<unchanged>>"` for any secret field so admins can update non-secret fields without re-entering keys.

### Audit (`auth_audit_events`)

Single append-only table. Sample event types:

- `login_success`, `login_failure`
- `sso_login_success`, `sso_login_failure`, `sso_jit_pending`
- `webauthn_register_success`, `webauthn_assertion_success`
- `logout`, `refresh_success`, `refresh_failure`
- `PRESCAN_OVERRIDE_CRITICAL_SECRET` (cross-cutting M10)
- `mfa_enrolled`, `mfa_disabled`
- `scim_user_created`, `scim_user_deleted`

Stored fields: `ts`, `event`, `user_id`, `provider_id`, `ip` (after `TRUSTED_PROXY_CIDRS` resolution), `user_agent`, `email_hash` (PII protection), `details` (JSONB).

Exposed for export via `GET /api/v1/admin/sso/audit?cursor=…&limit=…` (cursor-paginated).

### CORS & origin handling

- `security.allowed_origins` (system config, hot-reloaded) is the source of truth — the FastAPI CORS middleware is wired against this cached list.
- `security.cors_enabled` flag toggles the middleware entirely.
- `FRONTEND_BASE_URL` and `API_BASE_URL` allow split-origin deployments (e.g., SPA on `app.example.com`, API on `api.example.com`).
- `TRUSTED_PROXY_CIDRS` (e.g., `10.0.0.0/8`) lists ranges from which `X-Forwarded-For` is honored — outside that, the proxy header is ignored to prevent IP spoofing in audit logs.

---

## Source files

- `src/app/api/v1/routers/{auth_login_guard,sso,webauthn,scim,admin_sso,admin_scim,admin_tenants,admin_users,admin_groups}.py`
- `src/app/infrastructure/auth/{audit,oidc,saml,provisioning,scim/filter}.py`
- `src/app/infrastructure/database/models.py` (`User`, `OAuthAccount`, `SamlSubject`, `WebAuthnCredential`, `SsoProvider`, `ScimToken`, `AuthAuditEvent`, `Tenant`, `UserGroup`, `UserGroupMembership`)
- `src/app/api/dependencies.py` (`get_current_user`, `get_current_user_tenant_id`, `get_visible_user_ids`)
- `secure-code-ui/src/app/providers/{AuthContext,AuthProvider}.tsx`
- `secure-code-ui/src/shared/api/{authService,ssoService,scimService,webauthnService,userGroupService,tenantService}.ts`
- `secure-code-ui/src/pages/admin/{SsoProvidersPage,SsoAuditPage,ScimTokensPage,UserManagement,UserGroupsPage,TenantsPage}.tsx`
