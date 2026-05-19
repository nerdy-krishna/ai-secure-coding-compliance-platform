# 03 — Frontend Architecture

Detailed view of the SCCAP single-page application: build stack, routing, providers, service layer, real-time client, and asset pipeline.

---

## Diagram

```mermaid
flowchart TB
    User([Browser · End User]):::actor

    subgraph EdgeStack["Edge (sccap_ui container)"]
      Nginx["Nginx 1.25 (alpine)<br/>nginx-https.conf<br/>limit_req · gzip · OCSP stapling"]:::edge
      CertbotEntry["nginx-entrypoint.sh<br/>· Certbot renew loop (12 h)<br/>· fail-closed on missing cert"]:::edge
    end

    subgraph Build["Build pipeline (Vite 6.3 → /dist)"]
      Vite["Vite 6.3.5 · @vitejs/plugin-react (SWC)"]:::app
      TSC["TypeScript 5.8 (strict)"]:::app
      Gen["openapi-typescript 7.13<br/>npm run generate:api"]:::app
    end

    subgraph SPA["React 18.3 SPA · main.tsx"]
      direction TB

      subgraph Providers["Provider chain (App.tsx)"]
        QC["QueryClientProvider<br/>@tanstack/react-query 5.77"]:::app
        Feat["FeatureProvider<br/>· GET /features (public, pre-auth)<br/>· useFeatures() → isFeatureEnabled(name)<br/>· staleTime: Infinity"]:::gate
        Auth["AuthProvider<br/>· login / register / refresh<br/>· proactive 5 min before exp<br/>· cross-tab storage sync<br/>· circuit breaker (3 fails → 30 s)"]:::app
        Theme["ThemeProvider<br/>light/dark · variant A/B · accent<br/>localStorage: sccap-theme/variant/accent"]:::app
        ToastP["ToastProvider<br/>top-right · auto-dismiss 4.5 s"]:::app
      end

      subgraph Router["React Router v7.6"]
        RG["RouteGuard<br/>requires: unauth · auth · superuser · root-redirect<br/>+ feature gate (redirect when feature off)"]:::app
        LayoutA["AuthLayout"]:::app
        LayoutD["DashboardLayout<br/>+ TopNav + (admin) AdminSubNav<br/>nav links hidden by isFeatureEnabled()"]:::app
      end

      subgraph Pages["Page surfaces (pages/, features/, widgets/)"]
        direction LR
        PAuth["LoginPage · ForgotPasswordPage<br/>ResetPasswordPage · SsoCallbackPage"]:::app
        PSetup["SetupPage<br/>(4-step wizard)"]:::app
        PDash["DashboardPage<br/>UserDashboard · AdminSnapshot"]:::app
        PSubmit["SubmitPage<br/>· tabs: files / git / archive<br/>· ScanReadinessPanel<br/>· ScanCoverageWizard"]:::app
        PScan["ScanRunningPage<br/>· EventSource SSE client<br/>· PrescanReviewCard<br/>· CriticalSecretOverrideModal<br/>· Cost-approval UI"]:::app
        PResults["ProjectsPage · ProjectDetailPage<br/>ResultsPage · LlmLogViewerPage"]:::app
        PChat["SecurityAdvisorPage<br/>(3-col: sessions · thread · context)"]:::app
        PComp["CompliancePage<br/>(posture cards + ingest UI)"]:::app
        PAdmin["Admin pages (12+)<br/>SystemConfig · Users · Groups · Tenants<br/>· Agents · Frameworks · Prompts · SMTP<br/>· SSO · SCIM · AuthAudit · LLMConfigs · Findings"]:::app
        PSet["Account settings<br/>Appearance · Security · LLM · History"]:::app
      end

      subgraph Services["Service layer (shared/api/*.ts · 22 services)"]
        direction LR
        SAuth["authService<br/>+ admin user CRUD"]:::app
        SScan["scanService (332 lines)<br/>· createScan FormData<br/>· stream-token<br/>· approve · applySelectiveFixes"]:::app
        SChat["chatService"]:::app
        SFw["frameworkService"]:::app
        SAg["agentService"]:::app
        SLlm["llmConfigService"]:::app
        SRag["ragService (400 lines)<br/>· ingest · preprocess · approveJob"]:::app
        SComp["complianceService<br/>+ CSV export (file-saver)"]:::app
        SCfg["systemConfigService"]:::app
        SSso["ssoService"]:::app
        SGrp["userGroupService"]:::app
        STen["tenantService"]:::app
        SScim["scimService"]:::app
        SWa["webauthnService"]:::app
        SPrompt["promptService"]:::app
        SRules["ruleSourcesService"]:::app
        SDash["dashboardService"]:::app
        SLog["logService"]:::app
        SSeed["seedService"]:::app
        SFind["adminFindings"]:::app
        SSearch["searchService"]:::app
      end

      subgraph Client["HTTP client (shared/api/apiClient.ts)"]
        Axios["axios 1.9.0<br/>baseURL = VITE_API_BASE_URL || /api/v1<br/>withCredentials: true · maxRedirects: 0"]:::app
        ReqI["Request interceptor<br/>Authorization: Bearer (localStorage)"]:::app
        ResI["Response interceptor<br/>401 → refreshAccessToken() → retry<br/>(single-flight dedup)"]:::app
      end

      subgraph Realtime["Real-time (EventSource)"]
        SSEClient["EventSource(scans/{id}/stream?access_token=…)<br/>events: scan_state · scan_event · done<br/>retry: native + 30 s no-data safety net (max 5)"]:::app
      end

      subgraph Storage["Browser storage"]
        LS[("localStorage<br/>accessToken · sccap-theme · sccap-variant · sccap-accent")]:::data
        CK[("Cookies<br/>refresh_token (HttpOnly · Secure · SameSite)")]:::data
      end
    end

    %% ===== Backend =====
    Backend{{FastAPI /api/v1<br/>+ /auth · /scim · /scans · /chat · /compliance · /admin}}:::ext

    %% ===== Wiring =====
    User -- "HTTPS" --> Nginx
    Nginx -- "static SPA + cache headers" --> SPA
    Nginx -- "reverse proxy /api/v1/* → app:8000" --> Backend
    CertbotEntry -. "renders nginx-*.conf placeholders" .-> Nginx

    Vite --> TSC
    TSC --> SPA
    Gen -- "src/shared/types/api-generated.ts" --> Services

    Pages --> Providers
    Pages --> Services
    Services --> Axios
    Axios --> ReqI --> ResI --> Backend
    Auth <-- "JWT exp · proactive timer" --> LS
    Auth <-- "refresh cookie" --> CK
    PScan --> SSEClient
    SSEClient -- "SSE · text/event-stream" --> Backend
    Backend -. "GET /features (unauthenticated)" .-> Feat
    Feat -. "isFeatureEnabled() gates routes" .-> Router
    Feat -. "hides feature-off surfaces + nav" .-> Pages

    %% ===== Classes =====
    classDef actor fill:#fafafa,stroke:#475569,color:#0f172a;
    classDef edge  fill:#e0f2fe,stroke:#0369a1,color:#082f49;
    classDef app   fill:#e0e7ff,stroke:#4338ca,color:#1e1b4b;
    classDef data  fill:#dcfce7,stroke:#15803d,color:#052e16;
    classDef ext   fill:#ffe4e6,stroke:#9f1239,color:#4c0519;
    classDef gate  fill:#ede9fe,stroke:#6d28d9,color:#2e1065,stroke-dasharray: 4 3;
```

---

## Legend

### Build stack

| Tool                       | Version  | Role                                                                                      |
|----------------------------|----------|-------------------------------------------------------------------------------------------|
| React                      | 18.3.1   | UI library (automatic JSX runtime, `react-jsx`)                                           |
| TypeScript                 | 5.8.3    | Strict mode (`noUnusedLocals`, `noUnusedParameters`, `noFallthroughCasesInSwitch`)         |
| Vite                       | 6.3.5    | Bundler with `@vitejs/plugin-react` (SWC transform)                                       |
| @tanstack/react-query      | 5.77.2   | Server-state cache (123+ `useQuery`/`useMutation` hooks)                                   |
| axios                      | 1.9.0    | HTTP client (`maxRedirects: 0` to prevent auth-header leakage on redirect)                 |
| react-router-dom           | 7.6.1    | Routing                                                                                   |
| openapi-typescript         | 7.13.0   | Generates `src/shared/types/api-generated.ts` from FastAPI's `/openapi.json`               |
| file-saver                 | 2.0.5    | Report and CSV blob downloads                                                            |
| eslint-plugin-security     | latest   | Lints for unsafe React/DOM patterns                                                       |

### Provider chain (composed top-down in `App.tsx`)

| Provider              | File                                              | Stores                                                                                          |
|-----------------------|---------------------------------------------------|-------------------------------------------------------------------------------------------------|
| `QueryClientProvider` | `src/app/App.tsx`                                 | Single `QueryClient`; default stale time + retry                                                |
| `AuthProvider`        | `src/app/providers/AuthProvider.tsx`              | `user`, `accessToken`, `isLoading`, `error`, `isSetupCompleted`, `initialAuthChecked`           |
| `ThemeProvider`       | `src/app/providers/ThemeProvider.tsx`             | `theme: "light" \| "dark"`, `variant: "A" \| "B"`, `accent`; writes `data-theme`/`data-variant` to `<html>` |
| `ToastProvider`       | `src/shared/ui/Toast.tsx`                         | Toast queue (max 5, 4.5 s TTL)                                                                  |

### Routing (React Router v7)

| Guard            | Effect                                                        |
|------------------|---------------------------------------------------------------|
| `unauth`         | Auth'd users redirected to `/account/dashboard`               |
| `auth`           | Unauth'd users redirected to `/login`                         |
| `superuser`      | Requires `auth` **and** `user.is_superuser`                   |
| `root-redirect`  | `/` → `/account/dashboard` (auth) or `/login` (anon)          |

| Section            | Route                                          | Page component                          |
|--------------------|-------------------------------------------------|-----------------------------------------|
| Unauth             | `/login`                                       | `LoginPage`                              |
| Unauth             | `/forgot-password`                             | `ForgotPasswordPage`                     |
| Unauth             | `/reset-password`                              | `ResetPasswordPage`                      |
| Unauth             | `/auth/sso/complete`                           | `SsoCallbackPage`                        |
| Setup              | `/setup`                                       | `SetupPage` (4-step wizard)              |
| Dashboard          | `/account/dashboard`                           | `DashboardPage`                          |
| History            | `/account/history`                             | `SubmissionHistoryPage`                  |
| Settings           | `/account/settings/{appearance,security,llm}`  | `Appearance/Security/LLMSettingsPage`    |
| Submission         | `/submission/submit`                           | `SubmitPage`                             |
| Scan runtime       | `/analysis/scanning/:scanId`                   | `ScanRunningPage` (SSE)                  |
| Results            | `/analysis/results`                            | `ProjectsPage`                           |
| Results            | `/analysis/projects/:projectId`                | `ProjectDetailPage`                      |
| Results            | `/analysis/results/:scanId`                    | `ResultsPage`                            |
| LLM logs           | `/scans/:scanId/llm-logs`                      | `LlmLogViewerPage`                       |
| Chat               | `/advisor`                                     | `SecurityAdvisorPage`                    |
| Compliance         | `/compliance`                                  | `CompliancePage`                         |
| Admin              | `/admin/{system,users,user-groups,tenants,findings,agents,frameworks,prompts,smtp,sso/providers,sso/audit,scim/tokens,appearance}` | matching `*Page` / `*Tab` components |

### Service layer (`src/shared/api/*.ts`)

22 single-file services, each a singleton object exporting strongly-typed async methods. Highlights:

| Service                | LOC | Notable methods                                                                                                   |
|------------------------|-----|-------------------------------------------------------------------------------------------------------------------|
| `authService`          | —   | `loginUser`, `refreshToken`, `registerUser`, `getCurrentUser`, `logoutUser`, plus admin user CRUD                  |
| `scanService`          | 332 | `createScan(FormData)`, `previewGitRepo`, `previewArchive`, `getScanResult`, `getPrescanReview`, `approveScan`, `applySelectiveFixes`, `cancelScan`, `getStreamToken`, `getLlmInteractionsForScan`, `createProject`, `deleteScan`, `deleteProject` |
| `chatService`          | —   | `createSession`, `getSessions`, `getSessionMessages`, `askQuestion`, `deleteSession`, `getSessionContext`          |
| `frameworkService`     | 122 | Framework CRUD                                                                                                    |
| `agentService`         | 60  | Agent CRUD                                                                                                        |
| `llmConfigService`     | 148 | LLM configuration CRUD                                                                                            |
| `ragService`           | 400 | `ingestDocuments`, `preprocessDocuments` (per-framework in-flight dedup), `approvePreprocessingJob`, `getJobStatus`, `getEnrichedDocuments` |
| `complianceService`    | —   | `getFrameworkStats`, `getControlsForFramework`, `exportControlsAsCSV` (file-saver blob)                           |
| `systemConfigService`  | 177 | Get/list/update; cross-field guard `is_secret=true ⇒ encrypted=true`                                              |
| `ssoService`           | 163 | Provider CRUD + audit log                                                                                         |
| `userGroupService`     | 197 | Group CRUD + add/remove members                                                                                   |
| `tenantService`        | 45  | Multi-tenant CRUD                                                                                                 |
| `scimService`          | 54  | SCIM bearer-token management                                                                                      |
| `webauthnService`      | 219 | FIDO2 passkey registration + assertion                                                                            |
| `promptService`        | 117 | Prompt template CRUD                                                                                              |
| `ruleSourcesService`   | 91  | Semgrep cloud rule source CRUD                                                                                    |
| `dashboardService`     | —   | Dashboard stats endpoint                                                                                          |
| `logService`           | 44  | Per-scan `llm_interactions` log fetch                                                                             |
| `seedService`          | 50  | Trigger `POST /admin/seed`                                                                                        |
| `adminFindings`        | 55  | Admin-wide findings dashboard                                                                                     |
| `searchService`        | —   | Global search                                                                                                     |

### HTTP client wiring (`src/shared/api/apiClient.ts`)

- **Base URL** = `import.meta.env.VITE_API_BASE_URL || "/api/v1"`. In production the SPA is same-origin with the API so the relative path goes through Nginx's `/api/v1/*` proxy.
- **Request interceptor** reads `localStorage.accessToken` and sets `Authorization: Bearer …`.
- **Response interceptor** intercepts `401`, calls `refreshAccessToken()`, retries the original request with the new token. Single-flight dedup via a `refreshInFlight` promise; on three consecutive failures the breaker opens for 30 s.
- **Proactive refresh** decodes the JWT `exp` and schedules a refresh `5 min` before expiry (`PROACTIVE_LEAD_MS = 5 * 60 * 1000`). Reset on every successful login / refresh.

### Real-time SSE client (`pages/submission/ScanRunningPage.tsx`)

```text
1. POST /api/v1/scans/{id}/stream-token  →  { access_token, expires_in: 60 }   (audience "sse:scan-stream")
2. new EventSource(`/api/v1/scans/{id}/stream?access_token=${access_token}`, { withCredentials: true })
3. es.addEventListener("scan_state", …)   // status transitions; carries cost_details
4. es.addEventListener("scan_event", …)   // per-stage / per-file progress
5. es.addEventListener("done", …)         // terminal status; close stream and redirect
```

Includes a 30-second no-data safety timer and a max-5-retry frontend bound on top of the browser's native EventSource backoff.

### Theming & accessibility

- CSS custom properties live in `src/app/styles/tokens.css` (colors `--bg`, `--fg`, `--primary`, `--accent`, …, radii `--r-xs` … `--r-pill`, motion `--ease`, shadows).
- Theme switching writes `data-theme` and `data-variant` to `<html>`.
- Fonts: **Inter Tight** / **Inter** (UI) · **JetBrains Mono** (code).
- No i18n layer today — UI text is English-only.

### Browser storage

| Item            | Storage          | Why                                                                          |
|-----------------|------------------|------------------------------------------------------------------------------|
| `accessToken`   | `localStorage`   | Needs to be read by axios interceptor; risk accepted (V15.1.5) with CSP + sanitized React |
| `refresh_token` | HttpOnly cookie  | Inaccessible to JS; sent on `/auth/refresh` via `withCredentials: true`       |
| `sccap-theme`, `sccap-variant`, `sccap-accent` | `localStorage` | Theme persistence; synced cross-tab via `storage` event |

### Feature-flag gating (modular setup — #103–111)

`FeatureProvider` fetches the enabled-feature set once from the **public, unauthenticated** `GET /api/v1/features` (so route guards and the login page can decide before any user exists). `useFeatures()` exposes `isFeatureEnabled(name)`; it fails *open* — while `/features` is in flight every feature reads as enabled, so a slow fetch never flashes a stripped-down UI. Each route guard, `TopNav`/`AdminSubNav` link, and feature-scoped surface consults it. `scan` is `always_on` — the product floor is never gated off.

| Feature           | Frontend surface gated off when disabled                                                  |
|-------------------|--------------------------------------------------------------------------------------------|
| `scan`            | — (always on: submission, scan runtime, results, dashboard)                                |
| `chat`            | `/advisor` route + `SecurityAdvisorPage`, TopNav **Advisor** link                          |
| `compliance`      | `/compliance` route + `CompliancePage`, TopNav **Compliance** link                         |
| `multi_user`      | `/admin/users`, self-service registration                                                  |
| `user_groups`     | `/admin/user-groups`, group-membership UI                                                   |
| `sso`             | SSO buttons on `LoginPage`, `/admin/sso/providers` + `/admin/sso/audit`                     |
| `scim`            | `/admin/scim/tokens`                                                                         |
| `multi_tenant`    | `/admin/tenants`                                                                             |
| `email`           | `/forgot-password` + `/reset-password` flow                                                  |
| `log_stack`       | `LlmLogViewerPage`, `/scans/:scanId/llm-logs`, LLM-log links on results                      |
| `tracing`         | — (no dedicated SPA surface; Langfuse has its own UI — see diagram 10)                       |
| `mcp`             | — (no SPA surface; the `/mcp` tool endpoint is backend-only)                                 |
| `admin_authoring` | `/admin/{agents,frameworks,prompts}` + RAG ingest UI                                         |

A disabled feature is enforced server-side too: `bootstrap_enabled_features_sync()` skips mounting the corresponding routers at import time, so hiding a link is defence-in-depth, not the security boundary.

### Code-gen flow

```text
npm run generate:api
└─► fetch ${SCCAP_OPENAPI_URL:-http://localhost:8000/openapi.json}
└─► openapi-typescript → src/shared/types/api-generated.ts
└─► hand-maintained facade in src/shared/types/api.ts re-exports + adds UI-only types
```

---

## Source files

- `secure-code-ui/package.json`, `vite.config.ts`, `tsconfig*.json`
- `secure-code-ui/src/main.tsx`, `src/app/App.tsx`
- `secure-code-ui/src/app/providers/{AuthContext,AuthProvider,ThemeProvider}.tsx`
- `secure-code-ui/src/shared/api/*.ts` (22 services)
- `secure-code-ui/src/shared/api/apiClient.ts`, `authService.ts`
- `secure-code-ui/src/pages/**/*.tsx`, `src/features/**/*.tsx`, `src/widgets/**/*.tsx`
- `secure-code-ui/Dockerfile`, `nginx-http.conf`, `nginx-https.conf`, `nginx-entrypoint.sh`
