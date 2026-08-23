---
title: Frontend Services
sidebar_position: 4
---

# Frontend Services

`secure-code-ui/` is a React 18 + Vite + TypeScript app organized
feature-sliced:

```
secure-code-ui/src/
├── app/                   # providers, route guards, App shell
├── pages/                 # top-level route views
│   ├── auth/              # login / SSO callback / forgot / reset
│   ├── setup/             # first-run wizard
│   ├── account/           # dashboard + submission history
│   ├── admin/             # superuser-gated admin pages
│   ├── analysis/          # projects grid + results
│   ├── chat/              # security advisor
│   ├── compliance/        # per-framework posture
│   └── submission/        # submit + scanning progress
├── features/              # feature-scoped components
├── widgets/               # layouts (TopNav, DashboardLayout, Tweaks)
└── shared/
    ├── api/               # one service module per backend domain
    ├── hooks/             # useAuth, useTheme, etc.
    ├── types/             # hand-written + generated types
    └── ui/                # sccap design-system primitives
```

## API boundary

Every HTTP call goes through `shared/api/apiClient.ts` — a single
axios instance that handles:

- Base URL resolution (relative `/api/v1` when the UI is served from
  the same origin as the API; absolute when running Vite dev mode on
  `:5173`).
- Bearer token injection from `useAuth`.
- Automatic refresh on 401 via the custom `/auth/refresh` endpoint.

Domain services under `shared/api/` are thin wrappers that call into
this axios instance:

`authService`, `scanService`, `chatService`, `frameworkService`,
`agentService`, `promptService`, `ragService`, `llmConfigService`,
`systemConfigService`, `logService`, `complianceService`,
`dashboardService`, `searchService`, `userGroupService`, `seedService`.

## Routing + guards

`app/App.tsx` wires all routes under four guard variants:

| `requires` | Who sees it |
| ---------- | ----------- |
| `"root-redirect"` | `/` — forwards to `/login` or `/account/dashboard`. |
| `"unauth"` | Login / forgot / reset — redirects authenticated users away. |
| `"auth"` | Any authenticated user. Renders inside `DashboardLayout`. |
| `"superuser"` | `/admin/*` — requires `user.is_superuser`. Also renders inside `DashboardLayout`. |

Every guard redirects to `/setup` when
`isSetupCompleted === false`, so first-run deployments can't bypass
the wizard even by deep-linking.

## Layouts

### `DashboardLayout`

Wraps every authenticated route with:

- A sticky `TopNav` (brand, primary nav chips, global search combobox,
  theme toggle, role menu, notifications stub).
- The main content area.
- The floating `Tweaks` panel (theme / variant / accent preview).
- A conditional `AdminSubNav` strip rendered when the path starts
  with `/admin` or `/account/settings/llm` — gives admins one-click
  navigation between every admin surface.

### `AuthLayout`

Centered two-panel auth layout used by login / forgot / reset.

## State management

- **Server state**: TanStack Query. Keys are domain-prefixed
  (`["dashboard", "stats"]`, `["projects", search]`,
  `["chatSessions"]`, etc.). Mutations invalidate the relevant query
  keys on success.
- **Auth state**: `AuthProvider` in `app/providers/AuthProvider.tsx`
  holds the access token and user object; persists the refresh
  token via secure storage and automatically refreshes on load.
- **Theme + preview state**: `ThemeProvider` persists theme / variant
  / accent / role in localStorage. Roles are narrowed to
  `"user" | "admin"` as of H.3; legacy `dev` / `enterprise` values
  from the pre-H.3 era are migrated to `user` on read.

## Global search

`widgets/TopNav/SearchCombobox.tsx` is a 250 ms-debounced combobox
that hits `/api/v1/search?q=...`. Results are grouped Projects /
Scans / Findings; the dropdown supports arrow-key + Enter navigation
and Escape to close. See
[User Guide → Dashboard](../user-guide/dashboard-overview.md) for the
user-facing tour.

## Role preview vs. real admin

The Tweaks panel has a `Role preview` toggle (`user` / `admin`) that
swaps the Dashboard variant for design preview. This is **cosmetic
only**: the DashboardPage keys off the real `user.is_superuser` when
choosing between `UserDashboard` and `AdminSnapshot`, and every admin
route guard rejects non-superusers regardless of preview.

## Generated types

`shared/types/api-generated.ts` is generated from the running
backend's OpenAPI schema (`npm run generate:api`) and is committed so
frontend builds are reproducible without a live API. CI regenerates it
from the Compose API and fails on drift.

Endpoint boundaries derive types from concrete entries in the generated
`operations` map. The scan submission, result, and report calls use this
path so route parameters, query parameters, success bodies, validation
errors, and nullability change the TypeScript build when the backend
contract changes. `shared/lib/scanContract.ts` is the rendering boundary
for the few backend fields intentionally described as free-form JSON; it
discards malformed cost, temperature, fix, and affected-location values
before pages consume them. `shared/types/api.ts` remains a compatibility
facade and a home for genuinely frontend-only view models, not duplicate
endpoint response interfaces.

Regenerate and review after any API shape change:

```bash
SCCAP_OPENAPI_URL=http://127.0.0.1:8000/openapi.json npm run generate:api
git diff -- src/shared/types/api-generated.ts
npm run build
```
