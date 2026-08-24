---
title: Frontend Quality Gates
sidebar_position: 4
---

# Frontend quality gates

SCCAP treats accessibility, responsive operation, and JavaScript weight as
build contracts. A route is not complete merely because it renders at a desktop
width.

## Route and live-update boundaries

Every top-level screen in `app/App.tsx` is loaded through `React.lazy`, a shared
Suspense state, and a route error boundary. `DashboardLayout`, `TopNav`, and
`ScanWatcher` remain in the eager entry chunk. Navigating to a large results or
diagnostics screen therefore does not replace the shell or tear down the
cursor-aware scan event watcher.

The shell owns shared loading, route-error, empty, offline, and reconnect
states. The connectivity banner is informational: it never reloads the page or
restarts a scan. SSE consumers retain responsibility for reconnecting from the
last event cursor.

## Accessibility and responsive contract

Authenticated pages share these requirements:

- one labelled primary navigation landmark and one focusable `main` landmark;
- a keyboard-visible skip link before the sticky application navigation;
- accessible names and expanded/selected/current states for icon buttons,
  menus, combobox options, and route links;
- modal initial focus, Tab containment, Escape close, and focus restoration;
- no document-level horizontal overflow at 390 px or 1280 px. Evidence and
  diff regions may scroll locally so content is never clipped;
- visible theme and account actions at supported widths; primary and admin
  navigation scroll or wrap instead of hiding actions;
- reduced-motion preferences disable nonessential animation.

`tests/browser/accessibility.spec.ts` inventories every authenticated route at
desktop and mobile viewports. It also runs Axe WCAG A/AA checks on dashboard,
submission, results, diagnostics, and usage, and protects the skip-link and
account-menu keyboard flow. Feature-disabled routes may redirect through their
normal guard, but the resulting authenticated shell must still satisfy the
contract.

Run the browser checks only against the disposable browser topology described
in [Verification Strategy](testing-strategy.md). Its fixture creates its own
principal and data; do not point it at a shared environment.

## Deterministic bundle budget

`npm run build` emits a Vite manifest and calls
`scripts/check-bundle-budget.mjs`. The checker uses uncompressed byte counts,
which avoids gzip-version variance, and fails when any limit is exceeded:

| Artifact | Limit |
| --- | ---: |
| eager entry JavaScript | 360 KiB |
| any asynchronous JavaScript chunk | 315 KiB |
| all JavaScript chunks | 1,200 KiB |
| any stylesheet | 64 KiB |

The limits are ceilings, not targets. If a feature legitimately requires more
code, split the route or expensive visualization first. Raising a ceiling
requires a reviewed size report and an explanation in the change that raised
it. CI repeats `npm run check:bundle` explicitly so a missing or stale manifest
cannot silently pass.

## Local verification

```bash
npm --prefix secure-code-ui run lint
npm --prefix secure-code-ui test
npm --prefix secure-code-ui run build
npm --prefix secure-code-ui run check:bundle
npm --prefix secure-code-ui exec playwright test -- --list
```

For a release or a change to navigation, dialogs, scan activity, results, or
diagnostics, also run the authenticated browser suite and inspect light/dark
themes at 390×844, 768×1024, and 1280×800. Automated checks deliberately do not
claim that every assistive-technology/browser combination has been manually
certified.
