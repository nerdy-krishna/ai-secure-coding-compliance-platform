// secure-code-ui/src/shared/ui/Breadcrumbs.tsx
//
// One breadcrumb trail for every page in the authenticated shell.
//
// It is rendered by the layout rather than by each page, so a new route gets
// breadcrumbs automatically and the trail cannot drift between screens. Pages that
// render their own trail (via `PageHeader`, which knows dynamic names like a
// project or run title) register through the context below and this component then
// stays out of the way — one trail per page, never two.

import React, { createContext, useContext, useEffect, useMemo, useState } from "react";
import { Link, useLocation } from "react-router-dom";

interface BreadcrumbRegistration {
  register: () => () => void;
  count: number;
}

const BreadcrumbContext = createContext<BreadcrumbRegistration>({
  register: () => () => undefined,
  count: 0,
});

/**
 * Called by a page that renders its own breadcrumbs (`PageHeader` does this).
 * Keeps the layout trail hidden for that page.
 */
export function useRegisterBreadcrumbs(): void {
  const { register } = useContext(BreadcrumbContext);
  useEffect(() => register(), [register]);
}

interface Crumb {
  label: string;
  to?: string;
}

const ADMIN: Crumb = { label: "Administration", to: "/admin/system" };
const CODE_SCAN: Crumb = { label: "Code scanning", to: "/submission/submit" };
const PENTEST: Crumb = { label: "Pentesting", to: "/pentesting" };
const ACCOUNT: Crumb = { label: "Account", to: "/account/dashboard" };

/**
 * Explicit trails, keyed by route.
 *
 * The menu groups are the vocabulary: a page under Administration reads
 * "Administration / <page>", a code-scanning page reads "Code scanning / <page>",
 * even when its URL lives under /account. Unknown routes fall back to a trail
 * derived from the path.
 */
const TRAILS: Record<string, Crumb[]> = {
  "/account/dashboard": [],
  "/submission/submit": [CODE_SCAN, { label: "New scan" }],
  "/analysis/results": [CODE_SCAN, { label: "Projects and scans" }],
  "/account/history": [CODE_SCAN, { label: "Submission history" }],
  "/pentesting": [PENTEST, { label: "Projects and scans" }],
  "/pentesting/new": [PENTEST, { label: "New pentest" }],
  "/pentesting/history": [PENTEST, { label: "Submission history" }],
  "/advisor": [ADMIN, { label: "Security advisor" }],
  "/compliance": [ADMIN, { label: "Analysis config" }, { label: "Security standards" }],
  "/admin/analysis": [ADMIN, { label: "Analysis config" }],
  "/usage": [ADMIN, { label: "Usage" }],
  "/account/settings/appearance": [ACCOUNT, { label: "Appearance" }],
  "/account/settings/security": [ACCOUNT, { label: "Security" }],
  "/account/settings/llm": [ADMIN, { label: "LLM configs" }],
  "/admin/system": [ADMIN, { label: "Platform" }],
  "/admin/features": [ADMIN, { label: "Features" }],
  "/admin/appearance": [ADMIN, { label: "Appearance" }],
  "/admin/smtp": [ADMIN, { label: "SMTP" }],
  "/admin/rag": [ADMIN, { label: "Knowledge base" }],
  "/admin/sso/providers": [ADMIN, { label: "SSO providers" }],
  "/admin/sso/audit": [ADMIN, { label: "Auth audit" }],
  "/admin/scim/tokens": [ADMIN, { label: "SCIM tokens" }],
  "/admin/integrations": [ADMIN, { label: "Integrations" }],
  "/admin/users": [ADMIN, { label: "Users" }],
  "/admin/user-groups": [ADMIN, { label: "Groups" }],
  "/admin/tenants": [ADMIN, { label: "Tenants" }],
  "/admin/authorization": [ADMIN, { label: "Authorization" }],
};

const SEGMENT_LABELS: Record<string, string> = {
  analysis: "Code scanning",
  submission: "Code scanning",
  results: "Projects and scans",
  scanning: "Scanning",
  projects: "Project",
  diagnostics: "Diagnostics",
  runs: "Run",
  settings: "Settings",
  pentesting: "Pentesting",
  admin: "Administration",
  account: "Account",
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function humanise(segment: string): string {
  if (UUID_RE.test(segment)) return `…${segment.slice(0, 8)}`;
  const known = SEGMENT_LABELS[segment.toLowerCase()];
  if (known) return known;
  return segment
    .replace(/[-_]+/g, " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function trailFor(pathname: string): Crumb[] {
  const exact = TRAILS[pathname.replace(/\/$/, "") || "/"];
  const home: Crumb = { label: "Dashboard", to: "/account/dashboard" };
  if (exact) {
    return exact.length ? [home, ...exact] : [home];
  }

  const parts = pathname.split("/").filter(Boolean);
  if (!parts.length) return [home];

  // Fallback: derive from the path, linking each ancestor that has a parent page.
  const crumbs: Crumb[] = [home];
  parts.forEach((part, index) => {
    const isLast = index === parts.length - 1;
    const path = "/" + parts.slice(0, index + 1).join("/");
    crumbs.push({ label: humanise(part), to: isLast ? undefined : path });
  });
  return crumbs.filter(
    (crumb, index) => index === 0 || crumb.label !== crumbs[index - 1].label,
  );
}

export const Breadcrumbs: React.FC = () => {
  const { pathname } = useLocation();
  const { count } = useContext(BreadcrumbContext);
  const crumbs = useMemo(() => trailFor(pathname), [pathname]);

  // A page with its own trail wins; render nothing so there are never two.
  if (count > 0 || crumbs.length <= 1) return null;

  return (
    <nav className="page-breadcrumbs" aria-label="Breadcrumb">
      {crumbs.map((crumb, index) => (
        <React.Fragment key={`${crumb.label}-${index}`}>
          {index > 0 && <span className="page-breadcrumbs-sep">/</span>}
          {crumb.to ? (
            <Link className="page-breadcrumbs-link" to={crumb.to}>
              {crumb.label}
            </Link>
          ) : (
            <span className="page-breadcrumbs-current" aria-current="page">
              {crumb.label}
            </span>
          )}
        </React.Fragment>
      ))}
    </nav>
  );
};

/** Provider that lets pages claim the breadcrumb slot. */
export const BreadcrumbProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [count, setCount] = useState(0);
  const value = useMemo<BreadcrumbRegistration>(
    () => ({
      register: () => {
        setCount((current) => current + 1);
        return () => setCount((current) => Math.max(0, current - 1));
      },
      count,
    }),
    [count],
  );
  return <BreadcrumbContext.Provider value={value}>{children}</BreadcrumbContext.Provider>;
};
