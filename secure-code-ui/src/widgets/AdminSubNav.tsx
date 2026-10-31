// secure-code-ui/src/widgets/AdminSubNav.tsx
//
// Horizontal sub-nav rendered by DashboardLayout on /admin/* routes so
// users can move between admin surfaces without typing URLs. The top
// nav still has a single "Admin" link; this strip carries the detail.

import React from "react";
import { Link, useLocation } from "react-router-dom";

import { useAuth } from "../shared/hooks/useAuth";
import { useFeatures } from "../shared/hooks/useFeatures";
import { isSafeHttpUrl } from "../shared/lib/safeUrl";
import { hasAnyPermission, Permission } from "../shared/lib/permissions";

export interface AdminLink {
  to: string;
  label: string;
  /** When set, the link is hidden unless this feature flag is enabled. */
  feature?: string;
  permissions?: readonly string[];
}

export const ADMIN_LINKS: AdminLink[] = [
  // Configuration of how analysis works: frameworks (standards → agents → prompts →
  // mappings), the deterministic detectors, and the models behind them.
  {
    to: "/admin/analysis",
    label: "Framework Config",
    feature: "admin_authoring",
    permissions: [Permission.platformConfigManage],
  },
  {
    to: "/admin/semgrep",
    label: "Semgrep Config",
    feature: "admin_authoring",
    permissions: [Permission.platformConfigManage],
  },
  { to: "/account/settings/llm", label: "LLM Configs", permissions: [Permission.platformConfigManage] },
  { to: "/usage", label: "Usage & Spend" },
  // Who is in the platform, and how they prove who they are.
  { to: "/admin/access", label: "Access & Roles", permissions: [Permission.identityRead] },
  {
    to: "/admin/identity",
    label: "Identity & Email",
    feature: "sso",
    permissions: [Permission.tenantPolicyManage],
  },
  { to: "/admin/integrations", label: "Integrations", permissions: [Permission.servicePrincipalManage] },
  { to: "/admin/sso/audit", label: "Auth Audit", feature: "sso", permissions: [Permission.auditRead] },
  // Platform-level settings.
  { to: "/admin/platform", label: "Platform", permissions: [Permission.platformConfigManage] },
  { to: "/admin/appearance", label: "Appearance", permissions: [Permission.platformConfigManage] },
];

const LANGFUSE_HOST = (import.meta.env.VITE_LANGFUSE_HOST as string | undefined) ?? "";

export const AdminSubNav: React.FC = () => {
  const { pathname } = useLocation();
  const { user } = useAuth();
  const { isFeatureEnabled } = useFeatures();
  const isSuperuser = !!user?.is_superuser;
  // Hide admin links whose backing feature is disabled (modular setup).
  const adminLinks = ADMIN_LINKS.filter(
    (l) =>
      (!l.feature || isFeatureEnabled(l.feature)) &&
      (!l.permissions || hasAnyPermission(user?.permissions, l.permissions)),
  );
  // External link to the self-hosted Langfuse UI. Superuser-only because
  // Langfuse traces span all tenants (no per-project isolation in the
  // first iteration — see threat model #2). Also gated by `tracing`.
  const showLangfuse =
    isSuperuser &&
    isFeatureEnabled("tracing") &&
    LANGFUSE_HOST.length > 0 &&
    isSafeHttpUrl(LANGFUSE_HOST);
  const itemStyle = (active: boolean): React.CSSProperties => ({
    padding: "6px 12px",
    borderRadius: 8,
    fontSize: 12.5,
    fontWeight: 500,
    textDecoration: "none",
    background: active ? "var(--bg-elev)" : "transparent",
    color: active ? "var(--fg)" : "var(--fg-muted)",
    boxShadow: active ? "var(--shadow-xs)" : "none",
  });
  return (
    <nav
      aria-label="Administration"
      style={{
        display: "flex",
        gap: 4,
        flexWrap: "wrap",
        padding: 4,
        borderRadius: 12,
        border: "1px solid var(--border)",
        background: "var(--bg-soft)",
        marginBottom: 20,
      }}
    >
      {adminLinks.map((l) => {
        const active = pathname === l.to || pathname.startsWith(l.to + "/");
        return (
          <Link
            key={l.to}
            to={l.to}
            style={itemStyle(active)}
            aria-current={active ? "page" : undefined}
          >
            {l.label}
          </Link>
        );
      })}
      {showLangfuse ? (
        <a
          key="langfuse-external"
          href={LANGFUSE_HOST}
          target="_blank"
          rel="noopener noreferrer"
          style={itemStyle(false)}
          title="Open Langfuse trace UI in a new tab"
        >
          Langfuse ↗
        </a>
      ) : null}
    </nav>
  );
};

export default AdminSubNav;
