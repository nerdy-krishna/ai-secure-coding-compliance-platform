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

interface AdminLink {
  to: string;
  label: string;
  /** When set, the link is hidden unless this feature flag is enabled. */
  feature?: string;
}

const ADMIN_LINKS: AdminLink[] = [
  { to: "/admin/system", label: "Platform" },
  { to: "/admin/features", label: "Features" },
  { to: "/admin/users", label: "Users", feature: "multi_user" },
  { to: "/admin/user-groups", label: "Groups", feature: "user_groups" },
  { to: "/admin/tenants", label: "Tenants", feature: "multi_tenant" },
  { to: "/admin/agents", label: "Agents", feature: "admin_authoring" },
  { to: "/admin/frameworks", label: "Frameworks", feature: "admin_authoring" },
  { to: "/admin/prompts", label: "Prompts", feature: "admin_authoring" },
  { to: "/admin/smtp", label: "SMTP", feature: "email" },
  { to: "/admin/sso/providers", label: "SSO", feature: "sso" },
  { to: "/admin/scim/tokens", label: "SCIM tokens", feature: "scim" },
  { to: "/admin/sso/audit", label: "Auth audit", feature: "sso" },
  { to: "/account/settings/llm", label: "LLM configs" },
  { to: "/admin/appearance", label: "Appearance" },
];

const LANGFUSE_HOST = (import.meta.env.VITE_LANGFUSE_HOST as string | undefined) ?? "";

export const AdminSubNav: React.FC = () => {
  const { pathname } = useLocation();
  const { user } = useAuth();
  const { isFeatureEnabled } = useFeatures();
  const isSuperuser = !!user?.is_superuser;
  // Hide admin links whose backing feature is disabled (modular setup).
  const adminLinks = ADMIN_LINKS.filter(
    (l) => !l.feature || isFeatureEnabled(l.feature),
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
    <div
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
          <Link key={l.to} to={l.to} style={itemStyle(active)}>
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
    </div>
  );
};

export default AdminSubNav;
