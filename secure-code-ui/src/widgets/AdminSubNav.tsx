// secure-code-ui/src/widgets/AdminSubNav.tsx
//
// Horizontal sub-nav rendered by DashboardLayout on /admin/* routes so
// users can move between admin surfaces without typing URLs. The top
// nav still has a single "Admin" link; this strip carries the detail.

import React from "react";
import { Link, useLocation } from "react-router-dom";

import { useAuth } from "../shared/hooks/useAuth";
import { isSafeHttpUrl } from "../shared/lib/safeUrl";

interface AdminLink {
  to: string;
  label: string;
}

const ADMIN_LINKS: AdminLink[] = [
  { to: "/admin/system", label: "Platform" },
  { to: "/admin/users", label: "Users" },
  { to: "/admin/user-groups", label: "Groups" },
  { to: "/admin/agents", label: "Agents" },
  { to: "/admin/frameworks", label: "Frameworks" },
  { to: "/admin/prompts", label: "Prompts" },
  { to: "/admin/smtp", label: "SMTP" },
  { to: "/admin/sso/providers", label: "SSO" },
  { to: "/admin/scim/tokens", label: "SCIM tokens" },
  { to: "/admin/sso/audit", label: "Auth audit" },
  { to: "/account/settings/llm", label: "LLM configs" },
  { to: "/admin/appearance", label: "Appearance" },
];

const LANGFUSE_HOST = (import.meta.env.VITE_LANGFUSE_HOST as string | undefined) ?? "";

export const AdminSubNav: React.FC = () => {
  const { pathname } = useLocation();
  const { user } = useAuth();
  const isSuperuser = !!user?.is_superuser;
  // External link to the self-hosted Langfuse UI. Superuser-only because
  // Langfuse traces span all tenants (no per-project isolation in the
  // first iteration — see threat model #2).
  const showLangfuse = isSuperuser && LANGFUSE_HOST.length > 0 && isSafeHttpUrl(LANGFUSE_HOST);
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
      {ADMIN_LINKS.map((l) => {
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
