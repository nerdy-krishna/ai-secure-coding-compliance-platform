// secure-code-ui/src/widgets/TopNav/TopNav.tsx
//
// The SCCAP top-nav shell. Port of the design bundle's AppShell.jsx,
// adapted to the real app: React Router for active-item detection,
// useAuth for logout + superuser gate, useTheme for theme toggle.

import React, { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../../shared/hooks/useAuth";
import { useFeatures } from "../../shared/hooks/useFeatures";
import { useTheme } from "../../app/providers/ThemeProvider";
import { Icon } from "../../shared/ui/Icon";
import { NotificationCenter } from "../../shared/ui/NotificationCenter";
import { useToast } from "../../shared/ui/Toast";
import { SearchCombobox } from "./SearchCombobox";
import {
  ADMIN_AREA_PERMISSIONS,
  hasAnyPermission,
  hasPermission,
  Permission,
} from "../../shared/lib/permissions";
import { tenantService, type Tenant } from "../../shared/api/tenantService";

interface NavItem {
  id: string;
  label: string;
  /** Path prefix that marks this item active when the current URL starts with it. */
  match: string;
  /** Actual route to navigate to. */
  to: string;
  /** When set, the item is hidden unless this feature flag is enabled. */
  feature?: string;
  permission?: string;
}

// Order matches the design's center nav.
const NAV_ITEMS: NavItem[] = [
  { id: "dashboard", label: "Dashboard", match: "/account/dashboard", to: "/account/dashboard" },
  { id: "submit", label: "Submit", match: "/submission", to: "/submission/submit" },
  { id: "projects", label: "Projects", match: "/analysis", to: "/analysis/results" },
  { id: "pentesting", label: "Pentesting", match: "/pentesting", to: "/pentesting/engagements", feature: "pentesting_capability13", permission: Permission.pentestRead },
  { id: "compliance", label: "Compliance", match: "/compliance", to: "/compliance", feature: "compliance" },
  { id: "advisor", label: "Advisor", match: "/advisor", to: "/advisor", feature: "chat" },
  { id: "history", label: "History", match: "/account/history", to: "/account/history" },
  { id: "usage", label: "Usage", match: "/usage", to: "/usage" },
];

export const TopNav: React.FC = () => {
  const location = useLocation();
  const { theme, toggleTheme } = useTheme();
  const { user } = useAuth();
  const { isFeatureEnabled, featuresLoading } = useFeatures();
  const isSuperuser = !!user?.is_superuser;
  const hasAdminAccess = hasAnyPermission(
    user?.permissions,
    ADMIN_AREA_PERMISSIONS,
  );
  const canSwitchTenant = hasPermission(
    user?.permissions,
    Permission.platformTenantManage,
  );

  // Hide nav items whose backing feature is disabled (modular setup).
  const navItems = NAV_ITEMS.filter(
    (it) =>
      (!it.feature || (!featuresLoading && isFeatureEnabled(it.feature))) &&
      (!it.permission || hasPermission(user?.permissions, it.permission)),
  );

  // Stable capabilities, not the compatibility superuser bit, expose admin UX.
  if (hasAdminAccess) {
    navItems.push({
      id: "admin",
      label: "Admin",
      match: "/admin",
      to: "/admin/authorization",
    });
  }

  const activeId =
    navItems.find((it) => location.pathname.startsWith(it.match))?.id ?? null;

  return (
    <header
      className="top-nav-shell"
      style={{
        position: "sticky",
        top: 0,
        zIndex: 20,
        background:
          "color-mix(in oklch, var(--bg-elev) 92%, transparent)",
        backdropFilter: "blur(10px)",
        WebkitBackdropFilter: "blur(10px)",
        borderBottom: "1px solid var(--border)",
      }}
    >
      <div
        className="top-nav-grid"
        style={{
          display: "grid",
          gridTemplateColumns: "1fr auto 1fr",
          alignItems: "center",
          padding: "10px 24px",
          gap: 20,
          maxWidth: 1600,
          margin: "0 auto",
        }}
      >
        <Brand />

        <nav
          aria-label="Primary"
          className="top-nav-primary"
          style={{
            display: "flex",
            gap: 2,
            background: "var(--bg-soft)",
            padding: 4,
            borderRadius: 999,
            border: "1px solid var(--border)",
          }}
        >
          {navItems.map((it) => {
            const isActive = activeId === it.id;
            return (
              <Link
                key={it.id}
                to={it.to}
                aria-current={isActive ? "page" : undefined}
                style={{
                  padding: "6px 14px",
                  borderRadius: 999,
                  background: isActive ? "var(--bg-elev)" : "transparent",
                  color: isActive ? "var(--fg)" : "var(--fg-muted)",
                  fontSize: 13,
                  fontWeight: 500,
                  boxShadow: isActive ? "var(--shadow-xs)" : "none",
                  textDecoration: "none",
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 6,
                  transition: "all .15s var(--ease)",
                }}
              >
                {it.label}
              </Link>
            );
          })}
        </nav>

        <div
          className="top-nav-actions"
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            justifyContent: "flex-end",
          }}
        >
          <SearchCombobox />
          <NotificationCenter />
          <button
            className="sccap-btn sccap-btn-icon sccap-btn-ghost"
            onClick={toggleTheme}
            title={theme === "light" ? "Switch to dark" : "Switch to light"}
            aria-label={theme === "light" ? "Switch to dark theme" : "Switch to light theme"}
            aria-pressed={theme === "dark"}
          >
            {theme === "light" ? <Icon.Moon size={16} /> : <Icon.Sun size={16} />}
          </button>
          <UserMenu
            isSuperuser={isSuperuser}
            email={user?.email}
            canSwitchTenant={canSwitchTenant}
            activeTenantId={user?.active_tenant_id}
            activeTenantName={user?.active_tenant_display_name}
          />
        </div>
      </div>
    </header>
  );
};

const Brand: React.FC = () => (
  <Link
    to="/account/dashboard"
    className="top-nav-brand"
    aria-label="SCCAP dashboard"
    style={{
      display: "flex",
      alignItems: "center",
      gap: 10,
      textDecoration: "none",
      color: "inherit",
    }}
  >
    <div
      style={{
        width: 30,
        height: 30,
        borderRadius: 8,
        background:
          "linear-gradient(135deg, var(--primary), color-mix(in oklch, var(--primary) 60%, var(--accent)))",
        display: "grid",
        placeItems: "center",
        color: "var(--primary-ink)",
        boxShadow: "0 2px 8px color-mix(in oklch, var(--primary) 30%, transparent)",
      }}
    >
      <Icon.Shield size={16} />
    </div>
    <div style={{ lineHeight: 1.1 }}>
      <div
        style={{
          fontWeight: 600,
          fontSize: 14,
          letterSpacing: "-.01em",
          color: "var(--fg)",
        }}
      >
        SCCAP
      </div>
      <div
        style={{
          fontSize: 10.5,
          color: "var(--fg-subtle)",
          textTransform: "uppercase",
          letterSpacing: ".08em",
        }}
      >
        Secure Coding &amp; Compliance
      </div>
    </div>
  </Link>
);

interface UserMenuProps {
  isSuperuser: boolean;
  email?: string;
  canSwitchTenant: boolean;
  activeTenantId?: string | null;
  activeTenantName?: string | null;
}

const UserMenu: React.FC<UserMenuProps> = ({
  isSuperuser,
  email,
  canSwitchTenant,
  activeTenantId,
  activeTenantName,
}) => {
  const [open, setOpen] = useState(false);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [tenantsLoading, setTenantsLoading] = useState(false);
  const [switchingTenant, setSwitchingTenant] = useState(false);
  const { logout } = useAuth();
  const queryClient = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();
  const ref = useRef<HTMLDivElement | null>(null);
  const triggerRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("click", handler);
    return () => document.removeEventListener("click", handler);
  }, []);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setOpen(false);
        triggerRef.current?.focus();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open]);

  useEffect(() => {
    if (!open || !canSwitchTenant || tenants.length > 0 || tenantsLoading) return;
    setTenantsLoading(true);
    void tenantService
      .list()
      .then((rows) =>
        setTenants(
          [...rows].sort((a, b) => {
            if (a.is_default !== b.is_default) return a.is_default ? -1 : 1;
            return a.display_name.localeCompare(b.display_name);
          }),
        ),
      )
      .catch(() => toast.error("Failed to load tenants."))
      .finally(() => setTenantsLoading(false));
  }, [canSwitchTenant, open, tenants.length, tenantsLoading, toast]);

  const switchTenant = async (tenantId: string) => {
    if (!tenantId || tenantId === activeTenantId || switchingTenant) return;
    setSwitchingTenant(true);
    try {
      await queryClient.cancelQueries({ queryKey: ["capability13"] });
      queryClient.removeQueries({ queryKey: ["capability13"] });
      const selected = await tenantService.enter(tenantId);
      toast.success(`Switched to ${selected.display_name}.`);
      window.location.assign("/account/dashboard");
    } catch (error) {
      const detail = (
        error as { response?: { data?: { detail?: string } } }
      ).response?.data?.detail;
      toast.error(detail || "Failed to switch tenant.");
      setSwitchingTenant(false);
    }
  };

  const handleSignOut = async () => {
    setOpen(false);
    try {
      await logout();
    } catch {
      // logout best-effort; on failure still redirect to login.
    }
    navigate("/login", { replace: true });
  };

  const goSettings = () => {
    setOpen(false);
    navigate(isSuperuser ? "/admin/system" : "/account/settings/appearance");
  };

  const goSecurity = () => {
    setOpen(false);
    navigate("/account/settings/security");
  };

  const label = isSuperuser ? "Admin" : "User";
  const initials = isSuperuser ? "AD" : "US";

  return (
    <div ref={ref} style={{ position: "relative" }}>
      <button
        ref={triggerRef}
        className="sccap-btn sccap-btn-ghost"
        onClick={() => setOpen((o) => !o)}
        style={{ padding: "4px 10px 4px 4px", gap: 8 }}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={`${label} account menu`}
      >
        <div
          style={{
            width: 28,
            height: 28,
            borderRadius: 8,
            background: "var(--primary-weak)",
            color: "var(--primary)",
            display: "grid",
            placeItems: "center",
            fontSize: 12,
            fontWeight: 600,
          }}
        >
          {initials}
        </div>
        <div style={{ textAlign: "left", lineHeight: 1.15 }}>
          <div style={{ fontSize: 12.5, fontWeight: 500, color: "var(--fg)" }}>
            {label}
          </div>
          <div style={{ fontSize: 11, color: "var(--fg-subtle)" }}>
            {email ?? ""}
          </div>
        </div>
        <Icon.ChevronD size={12} />
      </button>
      {open && (
        <div
          className="surface fade-in"
          role="menu"
          aria-label="Account"
          style={{
            position: "absolute",
            top: "calc(100% + 6px)",
            right: 0,
            width: 240,
            padding: 6,
            boxShadow: "var(--shadow-md)",
            zIndex: 30,
          }}
        >
          {canSwitchTenant && (
            <div
              style={{
                padding: "8px 10px 10px",
                borderBottom: "1px solid var(--border)",
                marginBottom: 6,
              }}
            >
              <label
                htmlFor="active-tenant-select"
                style={{
                  display: "grid",
                  gap: 6,
                  color: "var(--fg-muted)",
                  fontSize: 11.5,
                }}
              >
                Active tenant
                <select
                  id="active-tenant-select"
                  className="sccap-input"
                  value={activeTenantId ?? ""}
                  disabled={tenantsLoading || switchingTenant}
                  onChange={(event) => void switchTenant(event.target.value)}
                  style={{ width: "100%", fontSize: 12.5 }}
                >
                  {activeTenantId && tenants.length === 0 && (
                    <option value={activeTenantId}>
                      {activeTenantName || "Current tenant"}
                    </option>
                  )}
                  {tenants.map((tenant) => (
                    <option key={tenant.id} value={tenant.id}>
                      {tenant.display_name}{tenant.is_default ? " (default)" : ""}
                    </option>
                  ))}
                </select>
              </label>
              <div style={{ marginTop: 5, fontSize: 10.5, color: "var(--fg-subtle)" }}>
                Selection lasts until this login session ends.
              </div>
            </div>
          )}
          <button
            role="menuitem"
            onClick={goSettings}
            style={{
              display: "flex",
              width: "100%",
              alignItems: "center",
              gap: 10,
              padding: "8px 10px",
              borderRadius: 6,
              border: "none",
              background: "transparent",
              color: "var(--fg)",
              cursor: "pointer",
              fontFamily: "inherit",
              fontSize: 13,
              textAlign: "left",
            }}
          >
            <Icon.Settings size={14} /> <span>Settings</span>
          </button>
          <button
            role="menuitem"
            onClick={goSecurity}
            style={{
              display: "flex",
              width: "100%",
              alignItems: "center",
              gap: 10,
              padding: "8px 10px",
              borderRadius: 6,
              border: "none",
              background: "transparent",
              color: "var(--fg)",
              cursor: "pointer",
              fontFamily: "inherit",
              fontSize: 13,
              textAlign: "left",
            }}
          >
            <Icon.Lock size={14} /> <span>Security &amp; passkeys</span>
          </button>
          <div
            style={{ height: 1, background: "var(--border)", margin: "6px 0" }}
          />
          <button
            role="menuitem"
            onClick={handleSignOut}
            style={{
              display: "flex",
              width: "100%",
              alignItems: "center",
              gap: 10,
              padding: "8px 10px",
              borderRadius: 6,
              border: "none",
              background: "transparent",
              color: "var(--fg-muted)",
              cursor: "pointer",
              fontFamily: "inherit",
              fontSize: 13,
              textAlign: "left",
            }}
          >
            <Icon.Lock size={14} /> <span>Sign out</span>
          </button>
        </div>
      )}
    </div>
  );
};

export default TopNav;
