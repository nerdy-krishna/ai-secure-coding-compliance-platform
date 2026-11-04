// secure-code-ui/src/widgets/TopNav/TopNav.tsx
//
// The SCCAP top-nav shell. Port of the design bundle's AppShell.jsx,
// adapted to the real app: React Router for active-item detection,
// useAuth for logout + superuser gate, useTheme for theme toggle.

import React, { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useAuth } from "../../shared/hooks/useAuth";
import { getBuildVersion } from "../../shared/api/systemConfigService";
import { Modal } from "../../shared/ui/Modal";
import { CopyButton } from "../../shared/ui/CopyButton";
import { useTheme } from "../../app/providers/ThemeProvider";
import { Icon } from "../../shared/ui/Icon";
import { NotificationCenter } from "../../shared/ui/NotificationCenter";
import { useToast } from "../../shared/ui/Toast";
import { SearchCombobox } from "./SearchCombobox";
import { hasPermission, Permission } from "../../shared/lib/permissions";
import { tenantService, type Tenant } from "../../shared/api/tenantService";

export const TopNav: React.FC = () => {
  const { theme, toggleTheme } = useTheme();
  const { user } = useAuth();
  const isSuperuser = !!user?.is_superuser;
  const canSwitchTenant = hasPermission(
    user?.permissions,
    Permission.platformTenantManage,
  );

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
          gridTemplateColumns: "1fr auto",
          alignItems: "center",
          padding: "10px 24px",
          gap: 20,
          maxWidth: 1600,
          margin: "0 auto",
        }}
      >
        <Brand />

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
  const [versionOpen, setVersionOpen] = useState(false);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [tenantsLoading, setTenantsLoading] = useState(false);
  const [switchingTenant, setSwitchingTenant] = useState(false);
  const { logout } = useAuth();
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

  // The running build, shown in the menu and in a details dialog. Cached for the
  // session: it cannot change without the API restarting.
  const versionQ = useQuery({
    queryKey: ["system", "version"],
    queryFn: getBuildVersion,
    staleTime: 5 * 60_000,
    retry: false,
  });
  const build = versionQ.data;

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
          {build && (
            <div
              style={{ fontSize: 10, color: "var(--fg-subtle)", letterSpacing: 0.2 }}
              title={`Running build ${build.display}${build.built_at ? `, built ${build.built_at}` : ""}`}
            >
              {build.display}
            </div>
          )}
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
            onClick={() => {
              setOpen(false);
              setVersionOpen(true);
            }}
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
            <Icon.Clock size={14} />
            <span>Version {build ? build.display : "…"}</span>
          </button>
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

      <Modal
        open={versionOpen}
        onClose={() => setVersionOpen(false)}
        title="Running version"
        footer={
          <button className="sccap-btn" onClick={() => setVersionOpen(false)}>
            Close
          </button>
        }
      >
        {build ? (
          <dl className="version-facts">
            <dt>Version</dt>
            <dd>
              <strong>{build.display}</strong>
            </dd>
            <dt>Release</dt>
            <dd>{build.version}</dd>
            <dt>Commit</dt>
            <dd>
              {build.commit ? (
                <>
                  <code>{build.commit}</code> <CopyButton value={build.commit} title="Copy commit" />
                </>
              ) : (
                "not recorded — this image was built without provenance"
              )}
            </dd>
            <dt>Built at</dt>
            <dd>{build.built_at ?? "unknown"}</dd>
            <dt>Database schema</dt>
            <dd>{build.migration_head ?? "not migrated"}</dd>
            <dt>Environment</dt>
            <dd>{build.environment}</dd>
            <p className="version-hint">
              The commit changes on every successful <code>./setup.sh --update</code>. If
              it did not change, the update did not reach the running containers — check
              <code> docker compose ps</code> before anything else.
            </p>
          </dl>
        ) : (
          <p className="version-hint">The build version could not be read from the API.</p>
        )}
      </Modal>
    </div>
  );
};

export default TopNav;
