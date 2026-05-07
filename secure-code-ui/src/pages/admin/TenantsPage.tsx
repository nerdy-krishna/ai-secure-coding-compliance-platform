// secure-code-ui/src/pages/admin/TenantsPage.tsx
//
// Admin CRUD for the multi-tenant foundation (Chunk 7). The tenancy
// schema is in place but enforcement (per-tenant visibility on scans /
// findings) lands in a later chunk; this page lets operators create
// tenants ahead of that switch so the data model is populated when it
// flips on.

import React, { useEffect, useMemo, useState } from "react";
import { Icon } from "../../shared/ui/Icon";
import { useToast } from "../../shared/ui/Toast";
import { SectionHead } from "../../shared/ui/DashboardPrimitives";
import {
  tenantService,
  type Tenant,
} from "../../shared/api/tenantService";

const fmt = (iso: string | null): string => {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
};

const SLUG_PATTERN = /^[a-z0-9][a-z0-9_-]{0,63}$/;

const TenantsPage: React.FC = () => {
  const toast = useToast();
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [removingId, setRemovingId] = useState<string | null>(null);
  const [renamingId, setRenamingId] = useState<string | null>(null);

  const [slug, setSlug] = useState("");
  const [displayName, setDisplayName] = useState("");

  const refresh = async () => {
    try {
      const rows = await tenantService.list();
      setTenants(rows);
    } catch (err) {
      const msg =
        (err as { response?: { data?: { detail?: string } }; message?: string })
          ?.response?.data?.detail ||
        (err as { message?: string })?.message ||
        "Failed to load tenants";
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const slugValid = useMemo(() => {
    if (!slug) return false;
    if (slug === "default") return false;
    return SLUG_PATTERN.test(slug);
  }, [slug]);

  const onCreate = async () => {
    if (!slugValid) {
      toast.error("Slug must be lowercase letters / digits / dashes / underscores.");
      return;
    }
    if (!displayName.trim()) {
      toast.error("Display name is required.");
      return;
    }
    setCreating(true);
    try {
      await tenantService.create({
        slug: slug.trim().toLowerCase(),
        display_name: displayName.trim(),
      });
      toast.success(`Tenant "${slug}" created.`);
      setSlug("");
      setDisplayName("");
      await refresh();
    } catch (err) {
      const msg =
        (err as { response?: { data?: { detail?: string } }; message?: string })
          ?.response?.data?.detail ||
        (err as { message?: string })?.message ||
        "Failed to create tenant";
      toast.error(msg);
    } finally {
      setCreating(false);
    }
  };

  const onRename = async (row: Tenant) => {
    const next = window.prompt(
      `Rename tenant "${row.slug}". New display name:`,
      row.display_name,
    );
    if (next == null) return;
    const trimmed = next.trim();
    if (!trimmed || trimmed === row.display_name) return;
    setRenamingId(row.id);
    try {
      await tenantService.update(row.id, { display_name: trimmed });
      toast.success("Tenant renamed.");
      await refresh();
    } catch (err) {
      const msg =
        (err as { response?: { data?: { detail?: string } }; message?: string })
          ?.response?.data?.detail ||
        (err as { message?: string })?.message ||
        "Failed to rename tenant";
      toast.error(msg);
    } finally {
      setRenamingId(null);
    }
  };

  const onRemove = async (row: Tenant) => {
    if (row.is_default) {
      toast.error("The default tenant is protected and cannot be deleted.");
      return;
    }
    const ok = window.confirm(
      `Delete tenant "${row.slug}"? Rows currently assigned to it will be detached (tenant_id set to NULL). Reassign first if that's not what you want.`,
    );
    if (!ok) return;
    setRemovingId(row.id);
    try {
      await tenantService.remove(row.id);
      toast.success("Tenant deleted.");
      await refresh();
    } catch (err) {
      const msg =
        (err as { response?: { data?: { detail?: string } }; message?: string })
          ?.response?.data?.detail ||
        (err as { message?: string })?.message ||
        "Failed to delete tenant";
      toast.error(msg);
    } finally {
      setRemovingId(null);
    }
  };

  const sortedTenants = useMemo(
    () =>
      [...tenants].sort((a, b) => {
        // Default tenant always first.
        if (a.is_default !== b.is_default) return a.is_default ? -1 : 1;
        return a.slug.localeCompare(b.slug);
      }),
    [tenants],
  );

  return (
    <div className="fade-in" style={{ display: "grid", gap: 20 }}>
      <div className="sccap-card">
        <SectionHead
          title={
            <>
              <Icon.Users size={16} /> Tenants
            </>
          }
        />
        <div style={{ color: "var(--fg-muted)", fontSize: 13, marginTop: 4 }}>
          Tenants partition the platform into isolated workspaces. The schema
          is in place; per-tenant visibility on scans, projects, and findings
          is rolling out in a follow-up. Creating tenants now lets you assign
          users + groups ahead of that switch.
        </div>
      </div>

      <div className="sccap-card">
        <div style={{ marginBottom: 12, fontWeight: 600, color: "var(--fg)" }}>
          Create a tenant
        </div>
        <div style={{ display: "grid", gap: 12, maxWidth: 720 }}>
          <label style={{ display: "grid", gap: 6 }}>
            <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
              Slug (lowercase, ASCII, used in URLs / audit logs)
            </span>
            <input
              className="sccap-input mono"
              placeholder="acme-corp"
              value={slug}
              onChange={(e) => setSlug(e.target.value.toLowerCase())}
              maxLength={64}
              disabled={creating}
              aria-invalid={!!slug && !slugValid}
            />
            {slug && !slugValid && (
              <span style={{ fontSize: 11.5, color: "var(--critical, var(--fg-subtle))" }}>
                {slug === "default"
                  ? "'default' is reserved for the seeded tenant."
                  : "Use lowercase letters, digits, dashes or underscores; start with a letter/digit."}
              </span>
            )}
          </label>
          <label style={{ display: "grid", gap: 6 }}>
            <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
              Display name
            </span>
            <input
              className="sccap-input"
              placeholder="ACME Corporation"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              maxLength={128}
              disabled={creating}
            />
          </label>
          <div>
            <button
              className="sccap-btn sccap-btn-primary"
              onClick={() => void onCreate()}
              disabled={creating || !slugValid || !displayName.trim()}
            >
              {creating ? "Creating…" : (
                <>
                  <Icon.Plus size={14} /> Create tenant
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      <div className="sccap-card">
        <SectionHead title={<>Tenants</>} />
        {loading && (
          <div style={{ color: "var(--fg-muted)", fontSize: 13 }}>Loading…</div>
        )}
        {!loading && sortedTenants.length === 0 && (
          <div
            style={{
              padding: 16,
              borderRadius: 8,
              border: "1px dashed var(--border)",
              color: "var(--fg-muted)",
              fontSize: 13,
            }}
          >
            No tenants yet — that shouldn't be possible (the seed tenant
            should always exist). Check the migration ran successfully.
          </div>
        )}
        {!loading && sortedTenants.length > 0 && (
          <div style={{ display: "grid", gap: 8 }}>
            {sortedTenants.map((row) => (
              <div
                key={row.id}
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr auto",
                  gap: 12,
                  padding: 12,
                  borderRadius: 8,
                  border: "1px solid var(--border)",
                  background: "var(--bg-soft)",
                }}
              >
                <div style={{ minWidth: 0 }}>
                  <div
                    style={{
                      display: "flex",
                      alignItems: "baseline",
                      gap: 8,
                      flexWrap: "wrap",
                    }}
                  >
                    <span
                      style={{
                        fontWeight: 600,
                        color: "var(--fg)",
                        fontSize: 14,
                      }}
                    >
                      {row.display_name}
                    </span>
                    <span
                      className="mono"
                      style={{
                        fontSize: 12,
                        color: "var(--fg-muted)",
                      }}
                    >
                      {row.slug}
                    </span>
                    {row.is_default && (
                      <span
                        style={{
                          fontSize: 10.5,
                          color: "var(--primary)",
                          fontWeight: 600,
                          textTransform: "uppercase",
                          letterSpacing: ".05em",
                          padding: "1px 6px",
                          borderRadius: 4,
                          background: "var(--primary-weak)",
                        }}
                      >
                        default
                      </span>
                    )}
                  </div>
                  <div
                    style={{
                      marginTop: 6,
                      fontSize: 12,
                      color: "var(--fg-muted)",
                      display: "flex",
                      gap: 12,
                      flexWrap: "wrap",
                    }}
                  >
                    <span>Created {fmt(row.created_at)}</span>
                    <span>Updated {fmt(row.updated_at)}</span>
                  </div>
                </div>
                <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                  <button
                    className="sccap-btn sccap-btn-sm sccap-btn-ghost"
                    onClick={() => void onRename(row)}
                    disabled={renamingId === row.id}
                    title="Rename this tenant"
                  >
                    {renamingId === row.id ? "Renaming…" : "Rename"}
                  </button>
                  <button
                    className="sccap-btn sccap-btn-sm sccap-btn-ghost"
                    onClick={() => void onRemove(row)}
                    disabled={row.is_default || removingId === row.id}
                    title={
                      row.is_default
                        ? "The default tenant is protected"
                        : "Delete this tenant"
                    }
                  >
                    <Icon.Trash size={12} />
                    {removingId === row.id ? "Deleting…" : "Delete"}
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default TenantsPage;
