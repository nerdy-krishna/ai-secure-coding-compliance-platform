// secure-code-ui/src/pages/admin/UserManagement.tsx
//
// Tenant user management — create, edit status/roles, and delete.
// Rows are clickable to open an edit drawer. The master admin (lowest user id =
// setup admin) has a deletion lock; only their own actions are blocked — other
// admins cannot delete them either.

import React, { useEffect, useState } from "react";
import { authService, type AdminUserRead } from "../../shared/api/authService";
import { useAuth } from "../../shared/hooks/useAuth";
import { Icon } from "../../shared/ui/Icon";
import { Modal } from "../../shared/ui/Modal";
import { useToast } from "../../shared/ui/Toast";

interface CreateForm {
  email: string;
  is_active: boolean;
  is_verified: boolean;
}

const INITIAL_FORM: CreateForm = {
  email: "",
  is_active: true,
  is_verified: false,
};

interface EditState {
  user: AdminUserRead;
  is_active: boolean;
  is_verified: boolean;
  role_keys: string[];
  action_request_id: string;
}

const TENANT_ROLES = [
  "tenant_admin",
  "security_approver",
  "analyst",
  "developer",
  "auditor",
] as const;

function roleLabel(role: string): string {
  return role
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function initials(email: string): string {
  return email
    .split("@")[0]
    .split(/[._-]/)
    .filter(Boolean)
    .slice(0, 2)
    .map((s) => s[0]?.toUpperCase() ?? "")
    .join("");
}

const UserManagementTab: React.FC = () => {
  const toast = useToast();
  const { user: currentUser } = useAuth();
  const [users, setUsers] = useState<AdminUserRead[]>([]);
  const [loading, setLoading] = useState(false);
  const [creating, setCreating] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);
  const [form, setForm] = useState<CreateForm>(INITIAL_FORM);
  const [search, setSearch] = useState("");

  // Edit modal state
  const [editState, setEditState] = useState<EditState | null>(null);
  const [saving, setSaving] = useState(false);
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const fetchUsers = async () => {
    setLoading(true);
    try {
      setUsers(await authService.adminListUsers());
    } catch {
      toast.error("Failed to load users.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // The master admin is the user with the lowest id (created during setup).
  const masterAdminId = users.length > 0 ? Math.min(...users.map((u) => u.id)) : null;

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);

    // V01.3.3: enforce RFC 5321 email length cap on the client (backend still validates)
    if (form.email.length > 254) {
      toast.error("Email exceeds 254 characters.");
      setCreating(false);
      return;
    }

    // V02.2.3: warn on inconsistent flag combinations before submitting
    if (form.is_verified && !form.is_active) {
      toast.warn("Creating an inactive verified user — confirm this is intentional.");
    }

    await doCreateUser(form);
  };

  const doCreateUser = async (payload: CreateForm) => {
    setCreating(true);
    try {
      await authService.adminCreateUser(payload);
      toast.success("User created. Setup email sent.");
      setModalOpen(false);
      setForm(INITIAL_FORM);
      fetchUsers();
    } catch {
      toast.error("Failed to create user. Check the email.");
    } finally {
      setCreating(false);
    }
  };

  const openEdit = (u: AdminUserRead) => {
    setEditState({
      user: u,
      is_active: u.is_active,
      is_verified: u.is_verified,
      role_keys: u.role_keys.filter((role) => role !== "platform_owner"),
      action_request_id: "",
    });
    setDeleteConfirmOpen(false);
  };

  const closeEdit = () => {
    setEditState(null);
    setDeleteConfirmOpen(false);
  };

  const handleSaveEdit = async () => {
    if (!editState) return;

    setSaving(true);
    try {
      let updated = editState.user;
      const statusDirty =
        editState.is_active !== editState.user.is_active ||
        editState.is_verified !== editState.user.is_verified;
      if (statusDirty) {
        updated = await authService.adminUpdateUser(editState.user.id, {
          is_active: editState.is_active,
          is_verified: editState.is_verified,
        });
      }
      const originalRoles = editState.user.role_keys
        .filter((role) => role !== "platform_owner")
        .sort();
      const desiredRoles = [...editState.role_keys].sort();
      const rolesDirty = originalRoles.join(",") !== desiredRoles.join(",");
      if (rolesDirty) {
        try {
          updated = await authService.adminUpdateUserRoles(
            editState.user.id,
            desiredRoles,
            editState.action_request_id.trim() || undefined,
          );
        } catch (err: unknown) {
          const response = (err as { response?: { status?: number; data?: { detail?: string } } })
            ?.response;
          if (response?.status === 409 && !editState.action_request_id.trim()) {
            const request = await authService.adminRequestUserRoleChange(
              editState.user.id,
              desiredRoles,
            );
            setEditState({ ...editState, action_request_id: request.id });
            toast.warn(
              `Approval request ${request.id} created. A distinct tenant admin must approve it; then save again to execute.`,
            );
            return;
          }
          throw err;
        }
      }
      toast.success("User updated.");
      setUsers((prev) => prev.map((u) => (u.id === updated.id ? updated : u)));
      closeEdit();
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      toast.error(msg ?? "Failed to update user.");
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!editState) return;
    setDeleting(true);
    try {
      await authService.adminDeleteUser(editState.user.id);
      toast.success("User deleted.");
      setUsers((prev) => prev.filter((u) => u.id !== editState.user.id));
      closeEdit();
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      toast.error(msg ?? "Failed to delete user.");
    } finally {
      setDeleting(false);
      setDeleteConfirmOpen(false);
    }
  };

  const filtered = users.filter((u) =>
    search ? u.email.toLowerCase().includes(search.toLowerCase()) : true,
  );

  // Dirty check for the edit modal save button
  const editDirty = editState
    ? editState.is_active !== editState.user.is_active ||
      editState.is_verified !== editState.user.is_verified ||
      editState.user.role_keys.filter((role) => role !== "platform_owner").sort().join(",") !==
        [...editState.role_keys].sort().join(",")
    : false;

  const isMasterAdmin = (u: AdminUserRead) => u.id === masterAdminId;
  const isSelf = (u: AdminUserRead) => u.id === currentUser?.id;

  return (
    <div className="fade-in" style={{ display: "grid", gap: 16 }}>
      <div>
        <h1 style={{ color: "var(--fg)" }}>Users</h1>
        <div style={{ color: "var(--fg-muted)", marginTop: 4 }}>
          Manage accounts and verification status in the active tenant.
        </div>
      </div>

      <div className="surface" style={{ padding: 0 }}>
        <div
          className="section-head"
          style={{ padding: "14px 18px 10px", marginBottom: 0 }}
        >
          <h3 style={{ margin: 0 }}>
            {loading ? "Loading…" : `${users.length} users`}
          </h3>
          <div style={{ display: "flex", gap: 8 }}>
            <div className="input-with-icon" style={{ width: 220 }}>
              <Icon.Search size={14} />
              <input
                className="sccap-input"
                placeholder="Search email…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                style={{ paddingLeft: 32 }}
              />
            </div>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={fetchUsers}
              disabled={loading}
            >
              <Icon.Refresh size={12} /> Refresh
            </button>
            <button
              className="sccap-btn sccap-btn-primary sccap-btn-sm"
              onClick={() => {
                setForm(INITIAL_FORM);
                setModalOpen(true);
              }}
            >
              <Icon.Plus size={12} /> Create user
            </button>
          </div>
        </div>

        {filtered.length === 0 ? (
          <div
            style={{
              padding: 40,
              textAlign: "center",
              color: "var(--fg-muted)",
            }}
          >
            {loading ? "Loading…" : "No users match your search."}
          </div>
        ) : (
          <table className="sccap-t">
            <thead>
              <tr>
                <th>User</th>
                <th>Active</th>
                <th>Verified</th>
                <th>Role</th>
                <th style={{ width: 80, textAlign: "right" }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((u) => (
                <tr
                  key={u.id}
                  style={{ cursor: "pointer" }}
                  onClick={() => openEdit(u)}
                >
                  <td>
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 10,
                      }}
                    >
                      <div
                        style={{
                          width: 28,
                          height: 28,
                          borderRadius: 8,
                          background: u.role_keys.includes("platform_owner")
                            ? "var(--primary-weak)"
                            : "var(--bg-soft)",
                          color: u.role_keys.includes("platform_owner")
                            ? "var(--primary)"
                            : "var(--fg-muted)",
                          display: "grid",
                          placeItems: "center",
                          fontSize: 11,
                          fontWeight: 600,
                          flexShrink: 0,
                        }}
                      >
                        {initials(u.email)}
                      </div>
                      <div style={{ lineHeight: 1.3 }}>
                        <div
                          style={{
                            fontFamily: "var(--font-mono)",
                            color: "var(--fg)",
                            fontSize: 13,
                          }}
                        >
                          {u.email}
                        </div>
                        {isMasterAdmin(u) && (
                          <div
                            style={{
                              fontSize: 10.5,
                              color: "var(--fg-subtle)",
                              marginTop: 1,
                            }}
                          >
                            Master admin · cannot be deleted
                          </div>
                        )}
                        {isSelf(u) && !isMasterAdmin(u) && (
                          <div
                            style={{
                              fontSize: 10.5,
                              color: "var(--fg-subtle)",
                              marginTop: 1,
                            }}
                          >
                            You
                          </div>
                        )}
                      </div>
                    </div>
                  </td>
                  <td>
                    {u.is_active ? (
                      <span className="chip chip-success">Active</span>
                    ) : (
                      <span className="chip">Inactive</span>
                    )}
                  </td>
                  <td>
                    {u.is_verified ? (
                      <span className="chip chip-info">Verified</span>
                    ) : (
                      <span
                        className="chip"
                        style={{ color: "var(--fg-subtle)" }}
                      >
                        Pending
                      </span>
                    )}
                  </td>
                  <td>
                    <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                      {u.role_keys.map((role) => (
                        <span
                          className={`chip ${role === "platform_owner" ? "chip-ai" : ""}`}
                          key={role}
                        >
                          {roleLabel(role)}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td style={{ textAlign: "right" }}>
                    <div
                      style={{ display: "flex", gap: 4, justifyContent: "flex-end" }}
                      onClick={(e) => e.stopPropagation()}
                    >
                      <button
                        className="sccap-btn sccap-btn-icon sccap-btn-ghost sccap-btn-sm"
                        title="Edit user"
                        onClick={(e) => { e.stopPropagation(); openEdit(u); }}
                      >
                        <Icon.Edit size={13} />
                      </button>
                      <button
                        className="sccap-btn sccap-btn-icon sccap-btn-ghost sccap-btn-sm"
                        title={
                          isMasterAdmin(u)
                            ? "Master admin cannot be deleted"
                            : isSelf(u)
                            ? "Cannot delete your own account"
                            : "Delete user"
                        }
                        disabled={isMasterAdmin(u) || isSelf(u)}
                        style={
                          !isMasterAdmin(u) && !isSelf(u)
                            ? { color: "var(--critical)" }
                            : undefined
                        }
                        onClick={(e) => {
                          e.stopPropagation();
                          openEdit(u);
                          // Small delay so edit modal mounts first
                          setTimeout(() => setDeleteConfirmOpen(true), 50);
                        }}
                      >
                        <Icon.Trash size={13} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* ── Edit user modal ───────────────────────────────────────────── */}
      <Modal
        open={!!editState && !deleteConfirmOpen}
        onClose={closeEdit}
        title={`Edit user`}
        footer={
          <>
            <div style={{ flex: 1 }}>
              {editState && !isMasterAdmin(editState.user) && !isSelf(editState.user) && (
                <button
                  className="sccap-btn sccap-btn-sm"
                  style={{ color: "var(--critical)" }}
                  onClick={() => setDeleteConfirmOpen(true)}
                  disabled={saving}
                >
                  <Icon.Trash size={12} /> Delete user
                </button>
              )}
            </div>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={closeEdit}
              disabled={saving}
            >
              Cancel
            </button>
            <button
              className="sccap-btn sccap-btn-primary sccap-btn-sm"
              onClick={handleSaveEdit}
              disabled={saving || !editDirty}
            >
              {saving ? "Saving…" : "Save changes"}
            </button>
          </>
        }
      >
        {editState && (
          <div style={{ display: "grid", gap: 16 }}>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 10,
                padding: "10px 12px",
                borderRadius: 8,
                background: "var(--bg-soft)",
                border: "1px solid var(--border)",
              }}
            >
              <div
                style={{
                  width: 32,
                  height: 32,
                  borderRadius: 8,
                  background: editState.user.role_keys.includes("platform_owner")
                    ? "var(--primary-weak)"
                    : "var(--bg-inset)",
                  color: editState.user.role_keys.includes("platform_owner")
                    ? "var(--primary)"
                    : "var(--fg-muted)",
                  display: "grid",
                  placeItems: "center",
                  fontSize: 12,
                  fontWeight: 600,
                  flexShrink: 0,
                }}
              >
                {initials(editState.user.email)}
              </div>
              <div>
                <div
                  style={{
                    fontFamily: "var(--font-mono)",
                    fontSize: 13,
                    color: "var(--fg)",
                  }}
                >
                  {editState.user.email}
                </div>
                <div style={{ fontSize: 11, color: "var(--fg-subtle)", marginTop: 2 }}>
                  {isMasterAdmin(editState.user)
                    ? "Master admin · deletion locked"
                    : isSelf(editState.user)
                    ? "Your account"
                    : `ID ${editState.user.id}`}
                </div>
              </div>
            </div>

            <ToggleRow
              label="Active"
              hint="User can sign in. Disable to suspend without deleting."
              value={editState.is_active}
              onChange={(v) => setEditState({ ...editState, is_active: v })}
              disabled={isSelf(editState.user)}
            />
            <ToggleRow
              label="Verified"
              hint="Email address has been confirmed."
              value={editState.is_verified}
              onChange={(v) => setEditState({ ...editState, is_verified: v })}
            />
            <div style={{ display: "grid", gap: 6 }}>
              <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>Roles</span>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                {TENANT_ROLES.map((role) => (
                  <label
                    key={role}
                    style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 12.5 }}
                  >
                    <input
                      type="checkbox"
                      checked={editState.role_keys.includes(role)}
                      onChange={(event) => {
                        const next = event.target.checked
                          ? [...editState.role_keys, role]
                          : editState.role_keys.filter((key) => key !== role);
                        if (next.length === 0) {
                          toast.error("At least one tenant role is required.");
                          return;
                        }
                        setEditState({
                          ...editState,
                          role_keys: next,
                          action_request_id: "",
                        });
                      }}
                    />
                    {roleLabel(role)}
                  </label>
                ))}
              </div>
              <span style={{ fontSize: 11.5, color: "var(--fg-subtle)" }}>
                In critical mode, permission increases require approval by a distinct tenant admin.
              </span>
              <label style={{ display: "grid", gap: 5, marginTop: 4 }}>
                <span style={{ fontSize: 11.5, color: "var(--fg-muted)" }}>
                  Approved action request ID (only for critical elevation)
                </span>
                <input
                  className="sccap-input"
                  value={editState.action_request_id}
                  placeholder="Created automatically, or paste an approved request ID"
                  onChange={(event) =>
                    setEditState({ ...editState, action_request_id: event.target.value })
                  }
                />
              </label>
            </div>
          </div>
        )}
      </Modal>

      {/* ── Delete confirmation ───────────────────────────────────────── */}
      <Modal
        open={deleteConfirmOpen}
        onClose={() => !deleting && setDeleteConfirmOpen(false)}
        title="Delete user"
        footer={
          <>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={() => setDeleteConfirmOpen(false)}
              disabled={deleting}
            >
              Cancel
            </button>
            <button
              className="sccap-btn sccap-btn-danger sccap-btn-sm"
              onClick={handleDelete}
              disabled={deleting}
            >
              {deleting ? "Deleting…" : "Delete permanently"}
            </button>
          </>
        }
      >
        <div style={{ display: "grid", gap: 12 }}>
          <p style={{ color: "var(--fg)", margin: 0 }}>
            Permanently delete{" "}
            <code style={{ fontFamily: "var(--font-mono)" }}>
              {editState?.user.email}
            </code>
            ?
          </p>
          <p style={{ color: "var(--fg-muted)", fontSize: 13, margin: 0 }}>
            This removes the account and all associated sessions. Their
            projects and scans will remain in the system. This action cannot
            be undone.
          </p>
        </div>
      </Modal>

      {/* ── Create user modal ─────────────────────────────────────────── */}
      <Modal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        title="Create new user"
        footer={
          <>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={() => setModalOpen(false)}
              disabled={creating}
            >
              Cancel
            </button>
            <button
              className="sccap-btn sccap-btn-primary sccap-btn-sm"
              onClick={handleCreate}
              disabled={creating || !form.email}
            >
              {creating ? "Creating…" : "Create & send email"}
            </button>
          </>
        }
      >
        <form onSubmit={handleCreate} style={{ display: "grid", gap: 14 }}>
          <label style={{ display: "grid", gap: 6 }}>
            <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
              Email address
            </span>
            <input
              className="sccap-input"
              type="email"
              required
              placeholder="user@example.com"
              value={form.email}
              onChange={(e) => setForm({ ...form, email: e.target.value })}
              maxLength={254}
              autoFocus
            />
          </label>
          <ToggleRow
            label="Active"
            hint="User can sign in immediately."
            value={form.is_active}
            onChange={(v) => setForm({ ...form, is_active: v })}
          />
          <ToggleRow
            label="Verified"
            hint="Skip the email-verification step."
            value={form.is_verified}
            onChange={(v) => setForm({ ...form, is_verified: v })}
          />
          {/* Hidden submit so Enter on the email field still fires handleCreate. */}
          <button type="submit" style={{ display: "none" }} />
        </form>
      </Modal>
    </div>
  );
};

const ToggleRow: React.FC<{
  label: string;
  hint?: string;
  value: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}> = ({ label, hint, value, onChange, disabled }) => (
  <div
    style={{
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      gap: 14,
      opacity: disabled ? 0.5 : 1,
    }}
  >
    <div>
      <div style={{ fontSize: 13, color: "var(--fg)", fontWeight: 500 }}>
        {label}
      </div>
      {hint && (
        <div style={{ fontSize: 11.5, color: "var(--fg-muted)", marginTop: 2 }}>
          {hint}
        </div>
      )}
    </div>
    <div
      className={`sccap-switch ${value ? "on" : ""}`}
      role="switch"
      aria-checked={value}
      tabIndex={disabled ? -1 : 0}
      onClick={() => !disabled && onChange(!value)}
      onKeyDown={(e) => {
        if (!disabled && (e.key === " " || e.key === "Enter")) {
          e.preventDefault();
          onChange(!value);
        }
      }}
      style={disabled ? { pointerEvents: "none" } : undefined}
    />
  </div>
);

export default UserManagementTab;
