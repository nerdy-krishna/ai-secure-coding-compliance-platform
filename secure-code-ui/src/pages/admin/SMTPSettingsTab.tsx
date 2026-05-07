// secure-code-ui/src/pages/admin/SMTPSettingsTab.tsx

import React, { useEffect, useState } from "react";
import apiClient from "../../shared/api/apiClient";
import { Icon } from "../../shared/ui/Icon";
import { Modal } from "../../shared/ui/Modal";
import { useToast } from "../../shared/ui/Toast";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface SmtpProfileMeta {
  id: string;
  name: string;
  host: string;
  port: number;
  user: string;
  from: string;
  tls: boolean;
  ssl: boolean;
}

interface SmtpProfilesResponse {
  active_id: string | null;
  profiles: SmtpProfileMeta[];
}

interface ProfileForm {
  name: string;
  host: string;
  port: number;
  user: string;
  from: string;
  tls: boolean;
  ssl: boolean;
  password: string;
}

const BLANK_FORM: ProfileForm = {
  name: "",
  host: "",
  port: 587,
  user: "",
  from: "",
  tls: true,
  ssl: false,
  password: "",
};

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------

const smtpApi = {
  list: () =>
    apiClient.get<SmtpProfilesResponse>("/admin/smtp/profiles").then((r) => r.data),
  create: (body: ProfileForm) =>
    apiClient.post<SmtpProfilesResponse>("/admin/smtp/profiles", body).then((r) => r.data),
  update: (id: string, body: Partial<ProfileForm>) =>
    apiClient.patch<SmtpProfilesResponse>(`/admin/smtp/profiles/${id}`, body).then((r) => r.data),
  remove: (id: string) => apiClient.delete(`/admin/smtp/profiles/${id}`),
  activate: (id: string) =>
    apiClient.post<SmtpProfilesResponse>(`/admin/smtp/profiles/${id}/activate`).then((r) => r.data),
};

// ---------------------------------------------------------------------------
// Shared primitives — MUST be top-level so React doesn't remount on every render
// ---------------------------------------------------------------------------

const Field: React.FC<{
  label: string;
  hint?: string;
  required?: boolean;
  children: React.ReactNode;
}> = ({ label, hint, required, children }) => (
  <label style={{ display: "grid", gap: 5 }}>
    <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
      {label}
      {required && (
        <span style={{ color: "var(--critical)", marginLeft: 2, fontWeight: 600 }}>*</span>
      )}
      {hint && (
        <span style={{ marginLeft: 8, color: "var(--fg-subtle)", fontWeight: 400 }}>
          {hint}
        </span>
      )}
    </span>
    {children}
  </label>
);

const InlineToggle: React.FC<{
  label: string;
  value: boolean;
  onChange: (v: boolean) => void;
}> = ({ label, value, onChange }) => (
  <label
    style={{
      display: "inline-flex",
      alignItems: "center",
      gap: 10,
      fontSize: 13,
      color: "var(--fg)",
      cursor: "pointer",
    }}
  >
    <div
      className={`sccap-switch ${value ? "on" : ""}`}
      role="switch"
      aria-checked={value}
      tabIndex={0}
      onClick={() => onChange(!value)}
      onKeyDown={(e) => {
        if (e.key === " " || e.key === "Enter") {
          e.preventDefault();
          onChange(!value);
        }
      }}
    />
    {label}
  </label>
);

// ---------------------------------------------------------------------------
// Profile form — top-level to avoid remount-on-render cursor jump
// ---------------------------------------------------------------------------

const ProfileForm: React.FC<{
  form: ProfileForm;
  setForm: React.Dispatch<React.SetStateAction<ProfileForm>>;
  isEdit: boolean;
}> = ({ form, setForm, isEdit }) => (
  <div style={{ display: "grid", gap: 14 }}>
    <Field label="Profile name" required>
      <input
        className="sccap-input"
        placeholder="e.g. ProtonMail, SendGrid"
        value={form.name}
        onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
        maxLength={80}
        autoFocus
      />
    </Field>

    <Field label="SMTP host" required>
      <input
        className="sccap-input"
        placeholder="smtp.proton.me"
        value={form.host}
        onChange={(e) => setForm((f) => ({ ...f, host: e.target.value }))}
        maxLength={256}
      />
    </Field>

    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
      <Field label="Port">
        <input
          className="sccap-input"
          type="number"
          min={1}
          max={65535}
          value={form.port}
          onChange={(e) => setForm((f) => ({ ...f, port: Number(e.target.value) }))}
        />
      </Field>
      <Field label="Sender address" hint="(From)" required>
        <input
          className="sccap-input"
          type="email"
          placeholder="noreply@domain.com"
          value={form.from}
          onChange={(e) => setForm((f) => ({ ...f, from: e.target.value }))}
          maxLength={256}
        />
      </Field>
    </div>

    <Field label="Username" required>
      <input
        className="sccap-input"
        placeholder="apikey or user@domain.com"
        value={form.user}
        onChange={(e) => setForm((f) => ({ ...f, user: e.target.value }))}
        maxLength={256}
      />
    </Field>

    <Field label="Password" required={!isEdit} hint={isEdit ? "(leave blank to keep existing)" : undefined}>
      <input
        className="sccap-input"
        type="password"
        placeholder={isEdit ? "Enter new password to change" : "Password / API key"}
        value={form.password}
        onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))}
        maxLength={512}
      />
    </Field>

    <div style={{ display: "flex", gap: 24, alignItems: "center" }}>
      <InlineToggle
        label="STARTTLS"
        value={form.tls}
        onChange={(v) => setForm((f) => ({ ...f, tls: v, ssl: v ? false : f.ssl }))}
      />
      <InlineToggle
        label="SSL / TLS"
        value={form.ssl}
        onChange={(v) => setForm((f) => ({ ...f, ssl: v, tls: v ? false : f.tls }))}
      />
    </div>
  </div>
);

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

const SMTPSettingsTab: React.FC = () => {
  const toast = useToast();
  const [state, setState] = useState<SmtpProfilesResponse>({ active_id: null, profiles: [] });
  const [loading, setLoading] = useState(true);

  const [modalMode, setModalMode] = useState<"create" | "edit" | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<ProfileForm>(BLANK_FORM);
  const [saving, setSaving] = useState(false);

  const [deleteTarget, setDeleteTarget] = useState<SmtpProfileMeta | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [activating, setActivating] = useState<string | null>(null);

  const load = async () => {
    try {
      const data = await smtpApi.list();
      setState(data);
    } catch {
      toast.error("Could not load SMTP profiles.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const openCreate = () => {
    setForm(BLANK_FORM);
    setEditingId(null);
    setModalMode("create");
  };

  const openEdit = (p: SmtpProfileMeta) => {
    setForm({ name: p.name, host: p.host, port: p.port, user: p.user, from: p.from, tls: p.tls, ssl: p.ssl, password: "" });
    setEditingId(p.id);
    setModalMode("edit");
  };

  const handleSave = async () => {
    if (!form.host || !form.user || !form.from) {
      toast.error("Host, username, and sender address are required.");
      return;
    }
    if (form.tls && form.ssl) { toast.error("STARTTLS and SSL are mutually exclusive."); return; }
    if (!form.tls && !form.ssl) { toast.error("Enable STARTTLS or SSL — cleartext SMTP is not allowed."); return; }
    if (modalMode === "create" && !form.password) { toast.error("Password is required for a new profile."); return; }

    setSaving(true);
    try {
      let updated: SmtpProfilesResponse;
      if (modalMode === "create") {
        updated = await smtpApi.create(form);
        toast.success("SMTP profile created.");
      } else {
        const patch: Partial<ProfileForm> = { ...form };
        if (!form.password) delete patch.password;
        updated = await smtpApi.update(editingId!, patch);
        toast.success("SMTP profile updated.");
      }
      setState(updated);
      setModalMode(null);
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      toast.error(msg ?? "Failed to save SMTP profile.");
    } finally {
      setSaving(false);
    }
  };

  const handleActivate = async (id: string) => {
    setActivating(id);
    try {
      setState(await smtpApi.activate(id));
      toast.success("SMTP profile activated.");
    } catch {
      toast.error("Failed to activate profile.");
    } finally {
      setActivating(null);
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await smtpApi.remove(deleteTarget.id);
      toast.success("SMTP profile deleted.");
      await load();
      setDeleteTarget(null);
    } catch {
      toast.error("Failed to delete profile.");
    } finally {
      setDeleting(false);
    }
  };

  if (loading) {
    return (
      <div className="sccap-card" style={{ padding: 40, textAlign: "center", color: "var(--fg-muted)" }}>
        Loading SMTP settings…
      </div>
    );
  }

  return (
    <div className="fade-in" style={{ display: "grid", gap: 20 }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between" }}>
        <div>
          <h1 style={{ color: "var(--fg)", margin: 0 }}>SMTP settings</h1>
          <div style={{ color: "var(--fg-muted)", marginTop: 4 }}>
            Outgoing mail server for password reset and user invitations. One profile is active at a time.
          </div>
        </div>
        <button className="sccap-btn sccap-btn-primary sccap-btn-sm" onClick={openCreate}>
          <Icon.Plus size={12} /> Add profile
        </button>
      </div>

      {/* Profile list */}
      {state.profiles.length === 0 ? (
        <div
          className="surface"
          style={{ padding: 40, textAlign: "center", color: "var(--fg-muted)", display: "grid", gap: 10 }}
        >
          <Icon.Mail size={24} style={{ margin: "0 auto", color: "var(--fg-subtle)" }} />
          <div>No SMTP profiles configured yet.</div>
          <div style={{ fontSize: 12, color: "var(--fg-subtle)" }}>
            Click <strong>Add profile</strong> to set up your first outgoing mail server.
          </div>
        </div>
      ) : (
        <div style={{ display: "grid", gap: 10 }}>
          {state.profiles.map((p) => {
            const isActive = p.id === state.active_id;
            return (
              <div
                key={p.id}
                className="surface"
                style={{
                  padding: "14px 18px",
                  display: "flex",
                  alignItems: "center",
                  gap: 14,
                  borderLeft: isActive ? "3px solid var(--primary)" : "3px solid transparent",
                  transition: "border-color .15s",
                }}
              >
                <div
                  style={{
                    width: 36,
                    height: 36,
                    borderRadius: 8,
                    background: isActive ? "var(--primary-weak)" : "var(--bg-soft)",
                    color: isActive ? "var(--primary)" : "var(--fg-muted)",
                    display: "grid",
                    placeItems: "center",
                    flexShrink: 0,
                  }}
                >
                  <Icon.Mail size={16} />
                </div>

                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                    <span style={{ fontWeight: 600, fontSize: 14, color: "var(--fg)" }}>{p.name}</span>
                    {isActive && <span className="chip chip-success">Active</span>}
                    <span className="chip">{p.tls ? "STARTTLS" : "SSL"}</span>
                  </div>
                  <div style={{ fontSize: 12, color: "var(--fg-muted)", marginTop: 3, fontFamily: "var(--font-mono)" }}>
                    {p.host}:{p.port} · from {p.from}
                  </div>
                  <div style={{ fontSize: 12, color: "var(--fg-subtle)", marginTop: 1 }}>
                    user: {p.user}
                  </div>
                </div>

                <div style={{ display: "flex", gap: 6, alignItems: "center", flexShrink: 0 }}>
                  {!isActive && (
                    <button
                      className="sccap-btn sccap-btn-sm"
                      onClick={() => handleActivate(p.id)}
                      disabled={activating === p.id}
                    >
                      {activating === p.id ? "Activating…" : "Set active"}
                    </button>
                  )}
                  <button
                    className="sccap-btn sccap-btn-icon sccap-btn-ghost sccap-btn-sm"
                    title="Edit profile"
                    onClick={() => openEdit(p)}
                  >
                    <Icon.Edit size={13} />
                  </button>
                  <button
                    className="sccap-btn sccap-btn-icon sccap-btn-ghost sccap-btn-sm"
                    title="Delete profile"
                    style={{ color: "var(--critical)" }}
                    onClick={() => setDeleteTarget(p)}
                  >
                    <Icon.Trash size={13} />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Create / Edit modal */}
      <Modal
        open={modalMode !== null}
        onClose={() => !saving && setModalMode(null)}
        title={modalMode === "create" ? "Add SMTP profile" : "Edit SMTP profile"}
        footer={
          <>
            <button className="sccap-btn sccap-btn-sm" onClick={() => setModalMode(null)} disabled={saving}>
              Cancel
            </button>
            <button className="sccap-btn sccap-btn-primary sccap-btn-sm" onClick={handleSave} disabled={saving}>
              {saving ? "Saving…" : modalMode === "create" ? "Create profile" : "Save changes"}
            </button>
          </>
        }
      >
        <ProfileForm form={form} setForm={setForm} isEdit={modalMode === "edit"} />
      </Modal>

      {/* Delete confirm */}
      <Modal
        open={!!deleteTarget}
        onClose={() => !deleting && setDeleteTarget(null)}
        title="Delete SMTP profile"
        footer={
          <>
            <button className="sccap-btn sccap-btn-sm" onClick={() => setDeleteTarget(null)} disabled={deleting}>
              Cancel
            </button>
            <button className="sccap-btn sccap-btn-danger sccap-btn-sm" onClick={handleDelete} disabled={deleting}>
              {deleting ? "Deleting…" : "Delete permanently"}
            </button>
          </>
        }
      >
        <p style={{ color: "var(--fg)", margin: 0 }}>
          Delete the SMTP profile <strong>{deleteTarget?.name}</strong>?
          {deleteTarget?.id === state.active_id && (
            <span style={{ color: "var(--medium)", display: "block", marginTop: 8, fontSize: 13 }}>
              This is the active profile. Deleting it will disable outgoing email until another profile is activated.
            </span>
          )}
        </p>
      </Modal>
    </div>
  );
};

export default SMTPSettingsTab;
