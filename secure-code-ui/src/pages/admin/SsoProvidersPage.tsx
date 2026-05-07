// secure-code-ui/src/pages/admin/SsoProvidersPage.tsx
//
// Admin CRUD for SSO providers (OIDC + SAML). Multi-provider, secrets
// encrypted at rest, redacted on read; PATCH accepts the literal
// "<<unchanged>>" sentinel to keep an existing secret without re-entry.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AxiosError } from "axios";
import React, { useMemo, useState } from "react";
import {
  ssoService,
  type SsoProtocol,
  type SsoProviderAdmin,
  type SsoProviderCreate,
  type SsoProviderUpdate,
} from "../../shared/api/ssoService";
import { Icon } from "../../shared/ui/Icon";
import { Modal } from "../../shared/ui/Modal";
import { useToast } from "../../shared/ui/Toast";

type JitPolicy = "auto" | "approve" | "deny";

interface CommonForm {
  name: string;
  display_name: string;
  protocol: SsoProtocol;
  enabled: boolean;
  jit_policy: JitPolicy;
  allowed_email_domains: string;
  force_for_domains: string;
}

interface OidcForm {
  issuer_url: string;
  client_id: string;
  client_secret: string;
  scopes: string;
  require_email_verified_claim: boolean;
  group_claim_path: string;
  group_mapping_json: string;
  bind_to_idp_session: boolean;
}

interface SamlForm {
  idp_entity_id: string;
  idp_sso_url: string;
  idp_slo_url: string;
  idp_x509_cert: string;
  sp_entity_id: string;
  sp_acs_url: string;
  sp_slo_url: string;
  sp_x509_cert: string;
  sp_private_key: string;
  name_id_format: string;
  attribute_mapping_json: string;
  sign_requests: boolean;
  want_assertions_signed: boolean;
  want_messages_signed: boolean;
  want_assertions_encrypted: boolean;
  group_attribute: string;
  group_mapping_json: string;
}

const EMPTY_COMMON: CommonForm = {
  name: "",
  display_name: "",
  protocol: "oidc",
  enabled: true,
  jit_policy: "auto",
  allowed_email_domains: "",
  force_for_domains: "",
};

const EMPTY_OIDC: OidcForm = {
  issuer_url: "",
  client_id: "",
  client_secret: "",
  scopes: "openid, email, profile",
  require_email_verified_claim: true,
  group_claim_path: "",
  group_mapping_json: "{}",
  bind_to_idp_session: false,
};

const EMPTY_SAML: SamlForm = {
  idp_entity_id: "",
  idp_sso_url: "",
  idp_slo_url: "",
  idp_x509_cert: "",
  sp_entity_id: "",
  sp_acs_url: "",
  sp_slo_url: "",
  sp_x509_cert: "",
  sp_private_key: "",
  name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  attribute_mapping_json: '{"email": "email"}',
  sign_requests: true,
  want_assertions_signed: true,
  want_messages_signed: true,
  want_assertions_encrypted: false,
  group_attribute: "",
  group_mapping_json: "{}",
};

const UNCHANGED_SENTINEL = "<<unchanged>>";

function apiDetail(err: unknown): string {
  if (err instanceof AxiosError) {
    const detail = (err.response?.data as { detail?: string })?.detail;
    if (detail) return typeof detail === "string" ? detail : JSON.stringify(detail);
  }
  return "Unknown error";
}

function buildOidcConfig(form: OidcForm, isEdit: boolean): Record<string, unknown> {
  const scopes = form.scopes
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const cfg: Record<string, unknown> = {
    issuer_url: form.issuer_url.trim(),
    client_id: form.client_id.trim(),
    scopes: scopes.length ? scopes : ["openid", "email", "profile"],
    require_email_verified_claim: form.require_email_verified_claim,
  };
  if (isEdit && (form.client_secret === "***" || form.client_secret === "")) {
    cfg.client_secret = UNCHANGED_SENTINEL;
  } else {
    cfg.client_secret = form.client_secret;
  }
  if (form.group_claim_path.trim()) {
    cfg.group_claim_path = form.group_claim_path.trim();
  }
  // group_mapping is admin-curated JSON: {idp_group: sccap_group_name}
  try {
    const parsed = JSON.parse(form.group_mapping_json || "{}");
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      cfg.group_mapping = parsed;
    }
  } catch {
    // Caller validated; leave empty
  }
  cfg.bind_to_idp_session = form.bind_to_idp_session;
  return cfg;
}

function buildSamlConfig(form: SamlForm, isEdit: boolean): Record<string, unknown> {
  let attributeMapping: Record<string, string> = { email: "email" };
  try {
    const parsed = JSON.parse(form.attribute_mapping_json);
    if (parsed && typeof parsed === "object") {
      attributeMapping = parsed as Record<string, string>;
    }
  } catch {
    // Caller already validated; leave default.
  }
  const cfg: Record<string, unknown> = {
    idp_entity_id: form.idp_entity_id.trim(),
    idp_sso_url: form.idp_sso_url.trim(),
    idp_x509_cert: form.idp_x509_cert.trim(),
    sp_entity_id: form.sp_entity_id.trim(),
    sp_acs_url: form.sp_acs_url.trim(),
    name_id_format: form.name_id_format.trim(),
    attribute_mapping: attributeMapping,
    sign_requests: form.sign_requests,
    want_assertions_signed: form.want_assertions_signed,
    want_messages_signed: form.want_messages_signed,
    want_assertions_encrypted: form.want_assertions_encrypted,
  };
  if (form.idp_slo_url.trim()) cfg.idp_slo_url = form.idp_slo_url.trim();
  if (form.sp_slo_url.trim()) cfg.sp_slo_url = form.sp_slo_url.trim();
  if (form.sp_x509_cert.trim()) cfg.sp_x509_cert = form.sp_x509_cert.trim();
  if (isEdit && (form.sp_private_key === "***" || form.sp_private_key === "")) {
    if (form.sp_x509_cert.trim()) cfg.sp_private_key = UNCHANGED_SENTINEL;
  } else if (form.sp_private_key.trim()) {
    cfg.sp_private_key = form.sp_private_key;
  }
  if (form.group_attribute.trim()) {
    cfg.group_attribute = form.group_attribute.trim();
  }
  try {
    const parsed = JSON.parse(form.group_mapping_json || "{}");
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      cfg.group_mapping = parsed;
    }
  } catch {
    // Caller validated; leave empty
  }
  return cfg;
}

const SsoProvidersPage: React.FC = () => {
  const toast = useToast();
  const qc = useQueryClient();

  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<SsoProviderAdmin | null>(null);
  const [common, setCommon] = useState<CommonForm>(EMPTY_COMMON);
  const [oidc, setOidc] = useState<OidcForm>(EMPTY_OIDC);
  const [saml, setSaml] = useState<SamlForm>(EMPTY_SAML);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<Record<string, unknown> | null>(
    null,
  );

  const { data: providers, isLoading } = useQuery({
    queryKey: ["admin-sso-providers"],
    queryFn: ssoService.adminListProviders,
  });

  const invalidate = () =>
    qc.invalidateQueries({ queryKey: ["admin-sso-providers"] });

  const createMutation = useMutation({
    mutationFn: (payload: SsoProviderCreate) =>
      ssoService.adminCreateProvider(payload),
    onSuccess: () => {
      toast.success("Provider created.");
      invalidate();
      closeModal();
    },
    onError: (err) =>
      toast.error(`Create failed: ${apiDetail(err)}`),
  });

  const updateMutation = useMutation({
    mutationFn: (args: { id: string; payload: SsoProviderUpdate }) =>
      ssoService.adminUpdateProvider(args.id, args.payload),
    onSuccess: () => {
      toast.success("Provider updated.");
      invalidate();
      closeModal();
    },
    onError: (err) =>
      toast.error(`Update failed: ${apiDetail(err)}`),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => ssoService.adminDeleteProvider(id),
    onSuccess: () => {
      toast.success("Provider deleted.");
      setConfirmDeleteId(null);
      invalidate();
    },
    onError: (err) =>
      toast.error(`Delete failed: ${apiDetail(err)}`),
  });

  const testMutation = useMutation({
    mutationFn: (id: string) => ssoService.adminTestProvider(id),
    onSuccess: (data) => {
      setTestResult(data);
      if (data.ok) {
        toast.success("Provider test OK.");
      } else {
        toast.error(`Test failed: ${String(data.error ?? "unknown")}`);
      }
    },
    onError: (err) => {
      toast.error(`Test failed: ${apiDetail(err)}`);
      setTestResult(null);
    },
  });

  const apiBase = useMemo(() => {
    const fromEnv = import.meta.env.VITE_API_BASE_URL;
    if (fromEnv) return String(fromEnv).replace(/\/+$/, "");
    return `${window.location.origin}/api/v1`;
  }, []);

  const openCreateModal = () => {
    setEditing(null);
    setCommon(EMPTY_COMMON);
    setOidc(EMPTY_OIDC);
    setSaml(EMPTY_SAML);
    setModalOpen(true);
  };

  const openEditModal = (p: SsoProviderAdmin) => {
    setEditing(p);
    setCommon({
      name: p.name,
      display_name: p.display_name,
      protocol: p.protocol,
      enabled: p.enabled,
      jit_policy: p.jit_policy,
      allowed_email_domains: (p.allowed_email_domains ?? []).join(", "),
      force_for_domains: (p.force_for_domains ?? []).join(", "),
    });
    if (p.protocol === "oidc") {
      const cfg = p.config as Record<string, unknown>;
      setOidc({
        issuer_url: String(cfg.issuer_url ?? ""),
        client_id: String(cfg.client_id ?? ""),
        client_secret: String(cfg.client_secret ?? "***"),
        scopes: Array.isArray(cfg.scopes)
          ? (cfg.scopes as string[]).join(", ")
          : EMPTY_OIDC.scopes,
        require_email_verified_claim: Boolean(
          cfg.require_email_verified_claim ?? true,
        ),
        group_claim_path: String(cfg.group_claim_path ?? ""),
        group_mapping_json: JSON.stringify(
          (cfg.group_mapping ?? {}) as Record<string, unknown>,
          null,
          2,
        ),
        bind_to_idp_session: Boolean(cfg.bind_to_idp_session ?? false),
      });
      setSaml(EMPTY_SAML);
    } else {
      const cfg = p.config as Record<string, unknown>;
      const am = (cfg.attribute_mapping ?? {}) as Record<string, string>;
      setSaml({
        idp_entity_id: String(cfg.idp_entity_id ?? ""),
        idp_sso_url: String(cfg.idp_sso_url ?? ""),
        idp_slo_url: String(cfg.idp_slo_url ?? ""),
        idp_x509_cert: String(cfg.idp_x509_cert ?? ""),
        sp_entity_id: String(cfg.sp_entity_id ?? ""),
        sp_acs_url: String(cfg.sp_acs_url ?? ""),
        sp_slo_url: String(cfg.sp_slo_url ?? ""),
        sp_x509_cert: String(cfg.sp_x509_cert ?? ""),
        sp_private_key: String(cfg.sp_private_key ?? "***"),
        name_id_format: String(
          cfg.name_id_format ?? EMPTY_SAML.name_id_format,
        ),
        attribute_mapping_json: JSON.stringify(am, null, 2),
        sign_requests: Boolean(cfg.sign_requests ?? true),
        want_assertions_signed: Boolean(cfg.want_assertions_signed ?? true),
        want_messages_signed: Boolean(cfg.want_messages_signed ?? true),
        want_assertions_encrypted: Boolean(cfg.want_assertions_encrypted ?? false),
        group_attribute: String(cfg.group_attribute ?? ""),
        group_mapping_json: JSON.stringify(
          (cfg.group_mapping ?? {}) as Record<string, unknown>,
          null,
          2,
        ),
      });
      setOidc(EMPTY_OIDC);
    }
    setModalOpen(true);
  };

  const closeModal = () => {
    setModalOpen(false);
    setEditing(null);
    setTestResult(null);
  };

  const validateCommon = (): boolean => {
    if (!common.name.trim() || !/^[a-zA-Z0-9_-]+$/.test(common.name.trim())) {
      toast.error("Name is required and must be URL-safe (a-z, 0-9, _, -).");
      return false;
    }
    if (!common.display_name.trim()) {
      toast.error("Display name is required.");
      return false;
    }
    return true;
  };

  const onSubmit = () => {
    if (!validateCommon()) return;
    const isEdit = editing !== null;
    let configPayload: Record<string, unknown>;
    try {
      if (common.protocol === "oidc") {
        if (!oidc.issuer_url.trim() || !oidc.client_id.trim()) {
          toast.error("OIDC: issuer URL and client ID are required.");
          return;
        }
        if (!isEdit && !oidc.client_secret) {
          toast.error("OIDC: client secret is required when creating a provider.");
          return;
        }
        configPayload = buildOidcConfig(oidc, isEdit);
      } else {
        if (!saml.idp_entity_id.trim() || !saml.idp_sso_url.trim() || !saml.idp_x509_cert.trim()) {
          toast.error("SAML: IdP entity ID, SSO URL, and X.509 cert are required.");
          return;
        }
        if (!saml.sp_entity_id.trim() || !saml.sp_acs_url.trim()) {
          toast.error("SAML: SP entity ID and ACS URL are required.");
          return;
        }
        try {
          JSON.parse(saml.attribute_mapping_json);
        } catch {
          toast.error("SAML: attribute mapping must be valid JSON.");
          return;
        }
        configPayload = buildSamlConfig(saml, isEdit);
      }
    } catch {
      toast.error("Failed to build provider config.");
      return;
    }

    const allowedDomains =
      common.allowed_email_domains
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean) || [];
    const forceDomains =
      common.force_for_domains
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean) || [];

    if (isEdit && editing) {
      const update: SsoProviderUpdate = {
        display_name: common.display_name.trim(),
        enabled: common.enabled,
        jit_policy: common.jit_policy,
        config: configPayload,
        allowed_email_domains: allowedDomains.length ? allowedDomains : null,
        force_for_domains: forceDomains.length ? forceDomains : null,
      };
      updateMutation.mutate({ id: editing.id, payload: update });
    } else {
      const create: SsoProviderCreate = {
        name: common.name.trim(),
        display_name: common.display_name.trim(),
        protocol: common.protocol,
        config: configPayload,
        enabled: common.enabled,
        jit_policy: common.jit_policy,
        allowed_email_domains: allowedDomains.length ? allowedDomains : null,
        force_for_domains: forceDomains.length ? forceDomains : null,
      };
      createMutation.mutate(create);
    }
  };

  const pending = createMutation.isPending || updateMutation.isPending;

  // Reusable callback URL for the operator to register at the IdP.
  const callbackUrlFor = (name: string, suffix: string) =>
    `${apiBase}/auth/sso/${name}/${suffix}`;

  // Provider name for display in the IdP-binding hint.
  const provName = common.name.trim() || editing?.name || "<provider-slug>";

  return (
    <div className="fade-in" style={{ display: "grid", gap: 16 }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-end",
          gap: 12,
        }}
      >
        <div>
          <h1 style={{ color: "var(--fg)" }}>SSO Providers</h1>
          <div style={{ color: "var(--fg-muted)", marginTop: 4 }}>
            Configure OIDC and SAML 2.0 identity providers. Multiple
            providers can run side by side.
          </div>
        </div>
        <button
          className="sccap-btn sccap-btn-primary"
          onClick={openCreateModal}
        >
          <Icon.Plus size={13} /> Add provider
        </button>
      </div>

      {isLoading ? (
        <div className="sccap-card" style={{ padding: 40, textAlign: "center", color: "var(--fg-muted)" }}>
          Loading…
        </div>
      ) : !providers || providers.length === 0 ? (
        <div className="sccap-card" style={{ padding: 60, textAlign: "center" }}>
          <div style={{ color: "var(--fg)", fontWeight: 500, marginBottom: 4 }}>
            No SSO providers yet
          </div>
          <div style={{ color: "var(--fg-muted)", fontSize: 13 }}>
            Add one to let users sign in via your identity provider.
          </div>
        </div>
      ) : (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(360px, 1fr))",
            gap: 14,
          }}
        >
          {providers.map((p) => (
            <div key={p.id} className="sccap-card">
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "flex-start",
                  marginBottom: 10,
                }}
              >
                <div>
                  <div style={{ fontSize: 10.5, color: "var(--fg-subtle)", textTransform: "uppercase", letterSpacing: ".06em" }}>
                    {p.protocol.toUpperCase()} · {p.enabled ? "Enabled" : "Disabled"}
                  </div>
                  <div style={{ fontWeight: 600, color: "var(--fg)", marginTop: 2 }}>
                    {p.display_name}
                  </div>
                  <div className="mono" style={{ fontSize: 11, color: "var(--fg-subtle)" }}>
                    {p.name}
                  </div>
                </div>
                <div style={{ display: "flex", gap: 4 }}>
                  <button
                    className="sccap-btn sccap-btn-icon sccap-btn-ghost"
                    onClick={() => testMutation.mutate(p.id)}
                    aria-label="Test provider"
                    disabled={testMutation.isPending}
                  >
                    <Icon.Check size={13} />
                  </button>
                  <button
                    className="sccap-btn sccap-btn-icon sccap-btn-ghost"
                    onClick={() => openEditModal(p)}
                    aria-label="Edit"
                  >
                    <Icon.Edit size={13} />
                  </button>
                  <button
                    className="sccap-btn sccap-btn-icon sccap-btn-ghost"
                    onClick={() => setConfirmDeleteId(p.id)}
                    aria-label="Delete"
                    style={{ color: "var(--critical)" }}
                  >
                    <Icon.Trash size={13} />
                  </button>
                </div>
              </div>
              <div style={{ display: "grid", gap: 4, fontSize: 12, color: "var(--fg-muted)" }}>
                <div>JIT policy: <b>{p.jit_policy}</b></div>
                {p.allowed_email_domains && p.allowed_email_domains.length > 0 && (
                  <div>Allowed domains: {p.allowed_email_domains.join(", ")}</div>
                )}
                {p.force_for_domains && p.force_for_domains.length > 0 && (
                  <div style={{ color: "var(--warning)" }}>
                    Force-SSO for: {p.force_for_domains.join(", ")}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Create / edit modal */}
      <Modal
        open={modalOpen}
        onClose={closeModal}
        title={editing ? `Edit ${editing.display_name}` : "Add SSO provider"}
        width={720}
        footer={
          <>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={closeModal}
              disabled={pending}
            >
              Cancel
            </button>
            <button
              className="sccap-btn sccap-btn-primary sccap-btn-sm"
              onClick={onSubmit}
              disabled={pending}
            >
              {pending ? "Saving…" : editing ? "Save changes" : "Create provider"}
            </button>
          </>
        }
      >
        <div style={{ display: "grid", gap: 14 }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <label style={{ display: "grid", gap: 6 }}>
              <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>Internal slug</span>
              <input
                className="sccap-input"
                placeholder="okta-prod"
                value={common.name}
                onChange={(e) => setCommon({ ...common, name: e.target.value })}
                disabled={editing !== null}
                maxLength={64}
              />
            </label>
            <label style={{ display: "grid", gap: 6 }}>
              <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>Display name</span>
              <input
                className="sccap-input"
                placeholder="Okta"
                value={common.display_name}
                onChange={(e) => setCommon({ ...common, display_name: e.target.value })}
                maxLength={128}
              />
            </label>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <label style={{ display: "grid", gap: 6 }}>
              <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>Protocol</span>
              <select
                className="sccap-input"
                value={common.protocol}
                disabled={editing !== null}
                onChange={(e) =>
                  setCommon({ ...common, protocol: e.target.value as SsoProtocol })
                }
              >
                <option value="oidc">OpenID Connect</option>
                <option value="saml">SAML 2.0</option>
              </select>
            </label>
            <label style={{ display: "grid", gap: 6 }}>
              <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>JIT policy</span>
              <select
                className="sccap-input"
                value={common.jit_policy}
                onChange={(e) =>
                  setCommon({ ...common, jit_policy: e.target.value as JitPolicy })
                }
              >
                <option value="auto">Auto-create new users</option>
                <option value="approve">Admin approves new users</option>
                <option value="deny">Deny new users (existing only)</option>
              </select>
            </label>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <label style={{ display: "grid", gap: 6 }}>
              <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
                Allowed email domains <span style={{ color: "var(--fg-subtle)" }}>(comma-sep, optional)</span>
              </span>
              <input
                className="sccap-input"
                placeholder="company.com, contractor.io"
                value={common.allowed_email_domains}
                onChange={(e) =>
                  setCommon({ ...common, allowed_email_domains: e.target.value })
                }
              />
            </label>
            <label style={{ display: "grid", gap: 6 }}>
              <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
                Force SSO for domains <span style={{ color: "var(--fg-subtle)" }}>(disables password)</span>
              </span>
              <input
                className="sccap-input"
                placeholder="company.com"
                value={common.force_for_domains}
                onChange={(e) =>
                  setCommon({ ...common, force_for_domains: e.target.value })
                }
              />
            </label>
          </div>

          <label style={{ display: "inline-flex", gap: 8, alignItems: "center", fontSize: 13 }}>
            <input
              type="checkbox"
              checked={common.enabled}
              onChange={(e) => setCommon({ ...common, enabled: e.target.checked })}
              style={{ accentColor: "var(--primary)" }}
            />
            Enabled
          </label>

          {/* Protocol-specific section */}
          <div style={{ paddingTop: 6, borderTop: "1px solid var(--border)" }}>
            <div
              style={{
                fontSize: 11,
                color: "var(--fg-subtle)",
                textTransform: "uppercase",
                letterSpacing: ".06em",
                margin: "10px 0 8px 0",
              }}
            >
              {common.protocol === "oidc" ? "OIDC settings" : "SAML 2.0 settings"}
            </div>

            {common.protocol === "oidc" ? (
              <div style={{ display: "grid", gap: 10 }}>
                <label style={{ display: "grid", gap: 6 }}>
                  <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>Issuer URL (https only)</span>
                  <input
                    className="sccap-input"
                    placeholder="https://company.okta.com"
                    value={oidc.issuer_url}
                    onChange={(e) => setOidc({ ...oidc, issuer_url: e.target.value })}
                  />
                </label>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                  <label style={{ display: "grid", gap: 6 }}>
                    <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>Client ID</span>
                    <input
                      className="sccap-input"
                      value={oidc.client_id}
                      onChange={(e) => setOidc({ ...oidc, client_id: e.target.value })}
                    />
                  </label>
                  <label style={{ display: "grid", gap: 6 }}>
                    <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
                      Client secret {editing && <span style={{ color: "var(--fg-subtle)" }}>(blank = keep)</span>}
                    </span>
                    <input
                      className="sccap-input"
                      type="password"
                      value={oidc.client_secret}
                      onChange={(e) => setOidc({ ...oidc, client_secret: e.target.value })}
                      placeholder={editing ? "(leave blank to keep)" : ""}
                    />
                  </label>
                </div>
                <label style={{ display: "grid", gap: 6 }}>
                  <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>Scopes (comma-sep)</span>
                  <input
                    className="sccap-input"
                    value={oidc.scopes}
                    onChange={(e) => setOidc({ ...oidc, scopes: e.target.value })}
                  />
                </label>
                <label style={{ display: "inline-flex", gap: 8, alignItems: "center", fontSize: 13 }}>
                  <input
                    type="checkbox"
                    checked={oidc.require_email_verified_claim}
                    onChange={(e) =>
                      setOidc({ ...oidc, require_email_verified_claim: e.target.checked })
                    }
                    style={{ accentColor: "var(--primary)" }}
                  />
                  Require <code>email_verified=true</code> claim from the IdP (recommended)
                </label>
                <label style={{ display: "grid", gap: 6 }}>
                  <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
                    Group claim path <span style={{ color: "var(--fg-subtle)" }}>(optional, e.g. <code>groups</code> or <code>realm_access.roles</code>)</span>
                  </span>
                  <input
                    className="sccap-input"
                    placeholder="groups"
                    value={oidc.group_claim_path}
                    onChange={(e) => setOidc({ ...oidc, group_claim_path: e.target.value })}
                  />
                </label>
                <label style={{ display: "grid", gap: 6 }}>
                  <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
                    Group mapping (JSON: IdP group → SCCAP user_group name)
                  </span>
                  <textarea
                    className="sccap-input mono"
                    rows={4}
                    placeholder='{"engineering": "Platform Engineering", "sec-ops": "Security"}'
                    value={oidc.group_mapping_json}
                    onChange={(e) =>
                      setOidc({ ...oidc, group_mapping_json: e.target.value })
                    }
                  />
                  <span style={{ fontSize: 11, color: "var(--fg-subtle)" }}>
                    Mapped groups are added <b>additively</b> on each login. Group memberships are NEVER auto-removed; <code>is_superuser</code> is NEVER granted via SSO claims.
                  </span>
                </label>
                <label style={{ display: "inline-flex", gap: 8, alignItems: "center", fontSize: 13 }}>
                  <input
                    type="checkbox"
                    checked={oidc.bind_to_idp_session}
                    onChange={(e) =>
                      setOidc({ ...oidc, bind_to_idp_session: e.target.checked })
                    }
                    style={{ accentColor: "var(--primary)" }}
                  />
                  Bind SCCAP session to IdP session lifetime
                  <span style={{ fontSize: 11, color: "var(--fg-subtle)", marginLeft: 8 }}>
                    (refresh fails after the IdP-issued access token expires)
                  </span>
                </label>
                <div className="inset" style={{ padding: 10, fontSize: 12, color: "var(--fg-muted)" }}>
                  Register this redirect URI at the IdP:
                  <div className="mono" style={{ marginTop: 4 }}>
                    {callbackUrlFor(provName, "callback")}
                  </div>
                  <div style={{ marginTop: 6, fontSize: 11, color: "var(--fg-subtle)" }}>
                    Split-origin deploys: ensure backend <code>API_BASE_URL</code> matches the host above.
                  </div>
                </div>
              </div>
            ) : (
              <div style={{ display: "grid", gap: 10 }}>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                  <label style={{ display: "grid", gap: 6 }}>
                    <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>IdP entity ID</span>
                    <input
                      className="sccap-input"
                      value={saml.idp_entity_id}
                      onChange={(e) => setSaml({ ...saml, idp_entity_id: e.target.value })}
                    />
                  </label>
                  <label style={{ display: "grid", gap: 6 }}>
                    <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>IdP SSO URL</span>
                    <input
                      className="sccap-input"
                      value={saml.idp_sso_url}
                      onChange={(e) => setSaml({ ...saml, idp_sso_url: e.target.value })}
                    />
                  </label>
                </div>
                <label style={{ display: "grid", gap: 6 }}>
                  <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
                    IdP X.509 certificate (PEM)
                  </span>
                  <textarea
                    className="sccap-input mono"
                    rows={5}
                    value={saml.idp_x509_cert}
                    onChange={(e) => setSaml({ ...saml, idp_x509_cert: e.target.value })}
                    placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                  />
                </label>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                  <label style={{ display: "grid", gap: 6 }}>
                    <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>SP entity ID</span>
                    <input
                      className="sccap-input"
                      value={saml.sp_entity_id}
                      onChange={(e) => setSaml({ ...saml, sp_entity_id: e.target.value })}
                      placeholder={callbackUrlFor(provName, "metadata")}
                    />
                  </label>
                  <label style={{ display: "grid", gap: 6 }}>
                    <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>SP ACS URL</span>
                    <input
                      className="sccap-input"
                      value={saml.sp_acs_url}
                      onChange={(e) => setSaml({ ...saml, sp_acs_url: e.target.value })}
                      placeholder={callbackUrlFor(provName, "acs")}
                    />
                  </label>
                </div>
                <label style={{ display: "grid", gap: 6 }}>
                  <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
                    Attribute mapping (JSON: SAML attr → internal field)
                  </span>
                  <textarea
                    className="sccap-input mono"
                    rows={3}
                    value={saml.attribute_mapping_json}
                    onChange={(e) =>
                      setSaml({ ...saml, attribute_mapping_json: e.target.value })
                    }
                  />
                </label>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                  <label style={{ display: "inline-flex", gap: 8, alignItems: "center", fontSize: 13 }}>
                    <input
                      type="checkbox"
                      checked={saml.want_assertions_signed}
                      onChange={(e) =>
                        setSaml({ ...saml, want_assertions_signed: e.target.checked })
                      }
                      style={{ accentColor: "var(--primary)" }}
                    />
                    Require signed assertions
                  </label>
                  <label style={{ display: "inline-flex", gap: 8, alignItems: "center", fontSize: 13 }}>
                    <input
                      type="checkbox"
                      checked={saml.want_messages_signed}
                      onChange={(e) =>
                        setSaml({ ...saml, want_messages_signed: e.target.checked })
                      }
                      style={{ accentColor: "var(--primary)" }}
                    />
                    Require signed responses
                  </label>
                </div>
                <label style={{ display: "grid", gap: 6 }}>
                  <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
                    Group attribute name <span style={{ color: "var(--fg-subtle)" }}>(optional, e.g. <code>memberOf</code> or <code>http://schemas.xmlsoap.org/claims/Group</code>)</span>
                  </span>
                  <input
                    className="sccap-input"
                    placeholder="memberOf"
                    value={saml.group_attribute}
                    onChange={(e) => setSaml({ ...saml, group_attribute: e.target.value })}
                  />
                </label>
                <label style={{ display: "grid", gap: 6 }}>
                  <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
                    Group mapping (JSON: IdP group → SCCAP user_group name)
                  </span>
                  <textarea
                    className="sccap-input mono"
                    rows={4}
                    placeholder='{"CN=Engineering,OU=Groups,DC=corp,DC=local": "Platform Engineering"}'
                    value={saml.group_mapping_json}
                    onChange={(e) =>
                      setSaml({ ...saml, group_mapping_json: e.target.value })
                    }
                  />
                  <span style={{ fontSize: 11, color: "var(--fg-subtle)" }}>
                    Mapped groups are added <b>additively</b>; <code>is_superuser</code> is NEVER granted via SSO claims.
                  </span>
                </label>
                <div className="inset" style={{ padding: 10, fontSize: 12, color: "var(--fg-muted)" }}>
                  Register these endpoints at the IdP:
                  <div className="mono" style={{ marginTop: 4 }}>
                    ACS: {callbackUrlFor(provName, "acs")}
                    <br />
                    Metadata: {callbackUrlFor(provName, "metadata")}
                    <br />
                    SLO: {callbackUrlFor(provName, "slo")}
                  </div>
                  <div style={{ marginTop: 6, fontSize: 11, color: "var(--fg-subtle)" }}>
                    Split-origin deploys: ensure backend <code>API_BASE_URL</code> matches the host above.
                  </div>
                </div>
              </div>
            )}
          </div>

          {testResult && (
            <div
              className="inset"
              style={{
                padding: 10,
                fontSize: 12,
                color: testResult.ok ? "var(--success)" : "var(--critical)",
              }}
            >
              <div style={{ fontWeight: 600 }}>
                {testResult.ok ? "Test OK" : "Test failed"}
              </div>
              <pre className="mono" style={{ margin: 0, fontSize: 11 }}>
                {JSON.stringify(testResult, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </Modal>

      {/* Delete confirm */}
      <Modal
        open={confirmDeleteId !== null}
        onClose={() => setConfirmDeleteId(null)}
        title="Delete SSO provider?"
        width={420}
        footer={
          <>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={() => setConfirmDeleteId(null)}
              disabled={deleteMutation.isPending}
            >
              Cancel
            </button>
            <button
              className="sccap-btn sccap-btn-sm"
              style={{ background: "var(--critical)", color: "#fff", border: "none" }}
              onClick={() =>
                confirmDeleteId && deleteMutation.mutate(confirmDeleteId)
              }
              disabled={deleteMutation.isPending}
            >
              {deleteMutation.isPending ? "Deleting…" : "Delete provider"}
            </button>
          </>
        }
      >
        <div style={{ fontSize: 13, color: "var(--fg-muted)" }}>
          Linked OAuth/SAML accounts for this provider will be removed. Users
          will need to re-link via a different provider, or use the password
          reset flow.
        </div>
      </Modal>
    </div>
  );
};

export default SsoProvidersPage;
