// secure-code-ui/src/pages/admin/ScimTokensPage.tsx
//
// Admin surface for SCIM 2.0 bearer tokens — the credentials IdPs
// (Okta, Azure / Entra) use to drive /scim/v2/Users + /scim/v2/Groups.
// The plaintext is returned ONCE at issue time and never retrievable
// later, so this page surfaces it in a copy-once banner.

import React, { useEffect, useMemo, useState } from "react";
import { Icon } from "../../shared/ui/Icon";
import { useToast } from "../../shared/ui/Toast";
import { SectionHead } from "../../shared/ui/DashboardPrimitives";
import {
  scimService,
  type ScimToken,
  type ScimTokenIssued,
  type ScimScope,
  ALL_SCIM_SCOPES,
} from "../../shared/api/scimService";

const fmt = (iso: string | null): string => {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
};

const ScopeChip: React.FC<{ children: React.ReactNode; tone?: "read" | "write" }> = ({
  children,
  tone = "read",
}) => (
  <span
    style={{
      display: "inline-flex",
      alignItems: "center",
      padding: "2px 8px",
      borderRadius: 999,
      fontSize: 11,
      lineHeight: 1.4,
      background: tone === "write" ? "var(--high)" : "var(--bg-soft)",
      color: tone === "write" ? "#fff" : "var(--fg-muted)",
      border: "1px solid var(--border)",
      letterSpacing: ".02em",
      fontFamily: "var(--font-mono)",
    }}
  >
    {children}
  </span>
);

const ScimTokensPage: React.FC = () => {
  const toast = useToast();
  const [tokens, setTokens] = useState<ScimToken[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [revokingId, setRevokingId] = useState<string | null>(null);

  // Form state.
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<Set<ScimScope>>(
    () => new Set<ScimScope>(["users:read", "users:write"]),
  );
  const [expiresAt, setExpiresAt] = useState<string>("");

  // Issue-once banner state.
  const [issued, setIssued] = useState<ScimTokenIssued | null>(null);
  const [copied, setCopied] = useState(false);

  const refresh = async () => {
    try {
      const rows = await scimService.listTokens();
      setTokens(rows);
    } catch (err) {
      const msg =
        (err as { response?: { data?: { detail?: string } }; message?: string })
          ?.response?.data?.detail ||
        (err as { message?: string })?.message ||
        "Failed to load SCIM tokens";
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const onToggleScope = (s: ScimScope) => {
    setScopes((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  };

  const onCreate = async () => {
    const trimmed = name.trim();
    if (!trimmed) {
      toast.error("Token name is required.");
      return;
    }
    if (scopes.size === 0) {
      toast.error("Pick at least one scope.");
      return;
    }
    setCreating(true);
    try {
      const row = await scimService.createToken({
        name: trimmed,
        scopes: Array.from(scopes),
        expires_at: expiresAt ? new Date(expiresAt).toISOString() : null,
      });
      setIssued(row);
      setCopied(false);
      setName("");
      setExpiresAt("");
      await refresh();
    } catch (err) {
      const msg =
        (err as { response?: { data?: { detail?: string } }; message?: string })
          ?.response?.data?.detail ||
        (err as { message?: string })?.message ||
        "Failed to issue token";
      toast.error(msg);
    } finally {
      setCreating(false);
    }
  };

  const onRevoke = async (row: ScimToken) => {
    const ok = window.confirm(
      `Revoke SCIM token "${row.name}"? Any IdP using it will start failing immediately.`,
    );
    if (!ok) return;
    setRevokingId(row.id);
    try {
      await scimService.revokeToken(row.id);
      toast.success("Token revoked.");
      // Defensive: clear the issue banner if the operator revokes the
      // token they just created without copying it.
      if (issued?.id === row.id) setIssued(null);
      await refresh();
    } catch (err) {
      const msg =
        (err as { response?: { data?: { detail?: string } }; message?: string })
          ?.response?.data?.detail ||
        (err as { message?: string })?.message ||
        "Failed to revoke token";
      toast.error(msg);
    } finally {
      setRevokingId(null);
    }
  };

  const onCopyPlaintext = async () => {
    if (!issued) return;
    try {
      await navigator.clipboard.writeText(issued.plaintext_token);
      setCopied(true);
      toast.success("Token copied to clipboard.");
    } catch {
      toast.error("Couldn't copy automatically — select and copy manually.");
    }
  };

  const sortedTokens = useMemo(
    () => [...tokens].sort((a, b) => a.created_at.localeCompare(b.created_at)),
    [tokens],
  );

  return (
    <div className="fade-in" style={{ display: "grid", gap: 20 }}>
      <div className="sccap-card">
        <SectionHead
          title={
            <>
              <Icon.Lock size={16} /> SCIM 2.0 tokens
            </>
          }
        />
        <div style={{ color: "var(--fg-muted)", fontSize: 13, marginTop: 4 }}>
          Bearer tokens for upstream IdPs (Okta, Azure / Entra, OneLogin) to
          provision users + groups via{" "}
          <code style={{ fontFamily: "var(--font-mono)" }}>/scim/v2</code>. The
          plaintext is shown once at issue time — copy it to your IdP
          immediately; we only store a hash.
        </div>
      </div>

      {issued && (
        <div
          className="sccap-card"
          style={{
            border: "2px solid var(--success, var(--primary))",
            background: "var(--success-weak, var(--bg-soft))",
          }}
        >
          <div style={{ display: "grid", gap: 10 }}>
            <div style={{ fontWeight: 600, color: "var(--fg)" }}>
              Token issued — copy it now
            </div>
            <div
              style={{
                display: "flex",
                gap: 8,
                alignItems: "stretch",
              }}
            >
              <input
                readOnly
                className="sccap-input mono"
                value={issued.plaintext_token}
                onFocus={(e) => e.currentTarget.select()}
                style={{ flex: 1 }}
              />
              <button
                className="sccap-btn"
                onClick={() => void onCopyPlaintext()}
                title="Copy to clipboard"
              >
                <Icon.Copy size={14} />
                {copied ? "Copied" : "Copy"}
              </button>
              <button
                className="sccap-btn sccap-btn-ghost"
                onClick={() => setIssued(null)}
                title="Dismiss"
              >
                <Icon.X size={12} /> Dismiss
              </button>
            </div>
            <div style={{ fontSize: 12, color: "var(--fg-muted)" }}>
              This is the only time the plaintext will be shown. Once you
              dismiss this banner, the token can only be revoked — never
              re-displayed.
            </div>
          </div>
        </div>
      )}

      <div className="sccap-card">
        <div style={{ marginBottom: 12, fontWeight: 600, color: "var(--fg)" }}>
          Issue a new token
        </div>
        <div style={{ display: "grid", gap: 12, maxWidth: 720 }}>
          <label style={{ display: "grid", gap: 6 }}>
            <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
              Name (so you can recognise this IdP later)
            </span>
            <input
              className="sccap-input"
              placeholder="Okta production tenant"
              value={name}
              onChange={(e) => setName(e.target.value)}
              maxLength={128}
              disabled={creating}
            />
          </label>
          <div>
            <div
              style={{
                fontSize: 12,
                color: "var(--fg-muted)",
                marginBottom: 6,
              }}
            >
              Scopes
            </div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              {ALL_SCIM_SCOPES.map((s) => {
                const active = scopes.has(s);
                const isWrite = s.endsWith(":write");
                return (
                  <button
                    key={s}
                    type="button"
                    onClick={() => onToggleScope(s)}
                    disabled={creating}
                    style={{
                      padding: "4px 10px",
                      borderRadius: 999,
                      border: active
                        ? "2px solid var(--primary)"
                        : "1px solid var(--border)",
                      background: active
                        ? isWrite
                          ? "var(--high)"
                          : "var(--primary-weak)"
                        : "var(--bg-soft)",
                      color: active && isWrite ? "#fff" : "var(--fg)",
                      fontSize: 12,
                      fontFamily: "var(--font-mono)",
                      cursor: creating ? "not-allowed" : "pointer",
                    }}
                    aria-pressed={active}
                  >
                    {s}
                  </button>
                );
              })}
            </div>
            <div
              style={{
                fontSize: 11.5,
                color: "var(--fg-subtle)",
                marginTop: 6,
                lineHeight: 1.5,
              }}
            >
              Most IdPs need <code className="mono">users:read</code> +{" "}
              <code className="mono">users:write</code>. Add{" "}
              <code className="mono">groups:*</code> for group-membership sync.
            </div>
          </div>
          <label style={{ display: "grid", gap: 6, maxWidth: 280 }}>
            <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
              Expires at (optional)
            </span>
            <input
              className="sccap-input"
              type="datetime-local"
              value={expiresAt}
              onChange={(e) => setExpiresAt(e.target.value)}
              disabled={creating}
            />
          </label>
          <div>
            <button
              className="sccap-btn sccap-btn-primary"
              onClick={() => void onCreate()}
              disabled={creating || scopes.size === 0 || !name.trim()}
            >
              {creating ? "Issuing…" : (
                <>
                  <Icon.Plus size={14} /> Issue token
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      <div className="sccap-card">
        <SectionHead title={<>Active tokens</>} />
        {loading && (
          <div style={{ color: "var(--fg-muted)", fontSize: 13 }}>Loading…</div>
        )}
        {!loading && sortedTokens.length === 0 && (
          <div
            style={{
              padding: 16,
              borderRadius: 8,
              border: "1px dashed var(--border)",
              color: "var(--fg-muted)",
              fontSize: 13,
            }}
          >
            No SCIM tokens issued yet. Issue one above to start receiving
            provisioning calls from an IdP.
          </div>
        )}
        {!loading && sortedTokens.length > 0 && (
          <div style={{ display: "grid", gap: 8 }}>
            {sortedTokens.map((row) => {
              const expired =
                row.expires_at != null &&
                new Date(row.expires_at).getTime() < Date.now();
              return (
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
                    opacity: expired ? 0.65 : 1,
                  }}
                >
                  <div style={{ minWidth: 0 }}>
                    <div
                      style={{
                        fontWeight: 600,
                        color: "var(--fg)",
                        fontSize: 14,
                      }}
                    >
                      {row.name}
                      {expired && (
                        <span
                          style={{
                            marginLeft: 8,
                            fontSize: 11,
                            color: "var(--critical, var(--fg-subtle))",
                            fontWeight: 500,
                            textTransform: "uppercase",
                            letterSpacing: ".04em",
                          }}
                        >
                          expired
                        </span>
                      )}
                    </div>
                    <div
                      style={{
                        display: "flex",
                        gap: 6,
                        marginTop: 6,
                        flexWrap: "wrap",
                      }}
                    >
                      {row.scopes.map((s) => (
                        <ScopeChip
                          key={s}
                          tone={s.endsWith(":write") ? "write" : "read"}
                        >
                          {s}
                        </ScopeChip>
                      ))}
                    </div>
                    <div
                      style={{
                        marginTop: 8,
                        fontSize: 12,
                        color: "var(--fg-muted)",
                        display: "flex",
                        gap: 12,
                        flexWrap: "wrap",
                      }}
                    >
                      <span>Created {fmt(row.created_at)}</span>
                      <span>
                        Expires {row.expires_at ? fmt(row.expires_at) : "never"}
                      </span>
                      <span>Last used {fmt(row.last_used_at)}</span>
                    </div>
                  </div>
                  <div>
                    <button
                      className="sccap-btn sccap-btn-sm sccap-btn-ghost"
                      onClick={() => void onRevoke(row)}
                      disabled={revokingId === row.id}
                      title="Revoke this token"
                    >
                      <Icon.Trash size={12} />
                      {revokingId === row.id ? "Revoking…" : "Revoke"}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};

export default ScimTokensPage;
