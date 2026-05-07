// secure-code-ui/src/pages/account/SecuritySettingsPage.tsx
//
// Per-user security settings. Currently scoped to passkey (WebAuthn)
// management — list registered passkeys, register a new one, and
// remove an existing one. Future scope: per-user MFA toggles, recent
// auth-event timeline, active sessions.

import React, { useEffect, useMemo, useState } from "react";
import { Icon } from "../../shared/ui/Icon";
import { useToast } from "../../shared/ui/Toast";
import { SectionHead } from "../../shared/ui/DashboardPrimitives";
import {
  webauthnService,
  type PasskeySummary,
} from "../../shared/api/webauthnService";

const RowChip: React.FC<{ children: React.ReactNode; tone?: "muted" | "ok" }> = ({
  children,
  tone = "muted",
}) => (
  <span
    style={{
      display: "inline-flex",
      alignItems: "center",
      padding: "2px 8px",
      borderRadius: 999,
      fontSize: 11,
      lineHeight: 1.4,
      background:
        tone === "ok" ? "var(--success-weak, var(--bg-soft))" : "var(--bg-soft)",
      color: tone === "ok" ? "var(--success, var(--fg))" : "var(--fg-muted)",
      border: "1px solid var(--border)",
      textTransform: "uppercase",
      letterSpacing: ".04em",
    }}
  >
    {children}
  </span>
);

const fmt = (iso: string | null): string => {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    return d.toLocaleString();
  } catch {
    return iso;
  }
};

const SecuritySettingsPage: React.FC = () => {
  const toast = useToast();
  const [passkeys, setPasskeys] = useState<PasskeySummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [registering, setRegistering] = useState(false);
  const [removingId, setRemovingId] = useState<string | null>(null);
  const [friendlyName, setFriendlyName] = useState("");

  const supported = useMemo(() => webauthnService.isSupported(), []);

  const refresh = async () => {
    try {
      const rows = await webauthnService.list();
      setPasskeys(rows);
    } catch (err) {
      const msg =
        (err as { response?: { data?: { detail?: string } }; message?: string })
          ?.response?.data?.detail ||
        (err as { message?: string })?.message ||
        "Failed to load passkeys";
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const onRegister = async () => {
    if (!supported) {
      toast.error("This browser does not support WebAuthn / passkeys.");
      return;
    }
    const name = friendlyName.trim() || defaultPasskeyName();
    setRegistering(true);
    try {
      const row = await webauthnService.register(name);
      toast.success(`Passkey "${row.friendly_name}" added.`);
      setFriendlyName("");
      await refresh();
    } catch (err) {
      const msg =
        (err as { response?: { data?: { detail?: string } }; message?: string })
          ?.response?.data?.detail ||
        (err as { message?: string })?.message ||
        "Failed to register passkey";
      toast.error(msg);
    } finally {
      setRegistering(false);
    }
  };

  const onRemove = async (row: PasskeySummary) => {
    const ok = window.confirm(
      `Remove passkey "${row.friendly_name}"? You won't be able to use it to sign in after this.`,
    );
    if (!ok) return;
    setRemovingId(row.id);
    try {
      await webauthnService.remove(row.id);
      toast.success("Passkey removed.");
      await refresh();
    } catch (err) {
      const msg =
        (err as { response?: { data?: { detail?: string } }; message?: string })
          ?.response?.data?.detail ||
        (err as { message?: string })?.message ||
        "Failed to remove passkey";
      toast.error(msg);
    } finally {
      setRemovingId(null);
    }
  };

  return (
    <div className="fade-in" style={{ display: "grid", gap: 20, maxWidth: 760 }}>
      <div className="sccap-card">
        <SectionHead
          title={
            <>
              <Icon.Lock size={16} /> Passkeys
            </>
          }
        />
        <div style={{ color: "var(--fg-muted)", fontSize: 13, marginTop: 4 }}>
          Passkeys let you sign in with your device's biometric or PIN instead
          of a password. They're phishing-resistant and never leave your device.
        </div>
      </div>

      <div className="sccap-card">
        <div style={{ marginBottom: 12, fontWeight: 600, color: "var(--fg)" }}>
          Add a passkey
        </div>
        {!supported && (
          <div
            style={{
              padding: 12,
              borderRadius: 8,
              border: "1px solid var(--border)",
              background: "var(--bg-soft)",
              fontSize: 13,
              color: "var(--fg-muted)",
            }}
          >
            Your browser doesn't expose the WebAuthn API — passkey enrollment
            isn't available here.
          </div>
        )}
        {supported && (
          <div style={{ display: "grid", gap: 10 }}>
            <label style={{ display: "grid", gap: 6 }}>
              <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
                Name (so you can recognise this device later)
              </span>
              <input
                className="sccap-input"
                placeholder={defaultPasskeyName()}
                value={friendlyName}
                onChange={(e) => setFriendlyName(e.target.value)}
                maxLength={128}
                disabled={registering}
              />
            </label>
            <div>
              <button
                className="sccap-btn sccap-btn-primary"
                disabled={registering}
                onClick={() => void onRegister()}
              >
                {registering ? (
                  <>Registering…</>
                ) : (
                  <>
                    <Icon.Plus size={14} /> Add passkey
                  </>
                )}
              </button>
            </div>
            <div style={{ fontSize: 12, color: "var(--fg-subtle)", lineHeight: 1.5 }}>
              Your browser will prompt you to verify with Touch ID, Face ID, your
              Windows Hello PIN, or a hardware security key.
            </div>
          </div>
        )}
      </div>

      <div className="sccap-card">
        <SectionHead title={<>Registered passkeys</>} />
        {loading && (
          <div style={{ color: "var(--fg-muted)", fontSize: 13 }}>Loading…</div>
        )}
        {!loading && passkeys.length === 0 && (
          <div
            style={{
              padding: 16,
              borderRadius: 8,
              border: "1px dashed var(--border)",
              color: "var(--fg-muted)",
              fontSize: 13,
            }}
          >
            No passkeys registered yet. Add one above to enable passkey sign-in.
          </div>
        )}
        {!loading && passkeys.length > 0 && (
          <div style={{ display: "grid", gap: 10 }}>
            {passkeys.map((row) => (
              <div
                key={row.id}
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr auto",
                  gap: 10,
                  padding: 12,
                  borderRadius: 8,
                  border: "1px solid var(--border)",
                  background: "var(--bg-soft)",
                }}
              >
                <div style={{ minWidth: 0 }}>
                  <div
                    style={{
                      fontWeight: 600,
                      color: "var(--fg)",
                      fontSize: 14,
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                  >
                    {row.friendly_name}
                  </div>
                  <div
                    style={{
                      display: "flex",
                      flexWrap: "wrap",
                      gap: 6,
                      marginTop: 6,
                      fontSize: 12,
                      color: "var(--fg-muted)",
                    }}
                  >
                    <span>Added {fmt(row.created_at)}</span>
                    <span>•</span>
                    <span>Last used {fmt(row.last_used_at)}</span>
                    {row.transports && row.transports.length > 0 && (
                      <>
                        <span>•</span>
                        {row.transports.map((t) => (
                          <RowChip key={t}>{t}</RowChip>
                        ))}
                      </>
                    )}
                  </div>
                </div>
                <div>
                  <button
                    className="sccap-btn sccap-btn-sm sccap-btn-ghost"
                    disabled={removingId === row.id}
                    onClick={() => void onRemove(row)}
                    title="Remove this passkey"
                  >
                    <Icon.Trash size={12} />
                    {removingId === row.id ? "Removing…" : "Remove"}
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

function defaultPasskeyName(): string {
  // Best-effort device label — user can edit before submitting.
  const ua = navigator.userAgent || "";
  const platform =
    /iPhone|iPad/.test(ua)
      ? "iOS device"
      : /Macintosh/.test(ua)
        ? "Mac"
        : /Android/.test(ua)
          ? "Android device"
          : /Windows/.test(ua)
            ? "Windows device"
            : /Linux/.test(ua)
              ? "Linux device"
              : "this device";
  return `Passkey on ${platform}`;
}

export default SecuritySettingsPage;
