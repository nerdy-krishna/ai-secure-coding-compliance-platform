// secure-code-ui/src/features/authentication/components/ResetPasswordPage.tsx
//
// SCCAP set-new-password form. Wiring to authService.resetPassword
// unchanged.

import { AxiosError } from "axios";
import React, { useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { authService } from "../../../shared/api/authService";
import { Icon } from "../../../shared/ui/Icon";
import { useToast } from "../../../shared/ui/Toast";

// Mirror of the backend rules in `app/infrastructure/auth/schemas.py`. Keep in
// sync if the server-side rules change. Class definitions match the regex
// alternation used by `_password_class_count`.
const MIN_PASSWORD_LEN = 12;
const MAX_PASSWORD_LEN = 128;

function passwordClassCount(p: string): number {
  let n = 0;
  if (/[a-z]/.test(p)) n += 1;
  if (/[A-Z]/.test(p)) n += 1;
  if (/[0-9]/.test(p)) n += 1;
  if (/[^a-zA-Z0-9]/.test(p)) n += 1;
  return n;
}

function clientValidatePassword(p: string): string | null {
  if (p.length < MIN_PASSWORD_LEN) {
    return `Password must be at least ${MIN_PASSWORD_LEN} characters.`;
  }
  if (p.length > MAX_PASSWORD_LEN) {
    return `Password must be at most ${MAX_PASSWORD_LEN} characters.`;
  }
  if (passwordClassCount(p) < 2) {
    return "Password must mix at least two character classes (e.g. letters + digits, letters + symbols).";
  }
  return null;
}

// fastapi-users surfaces specific reset-password failure modes via the
// `detail` field of the 400 response. Map each to a user-facing message
// instead of the catch-all "link might be expired".
function explainResetError(err: unknown): string {
  if (err instanceof AxiosError) {
    const status = err.response?.status;
    const detail = (err.response?.data as { detail?: unknown } | undefined)?.detail;
    if (status === 400 && typeof detail === "string") {
      if (detail === "RESET_PASSWORD_BAD_TOKEN") {
        return "Reset link is invalid or has already been used. Request a new one.";
      }
      // INVALID_PASSWORD comes back as either a bare string or with a
      // `{code, reason}` object — surface whichever shape we got.
      if (detail.startsWith("INVALID_PASSWORD")) {
        return `Password rejected by the server: ${detail.replace(/^INVALID_PASSWORD:?\s*/, "") || "does not meet complexity rules"}.`;
      }
      return detail;
    }
    if (status === 400 && detail && typeof detail === "object") {
      const obj = detail as { code?: string; reason?: string };
      if (obj.code === "INVALID_PASSWORD") {
        return `Password rejected by the server: ${obj.reason ?? "does not meet complexity rules"}.`;
      }
    }
    if (status === 422) {
      return "The reset request was malformed (the link may have been truncated by your email client).";
    }
  }
  return "Failed to reset password. The link might be expired — request a new one.";
}

// SECURITY (V15.1.5 dangerous functionality): token is a one-shot reset
// credential. It SHOULD NOT be logged, retained in localStorage, or kept in
// the URL after submit. The backend (`email_service.py`) deliberately puts
// the token in the URL fragment so it never reaches HTTP servers, proxies,
// browser history, or Referer headers (V06.4.1 / V14.2.1). We read from
// `location.hash` first; the `location.search` fallback is for any in-flight
// links issued before this dual-read was added.
function readResetTokenFromUrl(): string | null {
  if (typeof window === "undefined") return null;
  // Prefer fragment (current backend shape).
  const rawHash = window.location.hash.startsWith("#")
    ? window.location.hash.slice(1)
    : window.location.hash;
  if (rawHash) {
    const fromHash = new URLSearchParams(rawHash).get("token");
    if (fromHash) return fromHash;
  }
  // Backward-compat: query-string variant.
  const fromQuery = new URLSearchParams(window.location.search).get("token");
  return fromQuery || null;
}

const ResetPasswordPage: React.FC = () => {
  const toast = useToast();
  const navigate = useNavigate();
  const location = useLocation();
  // location is referenced so the hook re-evaluates on URL changes; the
  // actual read uses window.location because react-router does not parse
  // the hash into its own state.
  void location;
  const token = useMemo(readResetTokenFromUrl, []);

  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!token) {
      toast.error("Invalid or missing reset token.");
      return;
    }
    // Strip both the fragment and the query so the token isn't kept in
    // browser history once the page has loaded.
    window.history.replaceState({}, document.title, "/reset-password");
  }, [token, toast]);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) {
      toast.error("No token provided.");
      return;
    }
    if (!password || password !== confirm) {
      toast.error("The two passwords do not match.");
      return;
    }
    const clientError = clientValidatePassword(password);
    if (clientError) {
      toast.error(clientError);
      return;
    }
    setLoading(true);
    try {
      await authService.resetPassword(token, password);
      toast.success("Password secured. You can now log in.");
      navigate("/login");
    } catch (err) {
      toast.error(explainResetError(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <form
      onSubmit={onSubmit}
      className="surface"
      style={{
        padding: 36,
        display: "grid",
        gap: 16,
        boxShadow: "var(--shadow-md)",
        position: "relative",
        overflow: "hidden",
      }}
    >
      <div
        aria-hidden
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          height: 3,
          background:
            "linear-gradient(90deg, var(--primary) 0%, var(--accent) 100%)",
        }}
      />
      <div style={{ textAlign: "center" }}>
        <div
          style={{
            display: "inline-flex",
            alignItems: "center",
            justifyContent: "center",
            width: 48,
            height: 48,
            borderRadius: 12,
            background: "var(--primary-weak)",
            color: "var(--primary)",
            marginBottom: 12,
          }}
        >
          <Icon.Key size={22} />
        </div>
        <div
          style={{
            fontSize: 20,
            fontWeight: 600,
            color: "var(--fg)",
            letterSpacing: "-0.01em",
          }}
        >
          Set a new password
        </div>
      </div>
      <div
        style={{
          textAlign: "center",
          fontSize: 13,
          color: "var(--fg-muted)",
          lineHeight: 1.5,
        }}
      >
        Please enter your new password below.
      </div>
      <div className="input-with-icon">
        <Icon.Lock size={14} />
        <input
          className="sccap-input"
          type="password"
          placeholder="New password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          autoFocus
          autoComplete="new-password"
          maxLength={128}
          style={{ paddingLeft: 32 }}
        />
      </div>
      {password.length > 0 && (() => {
        const issue = clientValidatePassword(password);
        return (
          <div
            style={{
              fontSize: 11.5,
              color: issue ? "var(--critical)" : "var(--success)",
              marginTop: -8,
            }}
          >
            {issue ?? "Looks good."}
          </div>
        );
      })()}
      <div style={{ fontSize: 11.5, color: "var(--fg-subtle)", marginTop: -8 }}>
        Must be at least {MIN_PASSWORD_LEN} characters and mix at least two
        character classes (letters, digits, symbols).
      </div>
      <div className="input-with-icon">
        <Icon.Lock size={14} />
        <input
          className="sccap-input"
          type="password"
          placeholder="Confirm password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          required
          autoComplete="new-password"
          maxLength={128}
          style={{ paddingLeft: 32 }}
        />
      </div>
      <button
        type="submit"
        className="sccap-btn sccap-btn-primary sccap-btn-lg"
        disabled={loading || !token}
        style={{ width: "100%" }}
      >
        {loading ? "Saving…" : "Reset password"}
      </button>
    </form>
  );
};

export default ResetPasswordPage;
