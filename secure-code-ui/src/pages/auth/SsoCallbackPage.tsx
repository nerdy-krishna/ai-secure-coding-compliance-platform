// secure-code-ui/src/pages/auth/SsoCallbackPage.tsx
//
// Landing page for SSO redirects from the backend. The backend mints the
// access token + sets the refresh cookie, then redirects here with the
// access token in the URL fragment (#access_token=...). We strip the
// fragment IMMEDIATELY (M9 — first synchronous statement after read) and
// then forward the user to the dashboard.
//
// On error: backend redirects with #error=<code>; we show a friendly
// screen with a Back-to-login button.

import React, { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Icon } from "../../shared/ui/Icon";

interface CallbackHashState {
  accessToken: string | null;
  errorCode: string | null;
}

function readAndStripHash(): CallbackHashState {
  // CRITICAL: read the fragment then immediately strip it via
  // history.replaceState BEFORE any other code runs (M9). The page must
  // load no third-party assets — fragments are not normally sent in
  // Referer, but a third-party script's network request would include
  // document.referrer (which still holds the URL before replaceState).
  if (typeof window === "undefined") {
    return { accessToken: null, errorCode: null };
  }
  const raw = window.location.hash.startsWith("#")
    ? window.location.hash.slice(1)
    : window.location.hash;
  const params = new URLSearchParams(raw);
  const accessToken = params.get("access_token");
  const errorCode = params.get("error");
  // Strip the fragment from the URL.
  if (window.history && window.history.replaceState) {
    const cleanUrl = window.location.pathname + window.location.search;
    window.history.replaceState(null, document.title, cleanUrl);
  }
  return { accessToken, errorCode };
}

const SsoCallbackPage: React.FC = () => {
  const navigate = useNavigate();
  const initial = useMemo(readAndStripHash, []);
  const [errorCode, setErrorCode] = useState<string | null>(initial.errorCode);

  useEffect(() => {
    if (initial.accessToken) {
      try {
        localStorage.setItem("accessToken", initial.accessToken);
      } catch {
        setErrorCode("storage_error");
        return;
      }
      // Force a full reload to /analysis/results so AuthProvider re-mounts
      // with the fresh accessToken from localStorage. Avoids races where
      // useEffect fires before the new token is picked up.
      navigate("/analysis/results", { replace: true });
      // Belt-and-braces: also set window.location to ensure the AuthProvider
      // useEffect sees the new token via storage event/poll.
      window.location.assign("/analysis/results");
    } else if (!initial.errorCode) {
      // No token AND no error — landed here via direct navigation.
      setErrorCode("no_token_in_url");
    }
  }, [initial.accessToken, initial.errorCode, navigate]);

  const message = errorMessageFor(errorCode);

  return (
    <div
      className="surface"
      style={{
        maxWidth: 420,
        margin: "100px auto",
        padding: 36,
        textAlign: "center",
        boxShadow: "var(--shadow-md)",
      }}
    >
      <div
        style={{
          display: "inline-flex",
          alignItems: "center",
          justifyContent: "center",
          width: 56,
          height: 56,
          borderRadius: 14,
          background: errorCode ? "var(--danger-weak)" : "var(--primary-weak)",
          color: errorCode ? "var(--danger)" : "var(--primary)",
          marginBottom: 14,
        }}
      >
        {errorCode ? <Icon.Alert size={28} /> : <Icon.Shield size={28} />}
      </div>
      {errorCode ? (
        <>
          <div
            style={{ fontSize: 20, fontWeight: 600, color: "var(--fg)" }}
          >
            Sign-in didn't complete
          </div>
          <div
            style={{
              color: "var(--fg-muted)",
              fontSize: 13,
              marginTop: 8,
              lineHeight: 1.5,
            }}
          >
            {message}
          </div>
          <Link
            to="/login"
            className="sccap-btn sccap-btn-primary"
            style={{ marginTop: 18 }}
          >
            Back to login
          </Link>
        </>
      ) : (
        <>
          <div
            style={{ fontSize: 20, fontWeight: 600, color: "var(--fg)" }}
          >
            Signing you in…
          </div>
          <div
            style={{
              color: "var(--fg-muted)",
              fontSize: 13,
              marginTop: 8,
            }}
          >
            One moment.
          </div>
        </>
      )}
    </div>
  );
};

function errorMessageFor(code: string | null): string {
  switch (code) {
    case "missing_code_or_state":
      return "The identity provider didn't return a valid response.";
    case "missing_state_cookie":
    case "state_expired":
      return "Your sign-in attempt timed out. Please try again.";
    case "state_tampered":
    case "state_mismatch":
    case "relay_state_mismatch":
      return "The sign-in flow failed integrity checks. Try logging in again.";
    case "provider_not_found":
    case "provider_mismatch":
    case "provider_config_unavailable":
      return "The configured SSO provider is unavailable. Contact your administrator.";
    case "token_validation_failed":
      return "We couldn't verify the response from the identity provider.";
    case "email_unverified_at_idp":
      return "Your email isn't verified at the identity provider. Verify it and try again.";
    case "superuser_link_refused":
      return "Linking SSO to an existing administrator account requires manual setup.";
    case "pending_admin_approval":
      return "Your account was created but awaits administrator approval.";
    case "denied":
      return "Your account is not authorized to use this SSO provider.";
    case "saml_assertion_invalid":
      return "The SAML assertion failed signature or schema checks.";
    case "saml_email_missing":
      return "The SAML response didn't include your email address.";
    case "saml_body_too_large":
    case "saml_body_invalid":
      return "The SAML response was malformed or too large.";
    case "idp_error":
      return "The identity provider reported an error.";
    case "no_token_in_url":
      return "No sign-in token was provided. Please log in again.";
    case "storage_error":
      return "We couldn't save your session. Check your browser's storage settings.";
    default:
      return code
        ? `Sign-in failed (${code}).`
        : "An unexpected error occurred during sign-in.";
  }
}

export default SsoCallbackPage;
