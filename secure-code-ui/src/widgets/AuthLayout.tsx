// secure-code-ui/src/widgets/AuthLayout.tsx
//
// Centered auth container used by the login / forgot-password /
// reset-password routes. Ports the design bundle's branded feel onto
// the auth shell: a subtle radial gradient over --bg, a floating
// theme-toggle button in the top-right so pre-auth users can switch
// light/dark, and a small brand footer.

import React from "react";
import { useTheme } from "../app/providers/ThemeProvider";
import { Icon } from "../shared/ui/Icon";

interface AuthLayoutProps {
  children: React.ReactNode;
}

const AuthLayout: React.FC<AuthLayoutProps> = ({ children }) => {
  const { theme, toggleTheme } = useTheme();
  return (
    <div
      style={{
        minHeight: "100dvh",
        boxSizing: "border-box",
        background: "var(--bg)",
        position: "relative",
        overflow: "hidden",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 20,
      }}
    >
      {/* Subtle branded glow — picks up --primary-weak so it themes with
          the active variant and dark/light mode. */}
      <div
        aria-hidden
        style={{
          position: "absolute",
          top: "-20%",
          left: "50%",
          transform: "translateX(-50%)",
          width: 720,
          height: 720,
          background:
            "radial-gradient(circle, var(--primary-weak) 0%, transparent 60%)",
          opacity: 0.65,
          pointerEvents: "none",
          filter: "blur(40px)",
        }}
      />
      <div
        aria-hidden
        style={{
          position: "absolute",
          bottom: "-25%",
          right: "-10%",
          width: 520,
          height: 520,
          background:
            "radial-gradient(circle, var(--accent-weak) 0%, transparent 60%)",
          opacity: 0.5,
          pointerEvents: "none",
          filter: "blur(40px)",
        }}
      />

      {/* Theme toggle — floating, top-right. */}
      <button
        type="button"
        onClick={toggleTheme}
        aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
        className="sccap-btn sccap-btn-icon sccap-btn-ghost"
        style={{
          position: "absolute",
          top: 16,
          right: 16,
          background: "var(--bg-elev)",
          border: "1px solid var(--border)",
          zIndex: 2,
        }}
      >
        {theme === "dark" ? <Icon.Sun size={16} /> : <Icon.Moon size={16} />}
      </button>

      <div
        style={{
          width: "100%",
          maxWidth: 420,
          position: "relative",
          zIndex: 1,
        }}
      >
        {children}
        <div
          style={{
            marginTop: 20,
            textAlign: "center",
            color: "var(--fg-subtle)",
            fontSize: 11.5,
          }}
        >
          SCCAP · Secure Coding & Compliance Automation
        </div>
      </div>
    </div>
  );
};

export default AuthLayout;
