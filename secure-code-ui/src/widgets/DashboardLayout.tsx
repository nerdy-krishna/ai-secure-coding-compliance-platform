// secure-code-ui/src/widgets/DashboardLayout.tsx
//
// Authenticated app shell: top-nav + centered content. The `children`
// prop keeps the route guards in App.tsx working unchanged — they wrap
// each authenticated route in this layout.
//
// The body background + color are driven by the SCCAP design tokens
// (--bg / --fg) so light/dark/variant toggles apply globally. Theme,
// variation, and accent are edited from the Appearance settings page
// (/account/settings/appearance).

import React from "react";
import { useLocation } from "react-router-dom";
import AdminSubNav from "./AdminSubNav";
import { TopNav } from "./TopNav/TopNav";

const DashboardLayout: React.FC<{ children?: React.ReactNode }> = ({
  children,
}) => {
  const { pathname } = useLocation();
  const isAdminArea =
    pathname.startsWith("/admin") ||
    pathname.startsWith("/account/settings/llm");
  return (
    <div
      style={{
        minHeight: "100vh",
        background: "var(--bg)",
        color: "var(--fg)",
        fontFamily: "var(--font-sans)",
      }}
    >
      <TopNav />
      <main
        style={{
          padding: "24px 28px 80px",
          maxWidth: 1440,
          margin: "0 auto",
        }}
      >
        {isAdminArea && <AdminSubNav />}
        {children}
      </main>
    </div>
  );
};

export default DashboardLayout;
