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
import { TopNav } from "./TopNav/TopNav";
import { ConnectivityStatus } from "../shared/ui/ConnectivityStatus";
import { SidebarNav } from "./SidebarNav";

const DashboardLayout: React.FC<{ children?: React.ReactNode }> = ({
  children,
}) => {
  return (
    <div
      style={{
        minHeight: "100vh",
        background: "var(--bg)",
        color: "var(--fg)",
        fontFamily: "var(--font-sans)",
      }}
    >
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>
      <TopNav />
      <ConnectivityStatus />
      <div className="dashboard-shell">
        <SidebarNav />
        <main id="main-content" className="dashboard-main" tabIndex={-1}>{children}</main>
      </div>
    </div>
  );
};

export default DashboardLayout;
