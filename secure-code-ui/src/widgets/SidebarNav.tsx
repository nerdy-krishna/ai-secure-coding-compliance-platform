import { useState } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { useAuth } from "../shared/hooks/useAuth";
import { useFeatures } from "../shared/hooks/useFeatures";
import { ADMIN_AREA_PERMISSIONS, hasAnyPermission, hasPermission, Permission } from "../shared/lib/permissions";
import { ADMIN_LINKS } from "./AdminSubNav";

type Item = { to: string; label: string; feature?: string; permission?: string };

const codeScan: Item[] = [
  { to: "/submission/submit", label: "New scan" },
  { to: "/analysis/results", label: "Projects and results" },
  { to: "/account/history", label: "Submission history" },
];
const pentesting: Item[] = [
  { to: "/pentesting/engagements", label: "Engagements", feature: "pentesting_capability13", permission: Permission.pentestRead },
  { to: "/pentesting/projects", label: "Pentesting projects", feature: "pentesting_capability13", permission: Permission.pentestRead },
  { to: "/pentesting/credentials", label: "Credentials", feature: "pentesting_capability13", permission: Permission.pentestRead },
  { to: "/pentesting/configuration", label: "Configuration", feature: "pentesting_capability13", permission: Permission.pentestRead },
];
const tools: Item[] = [
  { to: "/compliance", label: "Compliance", feature: "compliance" },
  { to: "/advisor", label: "Security advisor", feature: "chat" },
  { to: "/usage", label: "Usage" },
];
const attemptSections = ["overview", "activity", "observations", "findings", "tests", "operations", "frameworks", "coverage", "cleanup", "callbacks", "evidence", "reports", "governance", "retests", "deltas", "audit"];

export function SidebarNav() {
  const [collapsed, setCollapsed] = useState(false);
  const { pathname } = useLocation();
  const { user } = useAuth();
  const { isFeatureEnabled, featuresLoading } = useFeatures();
  const visible = (items: Item[]) => items.filter((item) => (!item.feature || (!featuresLoading && isFeatureEnabled(item.feature))) && (!item.permission || hasPermission(user?.permissions, item.permission)));
  const pathParts = pathname.split("/");
  const attemptBase = pathParts.length >= 6
    && pathParts[1] === "pentesting"
    && pathParts[2] === "engagements"
    && pathParts[4] === "attempts"
    && pathParts[3]
    && pathParts[5]
    ? `/pentesting/engagements/${pathParts[3]}/attempts/${pathParts[5]}`
    : null;
  const canAudit = hasPermission(user?.permissions, "audit.read");
  const admin = ADMIN_LINKS.filter((item) => (!item.feature || isFeatureEnabled(item.feature)) && (!item.permissions || hasAnyPermission(user?.permissions, item.permissions)));
  const hasAdmin = hasAnyPermission(user?.permissions, ADMIN_AREA_PERMISSIONS) || admin.some((item) => pathname.startsWith(item.to));
  const group = (label: string, items: Item[], open = false) => <details className="side-nav-group" open={open}><summary>{collapsed ? label.slice(0, 1) : label}</summary><div>{visible(items).map((item) => <NavLink key={item.to} to={item.to} title={collapsed ? item.label : undefined}>{collapsed ? item.label.slice(0, 1) : item.label}</NavLink>)}</div></details>;
  return <aside className={`side-nav${collapsed ? " is-collapsed" : ""}`} aria-label="Application navigation">
    <button className="side-nav-toggle" type="button" onClick={() => setCollapsed((value) => !value)} aria-expanded={!collapsed} aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}>{collapsed ? "›" : "‹"}</button>
    <NavLink className="side-nav-home" to="/account/dashboard" title={collapsed ? "Dashboard" : undefined}>{collapsed ? "D" : "Dashboard"}</NavLink>
    {group("Code scanning", codeScan, pathname.startsWith("/analysis") || pathname.startsWith("/submission"))}
    {group("Pentesting", pentesting, pathname.startsWith("/pentesting"))}
    {attemptBase ? group("Current attempt", attemptSections.filter((section) => section !== "audit" || canAudit).map((section) => ({ to: `${attemptBase}/${section}`, label: section[0]!.toUpperCase() + section.slice(1) })), true) : null}
    {group("Tools", tools, pathname.startsWith("/compliance") || pathname.startsWith("/advisor") || pathname.startsWith("/usage"))}
    {hasAdmin ? <details className="side-nav-group" open={pathname.startsWith("/admin") || pathname.startsWith("/account/settings/llm")}><summary>{collapsed ? "A" : "Administration"}</summary><div>{admin.map((item) => <NavLink key={item.to} to={item.to} title={collapsed ? item.label : undefined}>{collapsed ? item.label.slice(0, 1) : item.label}</NavLink>)}</div></details> : null}
  </aside>;
}
