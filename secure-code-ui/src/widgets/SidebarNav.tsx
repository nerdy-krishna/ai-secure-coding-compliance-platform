import { useState } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { Icon } from "../shared/ui/Icon";
import { useAuth } from "../shared/hooks/useAuth";
import { useFeatures } from "../shared/hooks/useFeatures";
import { ADMIN_AREA_PERMISSIONS, hasAnyPermission, hasPermission, Permission } from "../shared/lib/permissions";
import { ADMIN_LINKS } from "./AdminSubNav";

type IconComponent = React.FC<{ size?: number; className?: string }>;
type Item = {
  to: string;
  label: string;
  icon: IconComponent;
  feature?: string;
  permission?: string;
};

const codeScan: Item[] = [
  { to: "/submission/submit", label: "New scan", icon: Icon.Plus },
  { to: "/analysis/results", label: "Projects and results", icon: Icon.Folder },
  { to: "/account/history", label: "Submission history", icon: Icon.History },
];
const pentesting: Item[] = [
  {
    to: "/pentesting",
    label: "Pentesting",
    icon: Icon.Shield,
    feature: "pentesting",
    permission: Permission.pentestRead,
  },
];
const tools: Item[] = [
  { to: "/compliance", label: "Compliance", icon: Icon.Check, feature: "compliance" },
  { to: "/advisor", label: "Security advisor", icon: Icon.Chat, feature: "chat" },
  { to: "/usage", label: "Usage", icon: Icon.Gauge },
];

// Admin links carry only a label, so the icon is chosen by keyword. A miss falls
// back to a neutral dot rather than a letter, which is what the collapsed rail
// used to render.
const ADMIN_ICON_RULES: Array<[RegExp, IconComponent]> = [
  [/authorization|policy/i, Icon.Lock],
  [/platform|features|system/i, Icon.Settings],
  [/users|groups|tenants|scim/i, Icon.Users],
  [/agents|frameworks|prompts/i, Icon.Sparkle],
  [/smtp|mail/i, Icon.Mail],
  [/sso|auth/i, Icon.Key],
  [/integration/i, Icon.Integrate],
  [/findings|audit/i, Icon.Flag],
  [/llm|model/i, Icon.Cpu],
  [/appearance|theme/i, Icon.Sun],
  [/logs|terminal/i, Icon.Terminal],
];

function adminIcon(label: string): IconComponent {
  for (const [pattern, icon] of ADMIN_ICON_RULES) {
    if (pattern.test(label)) return icon;
  }
  return Icon.Dot;
}

// Seven workspaces, in reading order. The eleven that used to be listed here -
// Tests, Operations, Frameworks, Coverage, Cleanup, Callbacks, Workflows,
// Governance, Retests, Deltas - were the pipeline's internal stages given equal
// billing with the results. Findings and Observations stay side by side on
// purpose: one is the interpreted result, the other is the raw thing it was
// interpreted from.

export function SidebarNav() {
  const [collapsed, setCollapsed] = useState(false);
  const { pathname } = useLocation();
  const { user } = useAuth();
  const { isFeatureEnabled, featuresLoading } = useFeatures();
  const visible = (items: Item[]) => items.filter((item) => (!item.feature || (!featuresLoading && isFeatureEnabled(item.feature))) && (!item.permission || hasPermission(user?.permissions, item.permission)));
  const admin = ADMIN_LINKS.filter((item) => (!item.feature || isFeatureEnabled(item.feature)) && (!item.permissions || hasAnyPermission(user?.permissions, item.permissions)));
  const hasAdmin = hasAnyPermission(user?.permissions, ADMIN_AREA_PERMISSIONS) || admin.some((item) => pathname.startsWith(item.to));

  const link = (item: Item) => (
    <NavLink
      key={item.to}
      to={item.to}
      title={item.label}
      aria-label={item.label}
      className="side-nav-link"
    >
      <span className="side-nav-icon" aria-hidden="true">
        <item.icon size={16} />
      </span>
      {!collapsed && <span className="side-nav-label">{item.label}</span>}
    </NavLink>
  );

  const group = (label: string, groupIcon: IconComponent, items: Item[], open = false) => {
    const shown = visible(items);
    if (!shown.length) return null;
    // A capitalized local is required: JSX treats lowercase names as DOM tags.
    const GroupIcon = groupIcon;
    return (
      <details className="side-nav-group" open={open}>
        <summary title={label} aria-label={label}>
          {collapsed ? (
            <span className="side-nav-icon" aria-hidden="true">
              <GroupIcon size={16} />
            </span>
          ) : (
            label
          )}
        </summary>
        <div>{shown.map(link)}</div>
      </details>
    );
  };

  return <aside className={`side-nav${collapsed ? " is-collapsed" : ""}`} aria-label="Application navigation">
    <button className="side-nav-toggle" type="button" onClick={() => setCollapsed((value) => !value)} aria-expanded={!collapsed} aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}>{collapsed ? "›" : "‹"}</button>
    <NavLink className="side-nav-home side-nav-link" to="/account/dashboard" title="Dashboard" aria-label="Dashboard">
      <span className="side-nav-icon" aria-hidden="true">
        <Icon.Home size={16} />
      </span>
      {!collapsed && <span className="side-nav-label">Dashboard</span>}
    </NavLink>
    {group("Code scanning", Icon.Code, codeScan, pathname.startsWith("/analysis") || pathname.startsWith("/submission"))}
    {group("Pentesting", Icon.Shield, pentesting, pathname.startsWith("/pentesting"))}
    {group("Tools", Icon.Terminal, tools, pathname.startsWith("/compliance") || pathname.startsWith("/advisor") || pathname.startsWith("/usage"))}
    {hasAdmin
      ? group(
          "Administration",
          Icon.Settings,
          admin.map((item) => ({ ...item, icon: adminIcon(item.label) })),
          pathname.startsWith("/admin") || pathname.startsWith("/account/settings/llm"),
        )
      : null}
  </aside>;
}
