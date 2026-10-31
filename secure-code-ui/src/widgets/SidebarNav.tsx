import { useEffect, useRef, useState } from "react";
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
  /** Match the path exactly, so a parent route does not light up too. */
  exact?: boolean;
};

const codeScan: Item[] = [
  { to: "/submission/submit", label: "New scan", icon: Icon.Plus },
  { to: "/analysis/results", label: "Projects and scans", icon: Icon.Folder },
  { to: "/account/history", label: "Submission history", icon: Icon.History },
];
// Same shape as the code-scanning group: start one, see the estate, see everything.
const pentesting: Item[] = [
  {
    to: "/pentesting/new",
    label: "New pentest",
    icon: Icon.Plus,
    feature: "pentesting",
    permission: Permission.pentestRead,
  },
  {
    to: "/pentesting",
    label: "Projects and scans",
    icon: Icon.Folder,
    feature: "pentesting",
    permission: Permission.pentestRead,
    // Without `end` this entry also matches /pentesting/history and /pentesting/new,
    // so two rows lit up at once.
    exact: true,
  },
  {
    to: "/pentesting/history",
    label: "Submission history",
    icon: Icon.History,
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

/**
 * A navigation group that remembers whether the user left it open.
 *
 * Navigating into a group opens it, but moving to another section only opens that
 * section — it never closes the one you were in. Only a click on the summary
 * collapses it, which is what "stay expanded unless the user collapses it" means.
 */
const NavGroup: React.FC<{
  label: string;
  icon: IconComponent;
  active: boolean;
  collapsed: boolean;
  children: React.ReactNode;
}> = ({ label, icon: GroupIcon, active, collapsed, children }) => {
  // Every group starts expanded and remembers the user's choice across reloads.
  const storageKey = `sccap.nav.group.${label}`;
  const [open, setOpen] = useState<boolean>(() => {
    if (typeof window === "undefined") return true;
    const stored = window.localStorage.getItem(storageKey);
    return stored === null ? true : stored === "1";
  });
  const detailsRef = useRef<HTMLDetailsElement>(null);

  useEffect(() => {
    if (active) setOpen(true);
  }, [active]);

  useEffect(() => {
    try {
      window.localStorage.setItem(storageKey, open ? "1" : "0");
    } catch {
      /* private mode — the in-memory state is enough */
    }
  }, [open, storageKey]);

  useEffect(() => {
    const node = detailsRef.current;
    if (node && node.open !== open) node.open = open;
  }, [open]);

  return (
    <details
      ref={detailsRef}
      className="side-nav-group"
      open={open}
      onToggle={(event) => {
        const next = (event.currentTarget as HTMLDetailsElement).open;
        setOpen(next);
      }}
    >
      <summary title={label} aria-label={label}>
        {collapsed ? (
          <span className="side-nav-icon" aria-hidden="true">
            <GroupIcon size={16} />
          </span>
        ) : (
          label
        )}
      </summary>
      <div>{children}</div>
    </details>
  );
};

export function SidebarNav() {
  const [collapsed, setCollapsed] = useState(false);
  const { pathname } = useLocation();
  const { user } = useAuth();
  const { isFeatureEnabled, featuresLoading } = useFeatures();
  const visible = (items: Item[]) => items.filter((item) => (!item.feature || (!featuresLoading && isFeatureEnabled(item.feature))) && (!item.permission || hasPermission(user?.permissions, item.permission)));
  const admin = ADMIN_LINKS.filter((item) => (!item.feature || isFeatureEnabled(item.feature)) && (!item.permissions || hasAnyPermission(user?.permissions, item.permissions)));
  // Administration holds the platform settings *and* the workspace pages (compliance,
  // advisor, usage) that used to sit in their own "Tools" group.
  const adminVisible = visible(tools).length > 0 || admin.length > 0;
  const adminItems: Item[] = [
    ...visible(tools),
    ...admin.map((item) => ({ ...item, icon: adminIcon(item.label) })),
  ];
  const adminOpen =
    hasAnyPermission(user?.permissions, ADMIN_AREA_PERMISSIONS) ||
    pathname.startsWith("/admin") ||
    pathname.startsWith("/account/settings/llm") ||
    pathname.startsWith("/compliance") ||
    pathname.startsWith("/advisor") ||
    pathname.startsWith("/usage");

  const link = (item: Item) => (
    <NavLink
      key={item.to}
      to={item.to}
      end={item.exact}
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

  const group = (label: string, groupIcon: IconComponent, items: Item[], active = false) => {
    const shown = visible(items);
    if (!shown.length) return null;
    return <NavGroup key={label} label={label} icon={groupIcon} active={active} collapsed={collapsed}>{shown.map(link)}</NavGroup>;
  };

  return <aside className={`side-nav${collapsed ? " is-collapsed" : ""}`} aria-label="Application navigation">
    <button
      className="side-nav-toggle"
      type="button"
      onClick={() => setCollapsed((value) => !value)}
      aria-expanded={!collapsed}
      aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
      title={collapsed ? "Expand navigation" : "Collapse navigation"}
    >
      {/* A panel glyph describes what the control does; it flips with the rail. */}
      <Icon.PanelLeft size={16} />
    </button>
    <NavLink className="side-nav-home side-nav-link" to="/account/dashboard" title="Dashboard" aria-label="Dashboard">
      <span className="side-nav-icon" aria-hidden="true">
        <Icon.Home size={16} />
      </span>
      {!collapsed && <span className="side-nav-label">Dashboard</span>}
    </NavLink>
    {group(
      "Code scanning",
      Icon.Code,
      codeScan,
      pathname.startsWith("/analysis") ||
        pathname.startsWith("/submission") ||
        pathname.startsWith("/account/history"),
    )}
    {group("Pentesting", Icon.Shield, pentesting, pathname.startsWith("/pentesting"))}
    {adminVisible ? group("Administration", Icon.Settings, adminItems, adminOpen) : null}
  </aside>;
}
