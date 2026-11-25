// secure-code-ui/src/shared/ui/CollapsibleCard.tsx
//
// A card that folds, and remembers that it was folded.
//
// A run page can hold a dozen cards, and the two that matter at any moment (the activity stream
// while it runs, the findings once it is done) are not always adjacent. Folding is how an operator
// stops scrolling past the same wall of text: the state is remembered per card, per browser, so a
// page you tuned yesterday comes back the way you left it.
//
// The toggle is a real button with `aria-expanded`, and the title stays visible when collapsed —
// a folded card that hides its own name is a mystery, not a summary.

import { useEffect, useState, type ReactNode } from "react";
import { Icon } from "./Icon";

const PREFIX = "sccap.collapse.";

const foldListeners = new Set<(folded: boolean) => void>();

/** Fold or unfold every collapsible card currently mounted, and remember it per card. */
export function setAllCollapsed(folded: boolean): void {
  foldListeners.forEach((listener) => listener(folded));
}

function readCollapsed(key: string, defaultCollapsed: boolean): boolean {
  try {
    const stored = localStorage.getItem(PREFIX + key);
    if (stored === "1") return true;
    if (stored === "0") return false;
  } catch {
    /* storage unavailable: fall back to the default */
  }
  return defaultCollapsed;
}

export interface CollapsibleCardProps {
  /** Stable identity for the remembered state. Defaults to the title. */
  storageKey?: string;
  title: ReactNode;
  /** Small line under the title, shown whether open or folded. */
  subtitle?: ReactNode;
  /** Rendered on the right of the header, outside the toggle. */
  actions?: ReactNode;
  children: ReactNode;
  defaultCollapsed?: boolean;
  /** Extra classes on the section (e.g. a page-specific spacing rule). */
  className?: string;
  style?: React.CSSProperties;
}

export function CollapsibleCard({
  storageKey,
  title,
  subtitle,
  actions,
  children,
  defaultCollapsed = false,
  className = "",
  style,
}: CollapsibleCardProps) {
  const key = storageKey ?? (typeof title === "string" ? title : "card");
  const [collapsed, setCollapsed] = useState(() => readCollapsed(key, defaultCollapsed));

  useEffect(() => {
    setCollapsed(readCollapsed(key, defaultCollapsed));
  }, [key, defaultCollapsed]);

  useEffect(() => {
    const listener = (folded: boolean) => {
      setCollapsed(folded);
      try {
        localStorage.setItem(PREFIX + key, folded ? "1" : "0");
      } catch {
        /* the fold still works, it just will not be remembered */
      }
    };
    foldListeners.add(listener);
    return () => {
      foldListeners.delete(listener);
    };
  }, [key]);

  const toggle = () => {
    setCollapsed((current) => {
      const next = !current;
      try {
        localStorage.setItem(PREFIX + key, next ? "1" : "0");
      } catch {
        /* the fold still works, it just will not be remembered */
      }
      return next;
    });
  };

  return (
    <section
      className={`sccap-card collapsible-card${collapsed ? " is-collapsed" : ""} ${className}`.trim()}
      style={style}
      data-collapsed={collapsed}
    >
      <div className="collapsible-head">
        <button
          type="button"
          className="collapsible-toggle"
          aria-expanded={!collapsed}
          onClick={toggle}
          title={collapsed ? "Expand this card" : "Collapse this card"}
        >
          <span className={`collapsible-chevron${collapsed ? " is-collapsed" : ""}`} aria-hidden="true">
            <Icon.ChevronD size={14} />
          </span>
          <span className="collapsible-title">{title}</span>
          {subtitle && <span className="collapsible-subtitle">{subtitle}</span>}
        </button>
        {actions && (
          <div className="collapsible-actions" onClick={(event) => event.stopPropagation()}>
            {actions}
          </div>
        )}
      </div>
      {!collapsed && <div className="collapsible-body">{children}</div>}
    </section>
  );
}

export default CollapsibleCard;
