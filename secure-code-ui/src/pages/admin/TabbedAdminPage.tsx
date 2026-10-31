import React, { useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { PageHeader } from "../../shared/ui/PageHeader";

export interface AdminTab {
  key: string;
  label: string;
  icon: React.ReactNode;
  description: string;
  requires?: string;
  adminOnly?: boolean;
  render: () => React.ReactNode;
}

/**
 * The shell shared by the grouped administration pages.
 *
 * Each group is one workflow shown as ordered tabs (the tab lives in `?tab=`), with
 * a step card above the panel that says what the tab is for and what it depends on.
 * The individual screens keep their own components and buttons; their `embedded`
 * prop only suppresses a duplicate heading.
 */
export const TabbedAdminPage: React.FC<{
  title: string;
  subtitle: string;
  crumbs: { label: string; to?: string }[];
  tabs: AdminTab[];
  isAdmin: boolean;
}> = ({ title, subtitle, crumbs, tabs, isAdmin }) => {
  const [params, setParams] = useSearchParams();
  const available = useMemo(
    () => tabs.filter((tab) => !tab.adminOnly || isAdmin),
    [tabs, isAdmin],
  );
  const requested = params.get("tab");
  const active = available.find((tab) => tab.key === requested) ?? available[0];

  const select = (key: string) => {
    const next = new URLSearchParams(params);
    next.set("tab", key);
    setParams(next, { replace: true });
  };

  return (
    <div className="c13-page analysis-config fade-in">
      <PageHeader
        crumbs={[{ label: "Dashboard", to: "/account/dashboard" }, { label: "Administration", to: "/admin/system" }, ...crumbs]}
        title={title}
        subtitle={subtitle}
      />

      <nav className="analysis-tabs" aria-label={`${title} sections`}>
        {available.map((tab, index) => (
          <button
            key={tab.key}
            type="button"
            className={`analysis-tab${active?.key === tab.key ? " is-active" : ""}`}
            aria-current={active?.key === tab.key ? "page" : undefined}
            onClick={() => select(tab.key)}
          >
            <span className="analysis-tab-step">{index + 1}</span>
            {tab.icon}
            <span className="analysis-tab-label">{tab.label}</span>
          </button>
        ))}
      </nav>

      {active && (
        <section className="analysis-step">
          <div className="analysis-step-head">
            <span className="analysis-step-number">
              Step {available.findIndex((tab) => tab.key === active.key) + 1}
            </span>
            <strong>{active.label}</strong>
            {active.requires && (
              <span className="analysis-step-requires">Requires {active.requires}</span>
            )}
          </div>
          <p className="analysis-step-body">{active.description}</p>
        </section>
      )}

      <div className="analysis-tab-panel">{active?.render()}</div>
    </div>
  );
};
