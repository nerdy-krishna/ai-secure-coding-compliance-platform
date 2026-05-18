// secure-code-ui/src/shared/ui/PageHeader.tsx
//
// Unified page header with breadcrumb trail, title, optional status chip,
// subtitle, and right-side action slot. Replaces ad-hoc back buttons and
// standalone breadcrumb rows across analysis / submission pages.

import React from "react";
import { useNavigate } from "react-router-dom";
import { Icon } from "./Icon";

export interface BreadcrumbCrumb {
  label: string;
  to?: string;
  onClick?: () => void;
}

export interface PageHeaderProps {
  crumbs: BreadcrumbCrumb[];
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  chip?: React.ReactNode;
  actions?: React.ReactNode;
}

export const PageHeader: React.FC<PageHeaderProps> = ({
  crumbs,
  title,
  subtitle,
  chip,
  actions,
}) => {
  const navigate = useNavigate();
  const hasTrail = crumbs.length > 1;

  return (
    <div>
      {hasTrail && (
        <nav
          style={{
            display: "flex",
            alignItems: "center",
            gap: 2,
            marginBottom: 10,
          }}
        >
          {crumbs.map((crumb, i) => {
            const isLast = i === crumbs.length - 1;
            const isFirst = i === 0;

            return (
              <React.Fragment key={i}>
                {isLast ? (
                  <span className="muted" style={{ fontSize: 13 }}>
                    {crumb.label}
                  </span>
                ) : (
                  <button
                    className="sccap-btn sccap-btn-sm sccap-btn-ghost"
                    onClick={() => {
                      if (crumb.onClick) {
                        crumb.onClick();
                      } else if (crumb.to) {
                        navigate(crumb.to);
                      }
                    }}
                    style={{ gap: 4 }}
                  >
                    {isFirst && <Icon.ChevronL size={12} />}
                    {crumb.label}
                  </button>
                )}
                {!isLast && (
                  <span
                    style={{
                      color: "var(--fg-subtle)",
                      fontSize: 13,
                      userSelect: "none",
                    }}
                  >
                    /
                  </span>
                )}
              </React.Fragment>
            );
          })}
        </nav>
      )}
      {chip && <div style={{ marginBottom: 8 }}>{chip}</div>}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-end",
          gap: 20,
        }}
      >
        <div>
          <h1
            style={{
              color: "var(--fg)",
              fontSize: 22,
              lineHeight: 1.3,
              margin: 0,
            }}
          >
            {title}
          </h1>
          {subtitle && (
            <div
              style={{
                color: "var(--fg-muted)",
                marginTop: 4,
                fontSize: 13,
                display: "flex",
                alignItems: "center",
                gap: 8,
                flexWrap: "wrap",
              }}
            >
              {subtitle}
            </div>
          )}
        </div>
        {actions && (
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            {actions}
          </div>
        )}
      </div>
    </div>
  );
};
