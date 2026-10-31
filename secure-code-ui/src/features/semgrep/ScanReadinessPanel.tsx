// src/features/semgrep/ScanReadinessPanel.tsx
//
// Compact sticky card shown on the right side of the scan submission page.
// Shows framework and Semgrep rule readiness at a glance.

import React from "react";
import { useQuery } from "@tanstack/react-query";
import { AxiosError } from "axios";
import { frameworkService } from "../../shared/api/frameworkService";
import { ruleSourcesService } from "../../shared/api/ruleSourcesService";
import type { FrameworkRead, RuleSourceRead } from "../../shared/types/api";
import { Icon } from "../../shared/ui/Icon";

const ScanReadinessPanel: React.FC = () => {
  const { data: frameworks, isLoading: loadingFw } = useQuery<FrameworkRead[]>({
    queryKey: ["frameworks"],
    queryFn: frameworkService.getFrameworks,
  });

  // Gracefully ignore 403 for non-superusers
  const {
    data: sources,
    isLoading: loadingSources,
    error: sourcesError,
  } = useQuery<RuleSourceRead[], Error>({
    queryKey: ["rule-sources"],
    queryFn: ruleSourcesService.listSources,
    retry: (failureCount, err) => {
      if (err instanceof AxiosError && err.response?.status === 403) return false;
      return failureCount < 2;
    },
  });

  const isForbidden =
    sourcesError instanceof AxiosError && sourcesError.response?.status === 403;

  const enabledSources = (sources ?? []).filter((s) => s.enabled);
  const totalRules = enabledSources.reduce((sum, s) => sum + s.rule_count, 0);
  const hasRunning = enabledSources.some((s) => s.last_sync_status === "running");

  return (
    <div
      className="sccap-card"
      style={{
        position: "sticky",
        top: 24,
        minWidth: 260,
        maxWidth: 320,
        display: "grid",
        gap: 16,
        padding: 16,
      }}
    >
      <div style={{ fontWeight: 600, fontSize: 13, color: "var(--fg)" }}>
        Scan readiness
      </div>

      {/* Frameworks section */}
      <div>
        <div
          style={{
            fontSize: 11,
            color: "var(--fg-subtle)",
            textTransform: "uppercase",
            letterSpacing: ".05em",
            marginBottom: 8,
          }}
        >
          Frameworks
        </div>
        {loadingFw ? (
          <div style={{ fontSize: 12, color: "var(--fg-muted)" }}>Loading…</div>
        ) : !frameworks?.length ? (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              fontSize: 12.5,
              color: "var(--warning)",
            }}
          >
            <Icon.Alert size={12} /> No frameworks configured
          </div>
        ) : (
          <div>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 6,
                fontSize: 12.5,
                color: "var(--success)",
                marginBottom: 8,
              }}
            >
              <Icon.Check size={12} />
              {frameworks.length} framework{frameworks.length === 1 ? "" : "s"}
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
              {frameworks.slice(0, 5).map((f) => (
                <span key={f.id} className="chip" style={{ fontSize: 10.5 }}>
                  {f.name}
                </span>
              ))}
              {frameworks.length > 5 && (
                <span className="chip" style={{ fontSize: 10.5, color: "var(--fg-subtle)" }}>
                  +{frameworks.length - 5} more
                </span>
              )}
            </div>
          </div>
        )}
        <a
          href="/admin/frameworks"
          style={{
            display: "block",
            marginTop: 8,
            fontSize: 11.5,
            color: "var(--primary)",
            textDecoration: "none",
          }}
        >
          Manage frameworks →
        </a>
      </div>

      <div style={{ borderTop: "1px solid var(--border)" }} />

      {/* Semgrep Rules section */}
      <div>
        <div
          style={{
            fontSize: 11,
            color: "var(--fg-subtle)",
            textTransform: "uppercase",
            letterSpacing: ".05em",
            marginBottom: 8,
          }}
        >
          Semgrep rules
        </div>
        {isForbidden ? (
          <div style={{ fontSize: 12.5, color: "var(--fg-muted)", lineHeight: 1.55 }}>
            <Icon.Lock size={12} style={{ verticalAlign: "middle", marginRight: 4 }} />
            Contact your admin to enable Semgrep rules.
          </div>
        ) : loadingSources ? (
          <div style={{ fontSize: 12, color: "var(--fg-muted)" }}>Loading…</div>
        ) : hasRunning ? (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              fontSize: 12.5,
              color: "var(--warning)",
            }}
          >
            <Icon.Refresh
              size={12}
              style={{ animation: "spin 1s linear infinite" }}
            />
            Syncing rules…
          </div>
        ) : totalRules > 0 ? (
          <div>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 6,
                fontSize: 12.5,
                color: "var(--success)",
                marginBottom: 8,
              }}
            >
              <Icon.Check size={12} />
              {totalRules.toLocaleString()} rules ready
            </div>
            <div style={{ display: "grid", gap: 4 }}>
              {enabledSources.slice(0, 4).map((s) => (
                <div
                  key={s.id}
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    fontSize: 11.5,
                    color: "var(--fg-muted)",
                  }}
                >
                  <span
                    style={{
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      maxWidth: 160,
                    }}
                  >
                    {s.display_name}
                  </span>
                  <span style={{ color: "var(--fg-subtle)" }}>
                    {s.rule_count.toLocaleString()}
                  </span>
                </div>
              ))}
              {enabledSources.length > 4 && (
                <div style={{ fontSize: 11, color: "var(--fg-subtle)" }}>
                  +{enabledSources.length - 4} more sources
                </div>
              )}
            </div>
          </div>
        ) : (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              fontSize: 12.5,
              color: "var(--warning)",
            }}
          >
            <Icon.Alert size={12} /> No rules — enable a source
          </div>
        )}
        {!isForbidden && (
          <a
            href="/admin/semgrep"
            style={{
              display: "block",
              marginTop: 8,
              fontSize: 11.5,
              color: "var(--primary)",
              textDecoration: "none",
            }}
          >
            Manage Semgrep rules →
          </a>
        )}
      </div>
    </div>
  );
};

export default ScanReadinessPanel;
