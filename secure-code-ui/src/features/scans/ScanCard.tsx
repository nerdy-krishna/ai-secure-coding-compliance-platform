// Shared scan-overview card (#86 / PRD #83).
//
// One component renders a scan row everywhere it appears — the Scans
// list page, the project detail scan list, and the dashboard
// recent-scans widget. For an active scan it shows the live
// status/stage + a compact progress bar; for a terminal scan it shows
// the finding-metrics overview (severity breakdown, risk score, total
// findings). The status/stage is derived from the scan-event stream
// via the same `deriveScanProgress` deriver the scan-status page uses.

import React from "react";

import { deriveScanProgress, type ProgressEvent } from "../../shared/lib/scanProgress";
import { displayStatus } from "../../shared/lib/scanStatus";
import type { ScanHistoryItem } from "../../shared/types/api";
import { Icon } from "../../shared/ui/Icon";

const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"] as const;
const SEV_COLOR: Record<string, string> = {
  CRITICAL: "var(--critical)",
  HIGH: "var(--high)",
  MEDIUM: "var(--medium)",
  LOW: "var(--low)",
  INFORMATIONAL: "var(--fg-subtle)",
};
const SEV_SHORT: Record<string, string> = {
  CRITICAL: "C",
  HIGH: "H",
  MEDIUM: "M",
  LOW: "L",
  INFORMATIONAL: "I",
};

interface ScanCardProps {
  scan: ScanHistoryItem;
  /** Open the scan (running scan → status page, terminal → results). */
  onOpen: () => void;
  /** Show the project name (Scans list / dashboard) or hide it (project page). */
  showProject?: boolean;
  /** Inline action buttons (Stop / Cancel / Delete) — #87 fills this. */
  controls?: React.ReactNode;
}

export const ScanCard: React.FC<ScanCardProps> = ({
  scan,
  onOpen,
  showProject = true,
  controls,
}) => {
  const progress = deriveScanProgress(
    (scan.events ?? []) as ProgressEvent[],
    scan.status,
    false,
  );
  const sev = scan.severity_counts ?? null;
  const hasMetrics =
    progress.isTerminal &&
    (typeof scan.total_findings === "number" || sev !== null);

  return (
    <div
      onClick={onOpen}
      style={{
        display: "grid",
        gridTemplateColumns: "1fr auto",
        alignItems: "center",
        gap: 14,
        padding: "14px 18px",
        cursor: "pointer",
        transition: "background var(--t)",
      }}
      onMouseEnter={(e) =>
        (e.currentTarget.style.background = "var(--bg-soft)")
      }
      onMouseLeave={(e) =>
        (e.currentTarget.style.background = "transparent")
      }
    >
      <div style={{ minWidth: 0 }}>
        {showProject && (
          <div
            style={{ fontWeight: 500, color: "var(--fg)", marginBottom: 2 }}
          >
            {scan.project_name}
          </div>
        )}
        <div style={{ fontSize: 11.5, color: "var(--fg-subtle)" }}>
          {scan.scan_type.toUpperCase()} ·{" "}
          <span style={{ fontFamily: "var(--font-mono)" }}>
            {scan.id.slice(0, 12)}
          </span>
        </div>

        {/* Active scan: live stage + compact progress bar. */}
        {!progress.isTerminal && (
          <div style={{ marginTop: 8 }}>
            <div
              style={{
                fontSize: 12,
                color: "var(--primary)",
                fontWeight: 500,
                marginBottom: 4,
              }}
            >
              {progress.badge}
            </div>
            <div
              style={{
                height: 4,
                borderRadius: 99,
                background: "var(--bg-soft)",
                overflow: "hidden",
              }}
            >
              <div
                style={{
                  width: `${progress.progressPct}%`,
                  height: "100%",
                  background: progress.isError
                    ? "var(--critical)"
                    : "var(--primary)",
                  transition: "width .3s var(--ease)",
                }}
              />
            </div>
          </div>
        )}

        {/* Terminal scan: finding-metrics overview. */}
        {hasMetrics && (
          <div
            style={{
              marginTop: 8,
              display: "flex",
              alignItems: "center",
              gap: 10,
              flexWrap: "wrap",
            }}
          >
            {typeof scan.risk_score === "number" && (
              <span
                style={{ fontSize: 12, color: "var(--fg-muted)" }}
                title="Risk score (0–10)"
              >
                Risk <strong style={{ color: "var(--fg)" }}>{scan.risk_score}</strong>
                /10
              </span>
            )}
            <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
              {scan.total_findings ?? 0} finding
              {(scan.total_findings ?? 0) === 1 ? "" : "s"}
            </span>
            {sev && (
              <span style={{ display: "inline-flex", gap: 5 }}>
                {SEV_ORDER.filter((k) => (sev[k] ?? 0) > 0).map((k) => (
                  <span
                    key={k}
                    title={`${k.toLowerCase()}: ${sev[k]}`}
                    style={{
                      fontSize: 10.5,
                      fontWeight: 600,
                      padding: "1px 6px",
                      borderRadius: 4,
                      color: SEV_COLOR[k],
                      border: `1px solid ${SEV_COLOR[k]}`,
                    }}
                  >
                    {SEV_SHORT[k]} {sev[k]}
                  </span>
                ))}
              </span>
            )}
          </div>
        )}
      </div>

      <div
        style={{ display: "flex", alignItems: "center", gap: 10 }}
        onClick={(e) => e.stopPropagation()}
      >
        {progress.isTerminal && (
          <span
            className="chip"
            style={{
              background: "transparent",
              borderColor: progress.isError
                ? "var(--critical)"
                : "var(--border)",
              color: progress.isError ? "var(--critical)" : "var(--fg-muted)",
            }}
          >
            {displayStatus(scan.status)}
          </span>
        )}
        {controls}
        <span onClick={onOpen} style={{ cursor: "pointer", display: "flex" }}>
          <Icon.ChevronR size={14} />
        </span>
      </div>
    </div>
  );
};
