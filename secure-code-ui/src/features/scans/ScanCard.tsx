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
import { displayStatus, statusKind } from "../../shared/lib/scanStatus";
import { formatDuration, useElapsed } from "../../shared/lib/useElapsed";
import type { ScanHistoryItem } from "../../shared/types/api";
import { Icon } from "../../shared/ui/Icon";
import { StageIcon } from "../../shared/ui/StageIcon";

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

  // Live timer: ticks while the scan is active, freezes once it ends.
  // For terminal scans with event-based active time, use that instead
  // of wall-clock (which includes dormant periods from stop/resume).
  const activeSeconds = scan.active_processing_seconds;
  const wallElapsed = useElapsed(
    scan.created_at,
    progress.isTerminal ? (scan.completed_at ?? scan.created_at) : null,
  );
  const elapsed =
    progress.isTerminal && typeof activeSeconds === "number"
      ? formatDuration(activeSeconds * 1000)
      : wallElapsed;

  // Status-coloured left accent so stacked scan items are easy to tell
  // apart at a glance.
  const kind = statusKind(scan.status);
  const accent = !progress.isTerminal
    ? "var(--primary)"
    : kind === "completed"
      ? "var(--success)"
      : kind === "failed"
        ? "var(--critical)"
        : kind === "blocked"
          ? "var(--high)"
          : "var(--border-strong)";

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
        borderLeft: `3px solid ${accent}`,
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
            {scan.id.slice(0, 8)}
          </span>
        </div>

        {/* Active scan: live stage + compact progress bar. */}
        {!progress.isTerminal && (
          <div style={{ marginTop: 8 }}>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 7,
                marginBottom: 4,
              }}
            >
              <span
                className="pulse-dot"
                style={{
                  width: 7,
                  height: 7,
                  borderRadius: "50%",
                  background: "var(--primary)",
                  flexShrink: 0,
                }}
              />
              <span
                style={{
                  fontSize: 12,
                  color: "var(--primary)",
                  fontWeight: 600,
                }}
              >
                {progress.badge}
              </span>
              {elapsed && (
                <span
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 3,
                    fontSize: 11.5,
                    color: "var(--fg-muted)",
                    fontVariantNumeric: "tabular-nums",
                  }}
                >
                  <Icon.Clock size={11} /> {elapsed}
                </span>
              )}
            </div>
            {/* Stage timeline (#86): an icon per pipeline stage with
                its name beneath, coloured by derived state. */}
            <div style={{ display: "flex", marginTop: 6 }}>
              {progress.stages.map((s, i) => {
                const last = i === progress.stages.length - 1;
                const segDone =
                  i > 0 && progress.stages[i - 1].state === "done";
                const circleBg =
                  s.state === "done"
                    ? "var(--success)"
                    : s.state === "running"
                      ? "var(--primary)"
                      : s.state === "paused"
                        ? "var(--medium)"
                        : "var(--bg-elev)";
                const labelColor =
                  s.state === "running"
                    ? "var(--primary)"
                    : s.state === "paused"
                      ? "var(--medium)"
                      : s.state === "done"
                        ? "var(--fg-muted)"
                        : "var(--fg-subtle)";
                return (
                  <div
                    key={s.key}
                    title={`${s.label} — ${s.state}`}
                    style={{
                      flex: 1,
                      minWidth: 0,
                      display: "flex",
                      flexDirection: "column",
                      alignItems: "center",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        width: "100%",
                      }}
                    >
                      <span
                        style={{
                          flex: 1,
                          height: 2,
                          background:
                            i === 0
                              ? "transparent"
                              : segDone
                                ? "var(--success)"
                                : "var(--border)",
                        }}
                      />
                      <span
                        className={
                          s.state === "running" ? "pulse-ring" : undefined
                        }
                        style={{
                          width: 26,
                          height: 26,
                          borderRadius: "50%",
                          flexShrink: 0,
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          background: circleBg,
                          color:
                            s.state === "pending"
                              ? "var(--fg-subtle)"
                              : "#fff",
                          border:
                            s.state === "pending"
                              ? "1.5px solid var(--border)"
                              : "1.5px solid transparent",
                        }}
                      >
                        <StageIcon name={s.icon} size={13} />
                      </span>
                      <span
                        style={{
                          flex: 1,
                          height: 2,
                          background: last
                            ? "transparent"
                            : s.state === "done"
                              ? "var(--success)"
                              : "var(--border)",
                        }}
                      />
                    </div>
                    <span
                      style={{
                        marginTop: 5,
                        fontSize: 9.5,
                        lineHeight: 1.25,
                        textAlign: "center",
                        color: labelColor,
                        fontWeight: s.state === "running" ? 600 : 400,
                      }}
                    >
                      {s.label}
                    </span>
                  </div>
                );
              })}
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
            {scan.completed_at && elapsed && (
              <span
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 3,
                  fontSize: 12,
                  color: "var(--fg-muted)",
                }}
                title="Scan duration"
              >
                <Icon.Clock size={11} /> {elapsed}
              </span>
            )}
          </div>
        )}
      </div>

      <div
        style={{ display: "flex", alignItems: "center", gap: 10 }}
        onClick={(e) => e.stopPropagation()}
      >
        {progress.isTerminal &&
          (() => {
            // Green fill/text for a successful scan, red for a failure,
            // amber for a safety block; stops/expiry stay neutral.
            const kind = statusKind(scan.status);
            const chipClass =
              kind === "completed"
                ? "chip chip-success"
                : kind === "failed"
                  ? "chip chip-critical"
                  : kind === "blocked"
                    ? "chip chip-warn"
                    : "chip";
            return (
              <span className={chipClass}>{displayStatus(scan.status)}</span>
            );
          })()}
        {controls}
        <span onClick={onOpen} style={{ cursor: "pointer", display: "flex" }}>
          <Icon.ChevronR size={14} />
        </span>
      </div>
    </div>
  );
};
