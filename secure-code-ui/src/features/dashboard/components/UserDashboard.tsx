// secure-code-ui/src/features/dashboard/components/UserDashboard.tsx
//
// Dashboard for regular users. Renamed from DevDashboard in H.3 and
// wired to the real `/dashboard/stats` endpoint so the risk ring,
// severity bar, and 14-day sparkline show live data instead of
// placeholders.

import { useQuery } from "@tanstack/react-query";
import React, { useMemo } from "react";
import { Link, useNavigate } from "react-router-dom";
import { dashboardService } from "../../../shared/api/dashboardService";
import type { DashboardStats } from "../../../shared/api/dashboardService";
import { scanService } from "../../../shared/api/scanService";
import type { ScanHistoryItem } from "../../../shared/types/api";
import { useAuth } from "../../../shared/hooks/useAuth";
import { scanRouteFor } from "../../../shared/lib/scanRoute";
import { displayStatus, statusKind } from "../../../shared/lib/scanStatus";
import { Icon } from "../../../shared/ui/Icon";
import {
  MetricCard,
  RiskRing,
  SectionHead,
  SevBar,
  Spark,
} from "../../../shared/ui/DashboardPrimitives";

const IN_PROGRESS_STATUSES = new Set([
  "QUEUED",
  "QUEUED_FOR_SCAN",
  "ANALYZING_CONTEXT",
  "RUNNING_AGENTS",
  "GENERATING_REPORTS",
  "PENDING_COST_APPROVAL",
  "PENDING_PRESCAN_APPROVAL",
]);

function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  const diffMs = Date.now() - then;
  if (diffMs < 60_000) return "just now";
  const mins = Math.floor(diffMs / 60_000);
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days === 1) return "yesterday";
  if (days < 30) return `${days}d ago`;
  return new Date(iso).toLocaleDateString();
}

function statusChip(status: string): React.ReactNode {
  // Mirror ProjectDetailPage / ScanRunningPage by routing through the
  // shared `statusKind` taxonomy. Crucially: `stopped` (CANCELLED,
  // BLOCKED_USER_DECLINE) and `expired` are neutral, NOT critical —
  // a user pressing Stop is not a failure.
  const kind = statusKind(status);
  const label = displayStatus(status);
  if (kind === "completed") {
    return (
      <span className="chip chip-success">
        <Icon.Check size={10} /> {label}
      </span>
    );
  }
  if (kind === "failed") {
    return <span className="chip chip-critical">{label}</span>;
  }
  if (kind === "blocked") {
    return <span className="chip chip-warn">{label}</span>;
  }
  if (kind === "stopped" || kind === "expired") {
    return <span className="chip">{label}</span>;
  }
  if (kind === "needs-input") {
    return (
      <span className="chip chip-info">
        <Icon.Clock size={10} /> {label}
      </span>
    );
  }
  return (
    <span className="chip chip-info">
      <span
        className="pulse-dot dot"
        style={{ background: "currentColor" }}
      />{" "}
      {label}
    </span>
  );
}

const EMPTY_STATS: DashboardStats = {
  risk_score: 100,
  open_findings: {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
  },
  fixes_ready: 0,
  scans_this_month: 0,
  scans_trend: [],
  cost_this_month_usd: 0,
};

export const UserDashboard: React.FC = () => {
  const navigate = useNavigate();
  const { user } = useAuth();

  const { data: statsData } = useQuery({
    queryKey: ["dashboard", "stats"],
    queryFn: dashboardService.getStats,
  });

  const { data: recentData, isLoading: recentLoading } = useQuery({
    queryKey: ["dashboard", "recent-scans"],
    queryFn: () => scanService.getScanHistory(1, 10, undefined, "desc"),
  });

  const stats = statsData ?? EMPTY_STATS;
  const scans: ScanHistoryItem[] = useMemo(
    () => recentData?.items ?? [],
    [recentData],
  );
  const inProgress = useMemo(
    () => scans.filter((s) => IN_PROGRESS_STATUSES.has(s.status)).length,
    [scans],
  );
  const recent = scans.slice(0, 5);
  const totalOpen =
    stats.open_findings.critical +
    stats.open_findings.high +
    stats.open_findings.medium +
    stats.open_findings.low +
    stats.open_findings.informational;

  return (
    <div className="fade-in" style={{ display: "grid", gap: 20 }}>
      {/* hero */}
      <div
        className="sccap-card"
        style={{
          background: "linear-gradient(135deg, var(--bg-elev), var(--bg-soft))",
          padding: 28,
          display: "grid",
          gridTemplateColumns: "1fr auto",
          alignItems: "center",
          gap: 20,
        }}
      >
        <div>
          <div className="chip chip-ai" style={{ marginBottom: 10 }}>
            <Icon.Sparkle size={11} /> Welcome back
            {user?.email ? `, ${user.email.split("@")[0]}` : ""}
          </div>
          <h1 style={{ marginBottom: 6 }}>
            {inProgress > 0
              ? `${inProgress} scan${inProgress === 1 ? "" : "s"} in progress.`
              : stats.scans_this_month === 0
                ? "No scans this month yet — start one."
                : "All caught up — no scans in progress."}
          </h1>
          <div style={{ color: "var(--fg-muted)", fontSize: 14 }}>
            {stats.scans_this_month} scan{stats.scans_this_month === 1 ? "" : "s"}{" "}
            this month · {totalOpen} open finding
            {totalOpen === 1 ? "" : "s"} ·{" "}
            <b>${stats.cost_this_month_usd.toFixed(2)}</b> spent
          </div>
          <div style={{ marginTop: 16, display: "flex", gap: 8 }}>
            <button
              className="sccap-btn sccap-btn-primary"
              onClick={() => navigate("/submission/submit")}
            >
              <Icon.Upload size={14} /> New scan
            </button>
            <button
              className="sccap-btn"
              onClick={() => navigate("/analysis/results")}
            >
              <Icon.Folder size={14} /> View projects
            </button>
          </div>
        </div>
        <div style={{ display: "grid", placeItems: "center" }}>
          <RiskRing score={stats.risk_score} label="Posture" />
        </div>
      </div>

      {/* metrics */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(4, 1fr)",
          gap: 16,
        }}
      >
        <MetricCard
          label="Scans / month"
          value={stats.scans_this_month}
          delta={`${stats.scans_trend.reduce((a, b) => a + b, 0)} in last 14 days`}
          spark={<Spark data={stats.scans_trend} idKey="trend" />}
        />
        <MetricCard
          label="In progress"
          value={inProgress}
          delta={inProgress > 0 ? "active now" : "idle"}
          tone={inProgress > 0 ? "warn" : "default"}
        />
        <MetricCard
          label="Open critical"
          value={stats.open_findings.critical}
          tone={stats.open_findings.critical > 0 ? "bad" : "good"}
          delta={`${stats.open_findings.high} high`}
        />
        <MetricCard
          label="Fixes ready"
          value={stats.fixes_ready}
          delta={stats.fixes_ready > 0 ? "AI-suggested" : "nothing queued"}
          tone={stats.fixes_ready > 0 ? "warn" : "default"}
        />
      </div>

      {/* two-col */}
      <div
        style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16 }}
      >
        {/* recent scans */}
        <div className="sccap-card" style={{ padding: 0, overflow: "hidden" }}>
          <SectionHead
            title={
              <>
                <Icon.Folder size={16} /> Recent scans
              </>
            }
            right={
              <Link
                to="/analysis/results"
                className="sccap-btn sccap-btn-sm sccap-btn-ghost"
                style={{ textDecoration: "none" }}
              >
                View all <Icon.ChevronR size={12} />
              </Link>
            }
            style={{ padding: "18px 20px 10px", margin: 0 }}
          />
          {recentLoading ? (
            <div
              style={{
                padding: 40,
                textAlign: "center",
                color: "var(--fg-muted)",
              }}
            >
              Loading scans…
            </div>
          ) : recent.length === 0 ? (
            <div
              style={{
                padding: 40,
                textAlign: "center",
                color: "var(--fg-muted)",
              }}
            >
              No scans yet.{" "}
              <Link
                to="/submission/submit"
                style={{ color: "var(--primary)" }}
              >
                Submit one
              </Link>{" "}
              to get started.
            </div>
          ) : (
            <table className="sccap-t">
              <thead>
                <tr>
                  <th>Project</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>When</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {recent.map((s) => {
                  return (
                    <tr
                      key={s.id}
                      onClick={() => navigate(scanRouteFor(s.id, s.status))}
                      style={{ cursor: "pointer" }}
                    >
                      <td>
                        <div
                          style={{
                            display: "flex",
                            alignItems: "center",
                            gap: 10,
                          }}
                        >
                          <div
                            style={{
                              width: 28,
                              height: 28,
                              borderRadius: 6,
                              background: "var(--bg-soft)",
                              display: "grid",
                              placeItems: "center",
                              color: "var(--fg-muted)",
                            }}
                          >
                            <Icon.Folder size={14} />
                          </div>
                          <div>
                            <div
                              style={{ fontWeight: 500, color: "var(--fg)" }}
                            >
                              {s.project_name}
                            </div>
                            <div
                              style={{
                                fontSize: 11.5,
                                color: "var(--fg-subtle)",
                                fontFamily: "var(--font-mono)",
                              }}
                            >
                              {s.id.slice(0, 12)}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td
                        style={{
                          color: "var(--fg-muted)",
                          fontSize: 12.5,
                        }}
                      >
                        {s.scan_type}
                      </td>
                      <td>{statusChip(s.status)}</td>
                      <td
                        style={{
                          color: "var(--fg-muted)",
                          fontSize: 12.5,
                        }}
                      >
                        {relativeTime(s.created_at)}
                      </td>
                      <td
                        style={{
                          textAlign: "right",
                          color: "var(--fg-subtle)",
                        }}
                      >
                        <Icon.ChevronR size={14} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* right col */}
        <div style={{ display: "grid", gap: 16 }}>
          <div className="sccap-card">
            <SectionHead
              title={
                <>
                  <Icon.Layers size={16} /> Findings by severity
                </>
              }
            />
            <div style={{ padding: "12px 4px 4px" }}>
              <SevBar
                crit={stats.open_findings.critical}
                high={stats.open_findings.high}
                med={stats.open_findings.medium}
                low={stats.open_findings.low}
                info={stats.open_findings.informational}
              />
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(5, 1fr)",
                  gap: 6,
                  marginTop: 14,
                  fontSize: 11.5,
                }}
              >
                <SevLegend
                  label="Critical"
                  value={stats.open_findings.critical}
                  swatch="var(--critical)"
                />
                <SevLegend
                  label="High"
                  value={stats.open_findings.high}
                  swatch="var(--high)"
                />
                <SevLegend
                  label="Medium"
                  value={stats.open_findings.medium}
                  swatch="var(--medium)"
                />
                <SevLegend
                  label="Low"
                  value={stats.open_findings.low}
                  swatch="var(--low)"
                />
                <SevLegend
                  label="Info"
                  value={stats.open_findings.informational}
                  swatch="var(--info)"
                />
              </div>
              {totalOpen === 0 && (
                <div
                  style={{
                    fontSize: 12,
                    color: "var(--fg-subtle)",
                    marginTop: 10,
                    textAlign: "center",
                  }}
                >
                  No open findings yet.
                </div>
              )}
            </div>
          </div>

          <div
            className="sccap-card"
            style={{
              background: "var(--primary-weak)",
              borderColor: "transparent",
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 10,
                marginBottom: 8,
              }}
            >
              <div
                style={{
                  width: 32,
                  height: 32,
                  borderRadius: 8,
                  background: "var(--primary)",
                  color: "var(--primary-ink)",
                  display: "grid",
                  placeItems: "center",
                }}
              >
                <Icon.Sparkle size={16} />
              </div>
              <div
                style={{ fontWeight: 600, color: "var(--primary-strong)" }}
              >
                Advisor
              </div>
            </div>
            <div
              style={{
                fontSize: 13.5,
                color: "var(--fg)",
                lineHeight: 1.55,
              }}
            >
              Ask the SCCAP advisor about any finding, get AI-suggested
              remediation bundles, or request a walkthrough of a scan.
            </div>
            <button
              className="sccap-btn sccap-btn-primary sccap-btn-sm"
              style={{ marginTop: 12 }}
              onClick={() => navigate("/advisor")}
            >
              Open advisor <Icon.ArrowR size={12} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

const SevLegend: React.FC<{
  label: string;
  value: number;
  swatch: string;
}> = ({ label, value, swatch }) => (
  <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
    <span
      style={{
        width: 8,
        height: 8,
        borderRadius: 2,
        background: swatch,
        flexShrink: 0,
      }}
    />
    <span style={{ color: "var(--fg-muted)" }}>
      {label} <b style={{ color: "var(--fg)" }}>{value}</b>
    </span>
  </div>
);

export default UserDashboard;
