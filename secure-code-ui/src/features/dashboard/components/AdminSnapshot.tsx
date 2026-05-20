// secure-code-ui/src/features/dashboard/components/AdminSnapshot.tsx
//
// Admin view of the same /dashboard/stats feed. The backend returns
// platform-wide aggregates when the caller is a superuser (no scope
// filter), so the component is thin — just relabels the hero + metrics
// to make it obvious the numbers are global, not personal.
//
// Leaves the "top users by scans" + "groups summary" tiles for a later
// iteration once the backend exposes those rollups; for now admins see
// the same posture + severity + spend view their users see, but
// platform-wide.

import { useQuery } from "@tanstack/react-query";
import React from "react";
import { Link, useNavigate } from "react-router-dom";
import { ScanCard } from "../../scans/ScanCard";
import { dashboardService } from "../../../shared/api/dashboardService";
import type { DashboardStats } from "../../../shared/api/dashboardService";
import { scanService } from "../../../shared/api/scanService";
import { isTerminalStatus } from "../../../shared/lib/scanProgress";
import { scanRouteFor } from "../../../shared/lib/scanRoute";
import { Icon } from "../../../shared/ui/Icon";
import {
  MetricCard,
  RiskRing,
  SectionHead,
  SevBar,
  Spark,
} from "../../../shared/ui/DashboardPrimitives";

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

export const AdminSnapshot: React.FC = () => {
  const navigate = useNavigate();

  const { data: statsData, isLoading } = useQuery({
    queryKey: ["dashboard", "stats", "admin"],
    queryFn: dashboardService.getStats,
  });

  // Recent scans across the platform (#88) — kept live while any is
  // still running.
  const { data: recentData } = useQuery({
    queryKey: ["dashboard", "recent-scans", "admin"],
    queryFn: () => scanService.getScanHistory(1, 6, undefined, "desc"),
    refetchInterval: (query) => {
      const items = query.state.data?.items ?? [];
      return items.some((s) => !isTerminalStatus(s.status)) ? 6_000 : false;
    },
  });
  const recentScans = (recentData?.items ?? []).slice(0, 6);

  const stats = statsData ?? EMPTY_STATS;
  const totalOpen =
    stats.open_findings.critical +
    stats.open_findings.high +
    stats.open_findings.medium +
    stats.open_findings.low +
    stats.open_findings.informational;

  return (
    <div className="fade-in" style={{ display: "grid", gap: 20 }}>
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
          <div className="chip" style={{ marginBottom: 10 }}>
            <Icon.Shield size={11} /> Admin snapshot · platform-wide
          </div>
          <h1 style={{ marginBottom: 6 }}>
            {totalOpen === 0
              ? "No open findings across the platform."
              : `${totalOpen.toLocaleString()} open finding${totalOpen === 1 ? "" : "s"} across the platform.`}
          </h1>
          <div style={{ color: "var(--fg-muted)", fontSize: 14 }}>
            {stats.scans_this_month.toLocaleString()} scan
            {stats.scans_this_month === 1 ? "" : "s"} this month · platform spend{" "}
            <b>${stats.cost_this_month_usd.toFixed(2)}</b>
          </div>
          <div style={{ marginTop: 16, display: "flex", gap: 8 }}>
            <Link
              to="/admin/user-groups"
              className="sccap-btn sccap-btn-primary"
              style={{ textDecoration: "none" }}
            >
              <Icon.Users size={14} /> Manage groups
            </Link>
            <Link
              to="/admin/users"
              className="sccap-btn"
              style={{ textDecoration: "none" }}
            >
              <Icon.Users size={14} /> Users
            </Link>
            <button
              className="sccap-btn"
              onClick={() => navigate("/analysis/results")}
            >
              <Icon.Folder size={14} /> All projects
            </button>
          </div>
        </div>
        <div style={{ display: "grid", placeItems: "center" }}>
          <RiskRing score={stats.risk_score} label="Platform" />
        </div>
      </div>

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
          spark={<Spark data={stats.scans_trend} idKey="admin-trend" />}
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
        <MetricCard
          label="Spend this month"
          value={`$${stats.cost_this_month_usd.toFixed(2)}`}
          delta={isLoading ? "loading…" : "across all LLM providers"}
        />
      </div>

      <div className="sccap-card">
        <SectionHead
          title={
            <>
              <Icon.Layers size={16} /> Severity breakdown · platform
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
              gap: 12,
              marginTop: 14,
              fontSize: 12,
            }}
          >
            <Legend
              label="Critical"
              value={stats.open_findings.critical}
              swatch="var(--critical)"
            />
            <Legend
              label="High"
              value={stats.open_findings.high}
              swatch="var(--high)"
            />
            <Legend
              label="Medium"
              value={stats.open_findings.medium}
              swatch="var(--medium)"
            />
            <Legend
              label="Low"
              value={stats.open_findings.low}
              swatch="var(--low)"
            />
            <Legend
              label="Info"
              value={stats.open_findings.informational}
              swatch="var(--info)"
            />
          </div>
        </div>
      </div>

      {recentScans.length > 0 && (
        <div style={{ display: "grid", gap: 16 }}>
          <SectionHead
            title={
              <>
                <Icon.Folder size={16} /> Recent scans · platform
              </>
            }
            right={
              <Link
                to="/account/history"
                className="sccap-btn sccap-btn-sm sccap-btn-ghost"
                style={{ textDecoration: "none" }}
              >
                View all <Icon.ChevronR size={12} />
              </Link>
            }
          />
          {recentScans.map((s) => (
            <div
              key={s.id}
              className="sccap-card"
              style={{ padding: 0, overflow: "hidden" }}
            >
              <ScanCard
                scan={s}
                onOpen={() => navigate(scanRouteFor(s.id, s.status))}
              />
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

const Legend: React.FC<{
  label: string;
  value: number;
  swatch: string;
}> = ({ label, value, swatch }) => (
  <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
    <span
      style={{
        width: 10,
        height: 10,
        borderRadius: 2,
        background: swatch,
        flexShrink: 0,
      }}
    />
    <span style={{ color: "var(--fg-muted)" }}>
      {label} <b style={{ color: "var(--fg)" }}>{value.toLocaleString()}</b>
    </span>
  </div>
);

export default AdminSnapshot;
