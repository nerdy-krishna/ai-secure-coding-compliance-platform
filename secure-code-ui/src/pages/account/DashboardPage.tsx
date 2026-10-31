import { Link } from "react-router-dom";
import React from "react";
import { useQuery } from "@tanstack/react-query";
import { PageHeader } from "../../shared/ui/PageHeader";
import { Icon } from "../../shared/ui/Icon";
import SemgrepReadinessBanner from "../../features/semgrep/SemgrepReadinessBanner";
import UpdateAvailableBanner from "../../features/system/UpdateAvailableBanner";
import { dashboardService } from "../../shared/api/dashboardService";
import { scanService } from "../../shared/api/scanService";
import { ruleSourcesService } from "../../shared/api/ruleSourcesService";
import { frameworkService } from "../../shared/api/frameworkService";
import {
  getDashboard as getPentestDashboard,
  listProjects,
  listRuns,
  listToolHealth,
} from "../../shared/api/pentestService";
import { useAuth } from "../../shared/hooks/useAuth";
import { Permission, hasPermission } from "../../shared/lib/permissions";
import type { PentestDashboard } from "../../shared/api/pentestService";
import { compactNumber } from "../pentesting/format";
import { useUsageTotals } from "../../shared/hooks/useUsageTotals";
import { sharedTiles, type Tile } from "../../shared/ui/OverviewTiles";
import "../pentesting/pentest.css";


function Section({
  title,
  description,
  action,
  tiles,
  children,
}: {
  title: string;
  description: string;
  action?: React.ReactNode;
  tiles: Tile[];
  children?: React.ReactNode;
}) {
  return (
    <section className="sccap-card home-section">
      <div className="pentest-table-head">
        <div>
          <h2 style={{ margin: 0 }}>{title}</h2>
          <p className="pentest-muted">{description}</p>
        </div>
        {action}
      </div>
      <div className="stat-grid">
        {tiles.map((tile) => (
          <div key={tile.label} className={`stat-card${tile.tone ? ` is-${tile.tone}` : ""}`}>
            <div className="stat-icon">{tile.icon}</div>
            <div>
              <div className="stat-value">{tile.value}</div>
              <div className="stat-label">{tile.label}</div>
              {tile.sub && <div className="stat-sub">{tile.sub}</div>}
            </div>
          </div>
        ))}
      </div>
      {children}
    </section>
  );
}

/**
 * Home overview: two sections, one per product area.
 *
 * The page answers "what is the state of my estate" for code scanning and for
 * pentesting side by side, and links into the pages that hold the detail.
 */
const DashboardPage: React.FC = () => {
  const { user } = useAuth();
  // Semgrep sources and frameworks are admin surfaces: asking for them as a
  // regular user would 403 and show a misleading zero.
  const isAdmin = hasPermission(user?.permissions, Permission.platformConfigManage);
  const statsQ = useQuery({ queryKey: ["dashboard", "stats"], queryFn: dashboardService.getStats });
  const projectsQ = useQuery({
    queryKey: ["dashboard", "projects"],
    queryFn: () => scanService.getProjectHistory(1, 1),
  });
  const scansQ = useQuery({
    queryKey: ["dashboard", "scans"],
    queryFn: () => scanService.getScanHistory(1, 50),
  });
  const sourcesQ = useQuery({
    queryKey: ["dashboard", "rule-sources"],
    queryFn: () => ruleSourcesService.listSources(),
    enabled: isAdmin,
  });
  const frameworksQ = useQuery({
    queryKey: ["dashboard", "frameworks"],
    queryFn: () => frameworkService.getFrameworks(),
    enabled: isAdmin,
  });
  const pentestQ = useQuery({ queryKey: ["pentest", "dashboard"], queryFn: getPentestDashboard, refetchInterval: 15_000 });
  const pentestRunsQ = useQuery({ queryKey: ["pentest", "runs"], queryFn: listRuns });
  const pentestProjectsQ = useQuery({ queryKey: ["pentest", "projects"], queryFn: listProjects });
  const pentestToolsQ = useQuery({ queryKey: ["pentest", "tool-health"], queryFn: listToolHealth, refetchInterval: 60_000 });
  const scanUsage = useUsageTotals("scan");
  const pentestUsageQ = useUsageTotals("pentest");

  const stats = statsQ.data;
  const scans = scansQ.data?.items ?? [];
  const sources = sourcesQ.data ?? [];
  const frameworks = frameworksQ.data ?? [];
  const pentest: PentestDashboard | undefined = pentestQ.data;

  const runningScans = scans.filter((scan) => scan.status === "RUNNING").length;
  const completedScans = scans.filter((scan) => scan.status === "COMPLETED").length;
  const enabledSources = sources.filter((source) => source.enabled);
  const syncingSources = sources.filter((source) => source.last_sync_status === "failed");
  const semgrepRules = sources.reduce((total, source) => total + (source.rule_count ?? 0), 0);
  const openFindings = stats?.open_findings;
  const criticalHigh = (openFindings?.critical ?? 0) + (openFindings?.high ?? 0);
  const missingTools = pentestToolsQ.data?.missing ?? pentest?.tools.missing ?? [];
  const pentestSeverity = pentest?.findings.by_severity ?? {};
  const pentestProjects = pentestProjectsQ.data ?? [];
  const pentestProjectCount = pentestProjects.length;
  const pentestUnassigned = (pentestRunsQ.data ?? []).filter((run) => !run.project_id).length;
  const pentestCriticalHigh = (pentestSeverity.critical ?? 0) + (pentestSeverity.high ?? 0);

  const codeTiles: Tile[] = [
    ...sharedTiles({
      projects: projectsQ.data?.total ?? 0,
      projectsSub: "repositories under scan",
      runsLabel: "Scans",
      runs: scansQ.data?.total ?? scans.length,
      runsSub: runningScans ? `${runningScans} running` : `${completedScans} completed`,
      runsTone: runningScans ? "ok" : undefined,
      findings: (openFindings?.critical ?? 0) + (openFindings?.high ?? 0) +
        (openFindings?.medium ?? 0) + (openFindings?.low ?? 0) +
        (openFindings?.informational ?? 0),
      findingsSub: criticalHigh ? `${criticalHigh} critical/high` : "none critical",
      findingsTone: criticalHigh ? "bad" : undefined,
      tokens: scanUsage.data,
      cost: scanUsage.data.cost_usd,
    }),
    {
      label: "Semgrep sources",
      value: isAdmin ? `${enabledSources.length}/${sources.length}` : "—",
      sub: syncingSources.length
        ? `${syncingSources.length} failed sync`
        : semgrepRules
          ? `${semgrepRules.toLocaleString()} rules`
          : "no rules ingested",
      tone: !isAdmin ? undefined : syncingSources.length ? "bad" : enabledSources.length ? "ok" : "warn",
      icon: <Icon.Code size={15} />,
    },
    {
      label: "Frameworks",
      value: isAdmin ? String(frameworks.length) : "—",
      sub: "compliance mappings",
      icon: <Icon.BookOpen size={15} />,
    },
    {
      label: "Scans this month",
      value: String(stats?.scans_this_month ?? 0),
      sub: stats ? `≈$${stats.cost_this_month_usd.toFixed(2)} spent` : undefined,
      icon: <Icon.Clock size={15} />,
    },
    {
      label: "Fixes ready",
      value: String(stats?.fixes_ready ?? 0),
      sub: "awaiting review",
      tone: stats?.fixes_ready ? "warn" : undefined,
      icon: <Icon.Check size={15} />,
    },
  ];

  const pentestTiles: Tile[] = [
    ...sharedTiles({
      projects: pentestProjectCount,
      projectsSub: pentestUnassigned
        ? `${pentestUnassigned} scan(s) unassigned`
        : "assessed estates",
      projectsTone: pentestUnassigned ? "warn" : "ok",
      runsLabel: "Assessments",
      runs: pentest?.runs.total ?? 0,
      runsSub: pentest?.runs.running ? `${pentest.runs.running} in flight` : "none running",
      runsTone: pentest?.runs.running ? "ok" : undefined,
      findings: pentest?.findings.total ?? 0,
      findingsSub: pentestCriticalHigh ? `${pentestCriticalHigh} critical/high` : "none critical",
      findingsTone: pentestCriticalHigh ? "bad" : undefined,
      tokens: pentestUsageQ.data,
      cost: pentest?.usage.cost_usd ?? pentestUsageQ.data.cost_usd,
    }),
    {
      label: "Proven by replay",
      value: String(pentest?.findings.proven ?? 0),
      sub: `${pentest?.findings.needs_review ?? 0} need review`,
      tone: pentest?.findings.proven ? "ok" : undefined,
      icon: <Icon.Check size={15} />,
    },
    {
      label: "Observations",
      value: compactNumber(pentest?.observations ?? 0),
      sub: "surface intelligence",
      icon: <Icon.Eye size={15} />,
    },
    {
      label: "Open tests",
      value: String(pentest?.leads.open ?? 0),
      sub: `${pentest?.leads.tested ?? 0} tested`,
      tone: pentest?.leads.open ? "warn" : "ok",
      icon: <Icon.Sort size={15} />,
    },
    {
      label: "Exploit chains",
      value: `${pentest?.chains.confirmed ?? 0}/${pentest?.chains.total ?? 0}`,
      sub: "confirmed / proposed",
      tone: pentest?.chains.confirmed ? "bad" : undefined,
      icon: <Icon.Zap size={15} />,
    },
    {
      label: "Tools ready",
      value: `${pentest?.tools.ready ?? pentestToolsQ.data?.available ?? 0}/${pentest?.tools.total ?? pentestToolsQ.data?.total ?? 0}`,
      sub: missingTools.length ? `missing ${missingTools.join(", ")}` : "all present",
      tone: missingTools.length ? "bad" : "ok",
      icon: <Icon.Terminal size={15} />,
    },
  ];

  return (
    <div className="c13-page home-overview fade-in">
      <PageHeader
        crumbs={[{ label: "Dashboard" }]}
        title="Overview"
        subtitle="The state of your code scanning and pentesting estate at a glance."
      />

      <UpdateAvailableBanner />
      <SemgrepReadinessBanner />

      <Section
        title="Code scanning"
        description="Static analysis over your repositories: scans, findings and the rule inventory behind them."
        action={
          <div className="home-section-actions">
            <Link className="sccap-btn" to="/analysis/results">
              Projects and results
            </Link>
            <Link className="sccap-btn sccap-btn-primary" to="/submission/submit">
              <Icon.Plus size={13} />New scan
            </Link>
          </div>
        }
        tiles={codeTiles}
      />

      <Section
        title="Pentesting"
        description="Autonomous assessments against authorised targets: discoveries, proven findings and the queue still being worked."
        action={
          <div className="home-section-actions">
            <Link className="sccap-btn" to="/pentesting">
              Projects and scans
            </Link>
            <Link className="sccap-btn sccap-btn-primary" to="/pentesting/new">
              <Icon.Plus size={13} />New pentest
            </Link>
          </div>
        }
        tiles={pentestTiles}
      />
    </div>
  );
};

export default DashboardPage;
