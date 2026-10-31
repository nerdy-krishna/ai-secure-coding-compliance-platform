// secure-code-ui/src/pages/analysis/ProjectsPage.tsx
//
// SCCAP projects grid. Each card shows the project name, latest scan
// status, and a per-project rollup served by `GET /projects` — the
// risk score, severity bar, and "fixes ready" counter all come from
// `project.stats`, which scan_service populates by aggregating findings
// from the latest terminal scan (H.4).

import { useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useDebounce } from "../../shared/hooks/useDebounce";
import { scanService } from "../../shared/api/scanService";
import { dashboardService } from "../../shared/api/dashboardService";
import { ruleSourcesService } from "../../shared/api/ruleSourcesService";
import { useAuth } from "../../shared/hooks/useAuth";
import { Permission, hasPermission } from "../../shared/lib/permissions";
import { useUsageTotals } from "../../shared/hooks/useUsageTotals";
import { sharedTiles, type Tile } from "../../shared/ui/OverviewTiles";
import type {
  ProjectHistoryItem,
  ScanHistoryItem,
} from "../../shared/types/api";
import { SevBar } from "../../shared/ui/DashboardPrimitives";
import { PageHeader } from "../../shared/ui/PageHeader";
import { Icon } from "../../shared/ui/Icon";
import { Modal } from "../../shared/ui/Modal";
import { useToast } from "../../shared/ui/Toast";

const TERMINAL_OK = new Set(["COMPLETED", "REMEDIATION_COMPLETED"]);

function formatWhen(iso: string | null | undefined): string {
  if (!iso) return "—";
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 60_000) return "just now";
  const m = Math.floor(diff / 60_000);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d}d ago`;
  return new Date(iso).toLocaleDateString();
}


function latestScan(p: ProjectHistoryItem): ScanHistoryItem | null {
  const sorted = [...p.scans].sort(
    (a, b) =>
      new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
  );
  return sorted.find((s) => TERMINAL_OK.has(s.status)) ?? sorted[0] ?? null;
}

const ProjectsPage: React.FC = () => {
  const navigate = useNavigate();
  const toast = useToast();
  const qc = useQueryClient();
  const [search, setSearch] = useState("");
  const debouncedSearch = useDebounce(search, 300);
  const [createOpen, setCreateOpen] = useState(false);
  const [newName, setNewName] = useState("");
  const [creating, setCreating] = useState(false);

  const { user } = useAuth();
  const isAdmin = hasPermission(user?.permissions, Permission.platformConfigManage);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["projects", debouncedSearch],
    queryFn: () => scanService.getProjectHistory(1, 100, debouncedSearch || undefined),
  });
  // The same tiles the home overview shows, on the page an operator actually
  // works from, so the numbers never need a trip back to the dashboard.
  const statsQ = useQuery({ queryKey: ["dashboard", "stats"], queryFn: dashboardService.getStats });
  const sourcesQ = useQuery({
    queryKey: ["dashboard", "rule-sources"],
    queryFn: () => ruleSourcesService.listSources(),
    enabled: isAdmin,
  });

  const handleCreateProject = async (e: React.FormEvent) => {
    e.preventDefault();
    const name = newName.trim();
    if (!name) return;
    setCreating(true);
    try {
      const project = await scanService.createProject(name);
      toast.success(`Project "${project.name}" created.`);
      setCreateOpen(false);
      setNewName("");
      qc.invalidateQueries({ queryKey: ["projects"] });
      navigate(`/analysis/projects/${project.id}`, {
        state: { projectName: project.name, repoUrl: null },
      });
    } catch {
      toast.error("Failed to create project.");
    } finally {
      setCreating(false);
    }
  };

  const projects = useMemo(() => data?.items ?? [], [data]);
  const stats = statsQ.data;
  const sources = sourcesQ.data ?? [];
  const scanUsage = useUsageTotals("scan");
  const scansQ = useQuery({
    queryKey: ["dashboard", "scans-window"],
    queryFn: () => scanService.getScanHistory(1, 100),
  });
  const scansWindow = scansQ.data?.items ?? [];
  const scansThisWindow = scansQ.data?.total ?? scansWindow.length;
  const completedScans = scansWindow.filter((scan) => scan.status === "COMPLETED").length;
  const openFindings = stats?.open_findings;
  const criticalHigh = (openFindings?.critical ?? 0) + (openFindings?.high ?? 0);
  const failedSources = sources.filter((source) => source.last_sync_status === "failed");
  const enabledSources = sources.filter((source) => source.enabled);

  const tiles = sharedTiles({
    projects: data?.total ?? projects.length,
    projectsSub: "repositories under scan",
    runsLabel: "Scans",
    runs: scansThisWindow,
    runsSub: `${completedScans} completed`,
    findings: (openFindings?.critical ?? 0) + (openFindings?.high ?? 0) +
      (openFindings?.medium ?? 0) + (openFindings?.low ?? 0) +
      (openFindings?.informational ?? 0),
    findingsSub: criticalHigh ? `${criticalHigh} critical/high` : "none critical",
    findingsTone: criticalHigh ? "bad" : undefined,
    tokens: scanUsage.data,
    cost: scanUsage.data.cost_usd,
  }).concat([
    {
      label: "Semgrep sources",
      value: isAdmin ? `${enabledSources.length}/${sources.length}` : "—",
      sub: failedSources.length
        ? `${failedSources.length} failed sync`
        : isAdmin
          ? `${sources.reduce((total, source) => total + (source.rule_count ?? 0), 0).toLocaleString()} rules`
          : "admin only",
      tone: failedSources.length ? "bad" : enabledSources.length ? "ok" : "warn",
      icon: <Icon.Code size={15} />,
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
  ] as Tile[]);

  return (
    <div className="c13-page pentest-landing fade-in">
      <PageHeader
        crumbs={[
          { label: "Dashboard", to: "/account/dashboard" },
          { label: "Code scanning", to: "/submission/submit" },
          { label: "Projects and scans" },
        ]}
        title="Projects and scans"
        subtitle="Repositories under scan, and what the latest assessment of each found."
        actions={
          <>
            <Link className="sccap-btn" to="/account/history">
              Submission history
            </Link>
            <button
              className="sccap-btn"
              onClick={() => {
                setNewName("");
                setCreateOpen(true);
              }}
            >
              <Icon.Plus size={13} />New project
            </button>
            <Link className="sccap-btn sccap-btn-primary" to="/submission/submit">
              <Icon.Plus size={13} />New scan
            </Link>
          </>
        }
      />

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

      <section className="sccap-card">
        <div className="pentest-table-head">
          <h2 style={{ margin: 0 }}>
            {isLoading ? "Projects" : `${data?.total ?? 0} project${data?.total === 1 ? "" : "s"}`}
          </h2>
          <div className="input-with-icon project-page-search">
            <Icon.Search size={14} />
            <input
              className="sccap-input"
              placeholder="Search projects…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              style={{ paddingLeft: 32 }}
            />
          </div>
        </div>

      {isError ? (
        <div
          className="sccap-card"
          style={{
            padding: 40,
            textAlign: "center",
            color: "var(--critical)",
          }}
        >
          Failed to load projects. Check your connection and retry.
        </div>
      ) : isLoading ? (
        <div
          className="sccap-card"
          style={{
            padding: 40,
            textAlign: "center",
            color: "var(--fg-muted)",
          }}
        >
          Loading projects…
        </div>
      ) : projects.length === 0 ? (
        <div
          className="sccap-card"
          style={{
            padding: 60,
            textAlign: "center",
          }}
        >
          <div
            style={{
              color: "var(--fg)",
              fontSize: 16,
              fontWeight: 500,
              marginBottom: 6,
            }}
          >
            No projects yet
          </div>
          <div
            style={{ color: "var(--fg-muted)", fontSize: 13, marginBottom: 16 }}
          >
            Submit your first scan to create a project.
          </div>
          <button
            className="sccap-btn sccap-btn-primary"
            onClick={() => navigate("/submission/submit")}
          >
            <Icon.Plus size={13} /> Start a scan
          </button>
        </div>
      ) : (
        <div className="entity-grid">
          {projects.map((p) => {
            const latest = latestScan(p);
            const stats = p.stats;
            const totalFindings = stats
              ? stats.open_findings.critical +
                stats.open_findings.high +
                stats.open_findings.medium +
                stats.open_findings.low +
                stats.open_findings.informational
              : 0;
            return (
              <Link
                key={p.id}
                className="sccap-card"
                to={`/analysis/projects/${p.id}`}
                state={{
                  projectName: p.name,
                  repoUrl: p.repository_url ?? null,
                }}
                aria-label={`Open project ${p.name}`}
                style={{
                  cursor: "pointer",
                  color: "inherit",
                  textDecoration: "none",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "flex-start",
                    marginBottom: 10,
                  }}
                >
                  <div
                    style={{ display: "flex", alignItems: "center", gap: 10 }}
                  >
                    <div
                      style={{
                        width: 34,
                        height: 34,
                        borderRadius: 9,
                        background: "var(--bg-soft)",
                        display: "grid",
                        placeItems: "center",
                        color: "var(--fg-muted)",
                      }}
                    >
                      <Icon.Folder size={16} />
                    </div>
                    <div>
                      <div style={{ fontWeight: 600, color: "var(--fg)" }}>
                        {p.name}
                      </div>
                      <div
                        style={{
                          fontSize: 11.5,
                          color: "var(--fg-subtle)",
                        }}
                      >
                        {p.repository_url
                          ? p.repository_url.replace(/^https?:\/\//, "")
                          : "Direct submission"}
                      </div>
                    </div>
                  </div>
                  <div style={{ fontSize: 11, color: "var(--fg-subtle)" }}>
                    {p.scans.length} scan{p.scans.length === 1 ? "" : "s"}
                  </div>
                </div>

                <SevBar
                  crit={stats?.open_findings.critical}
                  high={stats?.open_findings.high}
                  med={stats?.open_findings.medium}
                  low={stats?.open_findings.low}
                  info={stats?.open_findings.informational}
                />
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    marginTop: 10,
                    fontSize: 11.5,
                    color: "var(--fg-subtle)",
                  }}
                >
                  <span>
                    <Icon.Clock size={10} />{" "}
                    {latest
                      ? formatWhen(latest.created_at)
                      : formatWhen(p.updated_at)}
                  </span>
                  <span>
                    {stats
                      ? `${totalFindings} open · ${stats.fixes_ready} fix${stats.fixes_ready === 1 ? "" : "es"} ready`
                      : latest
                        ? latest.status === "FAILED"
                          ? "last failed"
                          : "no stats yet"
                        : "no scans"}
                  </span>
                </div>
              </Link>
            );
          })}
        </div>
      )}
      </section>

      <Modal
        open={createOpen}
        onClose={() => !creating && setCreateOpen(false)}
        title="New project"
        width={420}
        footer={
          <>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={() => setCreateOpen(false)}
              disabled={creating}
            >
              Cancel
            </button>
            <button
              className="sccap-btn sccap-btn-primary sccap-btn-sm"
              onClick={handleCreateProject}
              disabled={creating || !newName.trim()}
            >
              {creating ? "Creating…" : "Create project"}
            </button>
          </>
        }
      >
        <form onSubmit={handleCreateProject} style={{ display: "grid", gap: 14 }}>
          <label style={{ display: "grid", gap: 6 }}>
            <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
              Project name
            </span>
            <input
              className="sccap-input"
              placeholder="e.g. My API Service"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              maxLength={128}
              autoFocus
              required
            />
          </label>
          <button type="submit" style={{ display: "none" }} />
        </form>
      </Modal>
    </div>
  );
};

export default ProjectsPage;
