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
import type {
  ProjectHistoryItem,
  ScanHistoryItem,
} from "../../shared/types/api";
import { SevBar } from "../../shared/ui/DashboardPrimitives";
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

// Inverted from dashboard: the RiskRing reads "higher is better"; the
// progress bar on the card reads "higher is worse". Convert here so a
// posture score of 100 shows an empty bar.
function exposureColor(exposure: number): string {
  if (exposure >= 75) return "var(--critical)";
  if (exposure >= 50) return "var(--high)";
  if (exposure >= 25) return "var(--medium)";
  return "var(--success)";
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

  const { data, isLoading, isError } = useQuery({
    queryKey: ["projects", debouncedSearch],
    queryFn: () => scanService.getProjectHistory(1, 100, debouncedSearch || undefined),
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

  return (
    <div className="fade-in" style={{ display: "grid", gap: 16 }}>
      <div>
        <h1 style={{ color: "var(--fg)" }}>Projects</h1>
        <div
          className="project-page-toolbar"
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            gap: 12,
            marginTop: 8,
          }}
        >
          <span style={{ color: "var(--fg-muted)", fontSize: 13 }}>
            {isLoading
              ? "Loading…"
              : `${data?.total ?? 0} project${data?.total === 1 ? "" : "s"}`}
          </span>
          <div className="project-page-actions" style={{ display: "flex", gap: 8 }}>
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
            <button
              className="sccap-btn sccap-btn-primary"
              onClick={() => { setNewName(""); setCreateOpen(true); }}
            >
              <Icon.Plus size={13} /> New project
            </button>
          </div>
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
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
            gap: 14,
          }}
        >
          {projects.map((p) => {
            const latest = latestScan(p);
            const stats = p.stats;
            const exposure = stats ? 100 - stats.risk_score : 0;
            const color = exposureColor(exposure);
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

                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    fontSize: 11.5,
                    color: "var(--fg-muted)",
                    marginBottom: 6,
                  }}
                >
                  <span>Posture score</span>
                  <span style={{ fontWeight: 600, color }}>
                    {stats ? stats.risk_score : "—"}
                  </span>
                </div>
                <div className="sccap-progress" style={{ marginBottom: 12 }}>
                  <span
                    style={{
                      width: stats ? `${exposure}%` : "0%",
                      background: color,
                    }}
                  />
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
