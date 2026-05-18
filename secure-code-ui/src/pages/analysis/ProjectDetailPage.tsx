// secure-code-ui/src/pages/analysis/ProjectDetailPage.tsx
//
// Per-project scan list. Reached from the Projects grid (clicking a card
// no longer jumps straight to the latest scan; users now land here and
// pick the scan they want). Each row routes via scanRouteFor so an
// in-progress / pending-approval scan opens on ScanRunningPage and a
// terminal scan opens on ResultsPage.

import { useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useCallback, useMemo, useState } from "react";
import { useLocation, useNavigate, useParams } from "react-router-dom";
import { ScanCard } from "../../features/scans/ScanCard";
import { ScanRowControls } from "../../features/scans/ScanRowControls";
import { scanService } from "../../shared/api/scanService";
import { useAuth } from "../../shared/hooks/useAuth";
import { isTerminalStatus } from "../../shared/lib/scanProgress";
import { scanRouteFor } from "../../shared/lib/scanRoute";
import type { ScanHistoryItem } from "../../shared/types/api";
import { Icon } from "../../shared/ui/Icon";
import { Modal } from "../../shared/ui/Modal";
import { PageHeader } from "../../shared/ui/PageHeader";
import { useToast } from "../../shared/ui/Toast";

interface NavState {
  projectName?: string;
  repoUrl?: string | null;
}

const ProjectDetailPage: React.FC = () => {
  const { projectId } = useParams<{ projectId: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const navState = (location.state ?? {}) as NavState;
  const queryClient = useQueryClient();
  const toast = useToast();
  const { user } = useAuth();
  const isSuperuser = !!user?.is_superuser;

  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ["project-scans", projectId],
    queryFn: () => scanService.getScansForProject(projectId!, 1, 100),
    enabled: !!projectId,
    // Poll only while a scan in the list is still active (#87).
    refetchInterval: (query) => {
      const items = query.state.data?.items ?? [];
      return items.some((s) => !isTerminalStatus(s.status)) ? 6_000 : false;
    },
  });

  const scans = useMemo<ScanHistoryItem[]>(
    () =>
      [...(data?.items ?? [])].sort(
        (a, b) =>
          new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
      ),
    [data],
  );

  // Project name fallback chain: state from the previous page → first
  // scan's project_name → "Project". Repo URL similarly.
  const projectName =
    navState.projectName ?? scans[0]?.project_name ?? "Project";
  const repoUrl = navState.repoUrl ?? null;

  const handleDeleteProject = useCallback(async () => {
    if (!projectId) return;
    setDeleting(true);
    try {
      await scanService.deleteProject(projectId);
      toast.info("Project deleted.");
      // Drop the per-project query and the projects list so neither
      // serves stale rows after we navigate back.
      queryClient.removeQueries({ queryKey: ["project-scans", projectId] });
      queryClient.invalidateQueries({ queryKey: ["projects"] });
      navigate("/analysis/results");
    } catch (err) {
      const e = err as { message?: string };
      toast.error(e.message || "Failed to delete project");
    } finally {
      setDeleting(false);
      setDeleteConfirmOpen(false);
    }
  }, [projectId, navigate, queryClient, toast]);


  return (
    <div className="fade-in" style={{ display: "grid", gap: 16 }}>
      <PageHeader
        crumbs={[
          { label: "Projects", to: "/analysis/results" },
          { label: projectName },
        ]}
        title={projectName}
        subtitle={
          <>
            <span>
              {data?.total ?? scans.length} scan
              {(data?.total ?? scans.length) === 1 ? "" : "s"}
            </span>
            {repoUrl && (
              <span style={{ color: "var(--fg-subtle)" }}>
                · {repoUrl.replace(/^https?:\/\//, "")}
              </span>
            )}
          </>
        }
        actions={
          <>
            {isSuperuser && (
              <button
                className="sccap-btn"
                onClick={() => setDeleteConfirmOpen(true)}
                disabled={deleting}
                style={{ color: "var(--critical)" }}
              >
                <Icon.Trash size={13} />{" "}
                {deleting ? "Deleting…" : "Delete project"}
              </button>
            )}
            <button
              className="sccap-btn sccap-btn-primary"
              onClick={() =>
                navigate("/submission/submit", {
                  state: { projectId, projectName, repoUrl },
                })
              }
            >
              <Icon.Plus size={13} /> New scan
            </button>
          </>
        }
      />

      {isError ? (
        <div
          className="sccap-card"
          style={{
            padding: 40,
            textAlign: "center",
            color: "var(--critical)",
          }}
        >
          Failed to load scans for this project.
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
          Loading scans…
        </div>
      ) : scans.length === 0 ? (
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
            No scans yet for this project
          </div>
          <button
            className="sccap-btn sccap-btn-primary"
            style={{ marginTop: 12 }}
            onClick={() =>
              navigate("/submission/submit", {
                state: {
                  projectId,
                  projectName,
                  repoUrl,
                },
              })
            }
          >
            <Icon.Plus size={13} /> Start a scan
          </button>
        </div>
      ) : (
        <div className="sccap-card" style={{ padding: 0, overflow: "hidden" }}>
          {scans.map((s, idx) => (
            <div
              key={s.id}
              style={{
                borderBottom:
                  idx < scans.length - 1
                    ? "1px solid var(--border)"
                    : "none",
              }}
            >
              <ScanCard
                scan={s}
                showProject={false}
                onOpen={() =>
                  navigate(scanRouteFor(s.id, s.status), {
                    state: {
                      fromLabel: projectName,
                      fromPath: `/analysis/projects/${projectId}`,
                    },
                  })
                }
                controls={
                  <ScanRowControls scan={s} onChanged={() => refetch()} />
                }
              />
            </div>
          ))}
        </div>
      )}

      <Modal
        open={deleteConfirmOpen}
        onClose={() => (deleting ? undefined : setDeleteConfirmOpen(false))}
        title="Delete this project permanently?"
        footer={
          <>
            <button
              className="sccap-btn"
              onClick={() => setDeleteConfirmOpen(false)}
              disabled={deleting}
            >
              Cancel
            </button>
            <button
              className="sccap-btn sccap-btn-primary"
              onClick={handleDeleteProject}
              disabled={deleting}
              style={{ background: "var(--critical)" }}
            >
              {deleting ? "Deleting…" : "Delete project"}
            </button>
          </>
        }
      >
        <div style={{ color: "var(--fg)", fontSize: 13.5, lineHeight: 1.55 }}>
          <b>{projectName}</b> and{" "}
          <b>
            {data?.total ?? scans.length} scan
            {(data?.total ?? scans.length) === 1 ? "" : "s"}
          </b>{" "}
          (with all findings, fixes, and stage events) will be removed. This
          cannot be undone.
        </div>
      </Modal>
    </div>
  );
};

export default ProjectDetailPage;
