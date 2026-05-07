// secure-code-ui/src/pages/analysis/ResultsPage.tsx
//
// SCCAP scan-result view. Port of the design bundle's Results.jsx,
// wired to the real backend via scanService.getScanResult.
//
// Layout:
//   - Breadcrumb + header with project + scan summary
//   - Summary strip (risk score + severity counts + AI-fix count)
//   - Two-column body: findings list (filterable) + detail pane
//
// The detail pane renders description, remediation, compliance chips,
// and (when a fix suggestion exists) a side-by-side diff using the
// design's `.diff` / `.diff-row` utilities. Actions: SARIF download,
// navigate to LLM logs, apply selective fix.

import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useLocation, useNavigate, useParams } from "react-router-dom";
import { scanService } from "../../shared/api/scanService";
import { useAuth } from "../../shared/hooks/useAuth";
import { isSafeHttpUrl } from "../../shared/lib/safeUrl";
import { isTerminalStatus } from "../../shared/lib/scanRoute";
import { displayStatus, statusKind } from "../../shared/lib/scanStatus";
import { Icon } from "../../shared/ui/Icon";
import { SevBar } from "../../shared/ui/DashboardPrimitives";
import { Modal } from "../../shared/ui/Modal";
import { PageHeader } from "../../shared/ui/PageHeader";
import { useToast } from "../../shared/ui/Toast";
import type {
  Finding,
  PrescanFindingItem,
  ScanResultResponse,
  SubmittedFile,
  SummaryReport,
} from "../../shared/types/api";

const PRESCAN_BLOCKED_STATUSES = new Set([
  "BLOCKED_USER_DECLINE",
  "BLOCKED_PRE_LLM",
]);

function normaliseSeverity(raw?: string | null): string {
  switch ((raw ?? "").toUpperCase()) {
    case "CRITICAL":
    case "ERROR":
      return "CRITICAL";
    case "HIGH":
      return "HIGH";
    case "WARNING":
    case "MEDIUM":
      return "MEDIUM";
    default:
      return "LOW";
  }
}

function prescanToFinding(item: PrescanFindingItem): Finding {
  return {
    id: item.id,
    file_path: item.file_path,
    title: item.title,
    cwe: item.cwe ?? "",
    description: item.description ?? "",
    severity: normaliseSeverity(item.severity),
    line_number: item.line_number ?? 0,
    remediation: "",
    confidence: "",
    source: item.source ?? undefined,
    references: [],
  };
}

type SeverityFilter = "all" | "critical" | "high" | "medium" | "low";

const SEV_COLOR: Record<string, string> = {
  CRITICAL: "var(--critical)",
  HIGH: "var(--high)",
  MEDIUM: "var(--medium)",
  LOW: "var(--low)",
  INFORMATIONAL: "var(--info)",
};

function flattenFindings(summary?: SummaryReport): Finding[] {
  if (!summary) return [];
  return summary.files_analyzed.flatMap((f: SubmittedFile) =>
    f.findings.map((finding) => ({ ...finding, file_path: f.file_path })),
  );
}

function severityRank(s: string): number {
  const order: Record<string, number> = {
    CRITICAL: 4,
    HIGH: 3,
    MEDIUM: 2,
    LOW: 1,
    INFORMATIONAL: 0,
  };
  return order[s?.toUpperCase()] ?? 0;
}

const ResultsPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const queryClient = useQueryClient();
  const toast = useToast();

  const [sevFilter, setSevFilter] = useState<SeverityFilter>("all");
  const [search, setSearch] = useState("");
  // Per-source filter chip — "all" or a specific scanner name like
  // "bandit" / "gitleaks" / "semgrep" / "osv" / "agent". Driven by
  // the by-source pill row below the summary card.
  const [sourceFilter, setSourceFilter] = useState<string>("all");
  const [selectedFindingId, setSelectedFindingId] = useState<number | null>(null);
  const [applyingId, setApplyingId] = useState<number | null>(null);
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [filePathFilter, setFilePathFilter] = useState<string | null>(null);
  const [diffTab, setDiffTab] = useState<"findings" | "full-diff">("findings");
  const [diffSelectedFile, setDiffSelectedFile] = useState<string | null>(null);
  const [treeCollapsed, setTreeCollapsed] = useState(false);
  const [listCollapsed, setListCollapsed] = useState(false);
  const { user } = useAuth();
  const isSuperuser = !!user?.is_superuser;

  const { data, isLoading, isError, error } = useQuery<ScanResultResponse>({
    queryKey: ["scan-result", scanId],
    queryFn: () => scanService.getScanResult(scanId!),
    enabled: !!scanId,
  });

  const isPrescanBlocked =
    !!data?.status && PRESCAN_BLOCKED_STATUSES.has(data.status);

  const { data: prescanData } = useQuery({
    queryKey: ["prescan-findings", scanId],
    queryFn: () => scanService.getPrescanReview(scanId!),
    enabled: !!scanId && isPrescanBlocked,
  });

  // If the scan isn't terminal yet (queued, running, or awaiting approval)
  // the live progress + approval UI lives on /analysis/scanning/:id. Bounce
  // there so deep-links from search/admin/back-button always end up where
  // the user can act on the scan.
  useEffect(() => {
    if (data?.status && scanId && !isTerminalStatus(data.status)) {
      navigate(`/analysis/scanning/${scanId}`, { replace: true });
    }
  }, [data?.status, scanId, navigate]);

  const applyFix = useMutation({
    mutationFn: (findingId: number) =>
      scanService.applySelectiveFixes(scanId!, [findingId]),
    onSuccess: () => {
      toast.success("Fix applied. Refreshing results…");
      queryClient.invalidateQueries({ queryKey: ["scan-result", scanId] });
    },
    onError: (err: Error) => toast.error(err.message || "Apply failed"),
  });

  const allFindings = useMemo(() => {
    const llmFindings = flattenFindings(data?.summary_report);
    // For scans stopped before the LLM phase (BLOCKED_USER_DECLINE /
    // BLOCKED_PRE_LLM), llmFindings is always empty. Show prescan findings
    // instead so the user can see what the deterministic scanners found.
    const base =
      llmFindings.length === 0 && isPrescanBlocked && prescanData?.findings
        ? prescanData.findings.map(prescanToFinding)
        : llmFindings;
    return base.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
  }, [data, isPrescanBlocked, prescanData]);

  const severityCounts = useMemo(() => {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFORMATIONAL: 0 };
    for (const f of allFindings) {
      const s = (f.severity || "").toUpperCase();
      if (s in counts) counts[s as keyof typeof counts] += 1;
    }
    return counts;
  }, [allFindings]);

  const fixesReady = useMemo(
    () => allFindings.filter((f) => !!f.fixes?.code).length,
    [allFindings],
  );

  // All submitted files — used by FileTree and the full-diff panel.
  const allFiles = useMemo<SubmittedFile[]>(() => {
    if (data?.summary_report?.files_analyzed?.length) {
      return data.summary_report.files_analyzed;
    }
    // Fallback for prescan-blocked scans: derive synthetic file list from findings
    if (isPrescanBlocked && prescanData?.findings) {
      const seen = new Set<string>();
      return prescanData.findings
        .filter((f) => f.file_path && !seen.has(f.file_path) && seen.add(f.file_path))
        .map((f) => ({ file_path: f.file_path, findings: [] }));
    }
    return [];
  }, [data, isPrescanBlocked, prescanData]);

  // Changed files between original and fixed code maps — for Full Diff tab.
  const changedFiles = useMemo<string[]>(() => {
    if (!data?.original_code_map || !data?.fixed_code_map) return [];
    return Object.keys(data.fixed_code_map).filter(
      (p) => data.fixed_code_map![p] !== (data.original_code_map?.[p] ?? ""),
    );
  }, [data]);

  const filtered = useMemo(
    () =>
      allFindings.filter((f) => {
        if (sevFilter !== "all" && f.severity?.toLowerCase() !== sevFilter)
          return false;
        if (sourceFilter !== "all") {
          // Backend persists NULL `source` for legacy LLM-emitted rows
          // and the source_counts aggregate buckets those under "agent",
          // so the chip with `source=agent` should match findings with
          // a missing source field.
          const fSource = f.source ?? "agent";
          if (fSource !== sourceFilter) return false;
        }
        if (filePathFilter) {
          // Folder filter: prefix match; file filter: exact match
          if (
            f.file_path !== filePathFilter &&
            !f.file_path.startsWith(filePathFilter)
          )
            return false;
        }
        if (
          search &&
          !(
            f.title.toLowerCase().includes(search.toLowerCase()) ||
            f.file_path.toLowerCase().includes(search.toLowerCase()) ||
            (f.cwe || "").toLowerCase().includes(search.toLowerCase())
          )
        )
          return false;
        return true;
      }),
    [allFindings, sevFilter, sourceFilter, filePathFilter, search],
  );

  const selected =
    filtered.find((f) => f.id === selectedFindingId) ?? filtered[0] ?? null;

  // Prefer the always-present top-level project pointers (backend
  // populates these from the Scan row even when `summary_report` is
  // null because the scan never reached report-generation — e.g. a
  // CANCELLED scan the user opened from the project page). Fall back
  // to the report's copy for older API payloads served from cache.
  const projectId = data?.project_id ?? data?.summary_report?.project_id;
  const projectName =
    data?.project_name ?? data?.summary_report?.project_name;

  const handleDelete = useCallback(async () => {
    if (!scanId) return;
    setDeleting(true);
    try {
      await scanService.deleteScan(scanId);
      toast.info("Scan deleted.");
      queryClient.invalidateQueries({ queryKey: ["project-scans", projectId] });
      queryClient.invalidateQueries({ queryKey: ["projects"] });
      if (projectId) {
        navigate(`/analysis/projects/${projectId}`, {
          state: projectName ? { projectName } : undefined,
        });
      } else {
        navigate("/analysis/results");
      }
    } catch (err) {
      const e = err as { message?: string };
      toast.error(e.message || "Failed to delete scan");
    } finally {
      setDeleting(false);
      setDeleteConfirmOpen(false);
    }
  }, [scanId, projectId, projectName, navigate, queryClient, toast]);


  if (isLoading) {
    return (
      <div
        className="sccap-card"
        style={{
          padding: 40,
          textAlign: "center",
          color: "var(--fg-muted)",
        }}
      >
        Loading scan results…
      </div>
    );
  }

  if (isError || !data) {
    return (
      <div
        className="sccap-card"
        style={{
          padding: 40,
          textAlign: "center",
          color: "var(--critical)",
        }}
      >
        Failed to load scan: {(error as Error)?.message || "unknown error"}
      </div>
    );
  }

  const report = data.summary_report;
  const riskScore = report?.overall_risk_score?.score;
  const riskLabel = typeof riskScore === "number" ? riskScore : riskScore || "—";

  // Navigate back to the project this scan belongs to. Prefers the
  // top-level pointers (always present), falls back to the summary
  // report (also fine on completed scans). When neither is known
  // (extremely-early failure), bounces to the projects index.
  const goToProject = () => {
    if (projectId) {
      navigate(`/analysis/projects/${projectId}`, {
        state: projectName ? { projectName } : undefined,
      });
    } else {
      navigate("/analysis/results");
    }
  };
  // Display name for the project — prefer the top-level field over the
  // report copy so an in-progress / cancelled scan still shows it.
  const displayProjectName =
    projectName ?? report?.project_name ?? null;

  return (
    <div className="fade-in" style={{ display: "grid", gap: 16 }}>
      {/* header */}
      <PageHeader
        crumbs={(() => {
          const fromLabel = (location.state as Record<string, unknown>)
            ?.fromLabel as string | undefined;
          const fromPath = (location.state as Record<string, unknown>)
            ?.fromPath as string | undefined;
          if (fromLabel) {
            return [
              {
                label: fromLabel,
                to: fromPath,
                onClick: !fromPath ? () => navigate(-1) : undefined,
              },
              { label: scanId?.slice(0, 12) ?? "…" },
            ];
          }
          return [
            { label: "Projects", to: "/analysis/results" },
            {
              label: displayProjectName ?? "…",
              onClick: goToProject,
            },
            { label: scanId?.slice(0, 12) ?? "…" },
          ];
        })()}
        title={
          <>
            {displayProjectName ?? "Scan"}{" "}
            <span
              style={{
                color: "var(--fg-subtle)",
                fontWeight: 400,
                fontSize: 20,
              }}
            >
              / {report?.scan_type ?? data.status}
            </span>
          </>
        }
        subtitle={
          <>
            {(() => {
              // Single-source-of-truth status chip. `failed` (real
              // error) is the only one that goes red; user stops
              // (CANCELLED, BLOCKED_USER_DECLINE) and EXPIRED are
              // neutral; BLOCKED_PRE_LLM is amber/warn.
              const kind = statusKind(data.status);
              if (kind === "failed") {
                return (
                  <span className="chip chip-critical">
                    {displayStatus(data.status)}
                  </span>
                );
              }
              if (kind === "blocked") {
                return (
                  <span className="chip chip-warn">
                    {displayStatus(data.status)}
                  </span>
                );
              }
              if (kind === "stopped" || kind === "expired") {
                return (
                  <span className="chip">{displayStatus(data.status)}</span>
                );
              }
              return null;
            })()}
            <span>
              {allFindings.length} finding
              {allFindings.length === 1 ? "" : "s"}
            </span>
            {fixesReady > 0 && (
              <span className="chip chip-ai">
                <Icon.Sparkle size={10} /> {fixesReady} AI fix
                {fixesReady === 1 ? "" : "es"} ready
              </span>
            )}
            {report?.selected_frameworks?.length ? (
              <span style={{ color: "var(--fg-subtle)" }}>
                · {report.selected_frameworks.join(", ")}
              </span>
            ) : null}
          </>
        }
        actions={
          <>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={() => navigate(`/analysis/scanning/${scanId}`)}
              title="View the scan event timeline"
            >
              <Icon.Clock size={13} /> Timeline
            </button>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={() => navigate(`/scans/${scanId}/llm-logs`)}
            >
              <Icon.Terminal size={13} /> LLM logs
            </button>
            {isSuperuser && (
              <button
                className="sccap-btn sccap-btn-sm"
                onClick={() => setDeleteConfirmOpen(true)}
                disabled={deleting}
                style={{ color: "var(--critical)" }}
              >
                <Icon.Alert size={13} /> {deleting ? "Deleting…" : "Delete"}
              </button>
            )}
          </>
        }
      />

      {/* summary strip */}
      <div
        className="surface"
        style={{
          padding: 16,
          display: "grid",
          gridTemplateColumns: "1.5fr repeat(5, 1fr)",
          gap: 16,
          alignItems: "center",
        }}
      >
        <div>
          <div
            style={{
              fontSize: 11,
              color: "var(--fg-muted)",
              textTransform: "uppercase",
              letterSpacing: ".06em",
            }}
          >
            Risk score
          </div>
          <div
            style={{
              display: "flex",
              alignItems: "baseline",
              gap: 10,
              marginTop: 4,
            }}
          >
            <div
              style={{
                fontSize: 28,
                fontWeight: 600,
                color:
                  typeof riskScore === "number"
                    ? riskScore >= 7
                      ? "var(--critical)"
                      : riskScore >= 4
                        ? "var(--high)"
                        : "var(--medium)"
                    : "var(--fg)",
                letterSpacing: "-0.02em",
              }}
            >
              {riskLabel}
            </div>
          </div>
          <div style={{ marginTop: 6 }}>
            <SevBar
              crit={severityCounts.CRITICAL}
              high={severityCounts.HIGH}
              med={severityCounts.MEDIUM}
              low={severityCounts.LOW}
              info={severityCounts.INFORMATIONAL}
            />
          </div>
        </div>
        {[
          { k: "Critical", v: severityCounts.CRITICAL, c: "var(--critical)" },
          { k: "High", v: severityCounts.HIGH, c: "var(--high)" },
          { k: "Medium", v: severityCounts.MEDIUM, c: "var(--medium)" },
          { k: "Low", v: severityCounts.LOW, c: "var(--low)" },
          { k: "AI fixes", v: fixesReady, c: "var(--primary)" },
        ].map((m) => (
          <div key={m.k}>
            <div
              style={{
                fontSize: 11,
                color: "var(--fg-muted)",
                textTransform: "uppercase",
                letterSpacing: ".06em",
              }}
            >
              {m.k}
            </div>
            <div
              style={{
                fontSize: 28,
                fontWeight: 600,
                color: m.c,
                letterSpacing: "-0.02em",
              }}
            >
              {m.v}
            </div>
          </div>
        ))}
      </div>

      {/* Per-source filter row. Pills are buttons that filter the
          findings list to that single source. The leading "All" pill
          clears the filter; a "Clear" affordance appears once a
          specific source is selected so the active state is unambiguous.
          The aggregate counts come from the backend's `source_counts`
          (sast-prescan-followups Group D2) so they include findings
          excluded by the current sevFilter / search box. */}
      {data.source_counts && Object.keys(data.source_counts).length > 0 && (
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: 8,
            marginTop: 8,
            marginBottom: 8,
            alignItems: "center",
          }}
        >
          <span
            style={{
              fontSize: 11,
              color: "var(--fg-muted)",
              textTransform: "uppercase",
              letterSpacing: ".06em",
            }}
          >
            By source:
          </span>
          {(() => {
            const sourceColor: Record<string, string> = {
              bandit: "#3b82f6",
              semgrep: "#a855f7",
              gitleaks: "#dc2626",
              osv: "#0891b2",
              agent: "#6b7280",
            };
            const totalFindings = Object.values(data.source_counts).reduce(
              (sum, n) => sum + n,
              0,
            );
            // Reusable pill-button. Active = colored background + white
            // text. Inactive = transparent background + colored border +
            // colored text, with a subtle hover lift.
            const renderPill = (
              key: string,
              label: string,
              count: number,
              color: string,
              active: boolean,
              onClick: () => void,
              ariaLabel: string,
            ) => (
              <button
                key={key}
                type="button"
                onClick={onClick}
                aria-pressed={active}
                aria-label={ariaLabel}
                style={{
                  padding: "4px 10px",
                  borderRadius: 12,
                  border: `1px solid ${color}`,
                  background: active ? color : "transparent",
                  color: active ? "white" : color,
                  fontSize: 12,
                  fontWeight: 600,
                  cursor: "pointer",
                  transition: "all .12s var(--ease)",
                  fontFamily: "inherit",
                }}
              >
                {label}: {count}
              </button>
            );
            const pills: React.ReactNode[] = [];
            // Leading "All" pill — neutral grey. Active state when
            // no source filter is currently applied.
            pills.push(
              renderPill(
                "__all__",
                "all",
                totalFindings,
                "#6b7280",
                sourceFilter === "all",
                () => setSourceFilter("all"),
                "Show findings from every source",
              ),
            );
            for (const [source, count] of Object.entries(data.source_counts)) {
              pills.push(
                renderPill(
                  source,
                  source,
                  count,
                  sourceColor[source] || "#6b7280",
                  sourceFilter === source,
                  () =>
                    setSourceFilter((prev) =>
                      prev === source ? "all" : source,
                    ),
                  `Show only findings from ${source}`,
                ),
              );
            }
            return pills;
          })()}
          {sourceFilter !== "all" && (
            <button
              type="button"
              onClick={() => setSourceFilter("all")}
              className="sccap-btn sccap-btn-sm sccap-btn-ghost"
              style={{ marginLeft: 4 }}
              aria-label="Clear source filter"
            >
              <Icon.X size={11} /> Clear filter
            </button>
          )}
        </div>
      )}

      {/* Prescan-only banner — shown when scan was stopped before LLM phase */}
      {isPrescanBlocked && allFindings.length > 0 && (
        <div
          className="sccap-card"
          style={{
            background: "var(--info-weak)",
            borderColor: "var(--info)",
            padding: "10px 14px",
            fontSize: 12.5,
            color: "var(--fg-muted)",
            display: "flex",
            alignItems: "center",
            gap: 8,
          }}
        >
          <Icon.Alert size={13} style={{ color: "var(--info)", flexShrink: 0 }} />
          <span>
            These are deterministic pre-scan findings (Bandit, Semgrep, Gitleaks, OSV).
            The scan was stopped before LLM analysis — no AI-generated findings or
            fixes are available. Review and fix these issues, then re-submit.
          </span>
        </div>
      )}

      {/* Tab bar — only shown for REMEDIATE scans that have a full diff */}
      {data.summary_report?.scan_type === "REMEDIATE" && changedFiles.length > 0 && (
        <div className="sccap-tabs" style={{ marginBottom: -1 }}>
          <button
            className={`sccap-tab${diffTab === "findings" ? " active" : ""}`}
            onClick={() => setDiffTab("findings")}
          >
            Findings
          </button>
          <button
            className={`sccap-tab${diffTab === "full-diff" ? " active" : ""}`}
            onClick={() => setDiffTab("full-diff")}
          >
            Full Remediation Diff
            <span className="count">{changedFiles.length}</span>
          </button>
        </div>
      )}

      {diffTab === "full-diff" && changedFiles.length > 0 ? (
        <RemediationDiffPanel
          changedFiles={changedFiles}
          originalCodeMap={data.original_code_map ?? {}}
          fixedCodeMap={data.fixed_code_map ?? {}}
          findingsByFile={Object.fromEntries(
            allFiles.map((f) => [f.file_path, f.findings ?? []])
          )}
          selectedFile={diffSelectedFile}
          onSelectFile={setDiffSelectedFile}
        />
      ) : (
      <div
        style={{
          display: "grid",
          gridTemplateColumns: [
            allFiles.length > 0 ? (treeCollapsed ? "32px" : "220px") : null,
            listCollapsed ? "32px" : "360px",
            "1fr",
          ].filter(Boolean).join(" "),
          gap: 16,
          minHeight: 640,
          alignItems: "start",
        }}
      >
        {/* File tree — collapsible */}
        {allFiles.length > 0 && (
          treeCollapsed ? (
            <div
              className="surface"
              style={{ padding: 0, display: "flex", flexDirection: "column", alignItems: "center", overflow: "hidden", position: "sticky", top: 16 }}
            >
              <button
                className="sccap-btn sccap-btn-ghost sccap-btn-icon"
                onClick={() => setTreeCollapsed(false)}
                title="Expand file tree"
                style={{ width: "100%", borderRadius: 0, borderBottom: "1px solid var(--border)", padding: "8px 0" }}
              >
                <Icon.ChevronR size={13} />
              </button>
              <div style={{ writingMode: "vertical-rl", fontSize: 10.5, color: "var(--fg-subtle)", padding: "10px 0", letterSpacing: ".06em", textTransform: "uppercase", userSelect: "none" }}>
                Files
              </div>
            </div>
          ) : (
            <div style={{ position: "relative" }}>
              <FileTree
                files={allFiles}
                allFindings={allFindings}
                selected={filePathFilter}
                onSelect={setFilePathFilter}
                onCollapse={() => setTreeCollapsed(true)}
              />
            </div>
          )
        )}
        {/* Findings list — collapsible */}
        <div
          className="surface"
          style={{
            padding: 0,
            display: "flex",
            flexDirection: "column",
            overflow: "hidden",
          }}
        >
        {listCollapsed ? (
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", height: "100%", minHeight: 320 }}>
            <button
              className="sccap-btn sccap-btn-ghost sccap-btn-icon"
              onClick={() => setListCollapsed(false)}
              title="Expand findings list"
              style={{ width: "100%", borderRadius: 0, borderBottom: "1px solid var(--border)", padding: "8px 0" }}
            >
              <Icon.ChevronR size={13} />
            </button>
            <div style={{ writingMode: "vertical-rl", fontSize: 10.5, color: "var(--fg-subtle)", padding: "10px 0", letterSpacing: ".06em", textTransform: "uppercase", userSelect: "none" }}>
              Findings ({filtered.length})
            </div>
          </div>
        ) : (
        <>
          <div
            style={{
              padding: 12,
              borderBottom: "1px solid var(--border)",
              display: "grid",
              gap: 8,
            }}
          >
            {/* Collapse button row */}
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
              <span style={{ fontSize: 11, color: "var(--fg-muted)", fontWeight: 500 }}>
                {filtered.length} finding{filtered.length === 1 ? "" : "s"}
              </span>
              <button
                className="sccap-btn sccap-btn-ghost sccap-btn-icon"
                onClick={() => setListCollapsed(true)}
                title="Collapse findings list"
                style={{ padding: "3px 5px" }}
              >
                <Icon.ChevronL size={12} />
              </button>
            </div>
            <div className="input-with-icon">
              <Icon.Search size={14} />
              <input
                className="sccap-input"
                placeholder="Filter findings…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                style={{ paddingLeft: 32, height: 32 }}
              />
            </div>
            <div className="radio-group" style={{ width: "100%" }}>
              {(
                ["all", "critical", "high", "medium", "low"] as SeverityFilter[]
              ).map((s) => (
                <button
                  key={s}
                  className={sevFilter === s ? "active" : ""}
                  onClick={() => setSevFilter(s)}
                  style={{ flex: 1, textTransform: "capitalize" }}
                >
                  {s}
                  {s !== "all" && (
                    <span style={{ color: "var(--fg-subtle)", marginLeft: 4 }}>
                      ·
                      {
                        allFindings.filter(
                          (f) => f.severity?.toLowerCase() === s,
                        ).length
                      }
                    </span>
                  )}
                </button>
              ))}
            </div>
          </div>
          <div style={{ flex: 1, overflow: "auto" }}>
            {filtered.length === 0 ? (
              <div
                style={{
                  padding: 40,
                  textAlign: "center",
                  color: "var(--fg-muted)",
                }}
              >
                No findings match this filter.
              </div>
            ) : (
              filtered.map((f) => {
                const sev = (f.severity || "").toUpperCase();
                const color = SEV_COLOR[sev] ?? "var(--fg-muted)";
                const isSel = selected?.id === f.id;
                return (
                  <div
                    key={f.id}
                    onClick={() => setSelectedFindingId(f.id)}
                    style={{
                      padding: "12px 14px",
                      cursor: "pointer",
                      borderLeft: `3px solid ${isSel ? color : "transparent"}`,
                      background: isSel ? "var(--bg-soft)" : "transparent",
                      borderBottom: "1px solid var(--border)",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 6,
                        marginBottom: 4,
                      }}
                    >
                      <span
                        style={{
                          width: 6,
                          height: 6,
                          borderRadius: 99,
                          background: color,
                        }}
                      />
                      <span
                        style={{
                          fontSize: 10.5,
                          textTransform: "uppercase",
                          color,
                          fontWeight: 600,
                          letterSpacing: ".04em",
                        }}
                      >
                        {sev}
                      </span>
                      <span
                        style={{
                          fontSize: 10.5,
                          color: "var(--fg-subtle)",
                          marginLeft: "auto",
                        }}
                        className="mono"
                      >
                        {f.cwe}
                      </span>
                    </div>
                    <div
                      style={{
                        fontSize: 13,
                        fontWeight: 500,
                        lineHeight: 1.35,
                        marginBottom: 6,
                        color: "var(--fg)",
                      }}
                    >
                      {f.title}
                    </div>
                    <div
                      style={{
                        fontSize: 11,
                        color: "var(--fg-muted)",
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        gap: 8,
                      }}
                    >
                      <span
                        className="mono"
                        style={{
                          fontSize: 11,
                          whiteSpace: "nowrap",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          maxWidth: 200,
                        }}
                      >
                        {f.file_path}:{f.line_number}
                      </span>
                      {f.fixes?.code && (
                        <span
                          className="chip chip-ai"
                          style={{ fontSize: 10, padding: "1px 7px" }}
                        >
                          <Icon.Sparkle size={9} /> fix
                        </span>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </>
        )}
        </div>

        {/* detail */}
        {selected ? (
          <FindingDetail
            f={selected}
            applying={applyingId === selected.id && applyFix.isPending}
            onApply={() => {
              setApplyingId(selected.id);
              applyFix.mutate(selected.id);
            }}
            originalCodeMap={data?.original_code_map ?? undefined}
          />
        ) : (
          <div
            className="surface"
            style={{
              padding: 40,
              textAlign: "center",
              color: "var(--fg-muted)",
              alignSelf: "start",
            }}
          >
            {allFindings.length === 0
              ? "No findings in this scan."
              : "Select a finding on the left."}
          </div>
        )}
      </div>
      )}

      <Modal
        open={deleteConfirmOpen}
        onClose={() => (deleting ? undefined : setDeleteConfirmOpen(false))}
        title="Delete this scan permanently?"
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
              onClick={handleDelete}
              disabled={deleting}
              style={{ background: "var(--critical)" }}
            >
              {deleting ? "Deleting…" : "Delete scan"}
            </button>
          </>
        }
      >
        <div style={{ color: "var(--fg)", fontSize: 13.5, lineHeight: 1.55 }}>
          This removes the scan, its findings, and event log from the
          database. The action cannot be undone.
        </div>
      </Modal>
    </div>
  );
};

// ============================================================================
// Diff engine
// ============================================================================

type DiffType = "ctx" | "del" | "ins";
interface RawDiffLine {
  type: DiffType;
  oldNum: number | null;
  newNum: number | null;
  text: string;
}

function computeLineDiff(before: string[], after: string[]): RawDiffLine[] {
  const m = before.length, n = after.length;
  // Build LCS table bottom-up (O(mn) — fine for typical fix sizes)
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = m - 1; i >= 0; i--)
    for (let j = n - 1; j >= 0; j--)
      dp[i][j] = before[i] === after[j]
        ? 1 + dp[i + 1][j + 1]
        : Math.max(dp[i + 1][j], dp[i][j + 1]);

  const out: RawDiffLine[] = [];
  let i = 0, j = 0, o = 1, nv = 1;
  while (i < m || j < n) {
    if (i < m && j < n && before[i] === after[j]) {
      out.push({ type: "ctx", oldNum: o++, newNum: nv++, text: before[i] });
      i++; j++;
    } else if (j < n && (i >= m || dp[i + 1][j] <= dp[i][j + 1])) {
      out.push({ type: "ins", oldNum: null, newNum: nv++, text: after[j++] });
    } else {
      out.push({ type: "del", oldNum: o++, newNum: null, text: before[i++] });
    }
  }
  return out;
}

type CharChunk = { text: string; changed: boolean };

// Find the common prefix/suffix to isolate the changed middle span
function charDiff(a: string, b: string): { aChunks: CharChunk[]; bChunks: CharChunk[] } {
  const aT = a.trimStart(), bT = b.trimStart();
  let pre = 0;
  while (pre < aT.length && pre < bT.length && aT[pre] === bT[pre]) pre++;
  let suf = 0;
  while (
    suf < aT.length - pre && suf < bT.length - pre &&
    aT[aT.length - 1 - suf] === bT[bT.length - 1 - suf]
  ) suf++;
  const split = (_s: string, src: string): CharChunk[] => {
    const indent = src.length - src.trimStart().length;
    return ([
      { text: src.slice(0, indent + pre), changed: false },
      { text: suf > 0 ? src.slice(indent + pre, -suf) : src.slice(indent + pre), changed: true },
      { text: suf > 0 ? src.slice(-suf) : "", changed: false },
    ] as CharChunk[]).filter(c => c.text.length > 0);
  };
  return { aChunks: split(aT, a), bChunks: split(bT, b) };
}

// ============================================================================
// DiffViewer — side-by-side split view
// ============================================================================

const CONTEXT_LINES = 3;

interface SplitSide {
  lineNum: number;
  text: string;
  chunks: CharChunk[] | null;
}
interface SplitRow {
  type: "ctx" | "change" | "hunk";
  left: SplitSide | null;
  right: SplitSide | null;
  hunkCount?: number;
}

function buildSplitView(before: string[], after: string[]): SplitRow[] {
  const raw = computeLineDiff(before, after);
  const allRows: SplitRow[] = [];
  let i = 0;
  while (i < raw.length) {
    if (raw[i].type === "ctx") {
      const l = raw[i];
      allRows.push({ type: "ctx", left: { lineNum: l.oldNum!, text: l.text, chunks: null }, right: { lineNum: l.newNum!, text: l.text, chunks: null } });
      i++;
    } else {
      const dels: RawDiffLine[] = [], ins: RawDiffLine[] = [];
      while (i < raw.length && raw[i].type !== "ctx") {
        if (raw[i].type === "del") dels.push(raw[i]); else ins.push(raw[i]);
        i++;
      }
      const count = Math.max(dels.length, ins.length);
      for (let k = 0; k < count; k++) {
        const d = dels[k] ?? null, n = ins[k] ?? null;
        let dChunks: CharChunk[] | null = null, nChunks: CharChunk[] | null = null;
        if (d && n) {
          const { aChunks, bChunks } = charDiff(d.text, n.text);
          if (aChunks.some(c => !c.changed && c.text.trim().length > 0)) { dChunks = aChunks; nChunks = bChunks; }
        }
        allRows.push({ type: "change", left: d ? { lineNum: d.oldNum!, text: d.text, chunks: dChunks } : null, right: n ? { lineNum: n.newNum!, text: n.text, chunks: nChunks } : null });
      }
    }
  }
  const near = new Set<number>();
  for (let k = 0; k < allRows.length; k++)
    if (allRows[k].type === "change")
      for (let d = -CONTEXT_LINES; d <= CONTEXT_LINES; d++)
        if (k + d >= 0 && k + d < allRows.length) near.add(k + d);
  const result: SplitRow[] = [];
  let skipping = 0;
  for (let k = 0; k < allRows.length; k++) {
    if (near.has(k)) { if (skipping > 0) { result.push({ type: "hunk", left: null, right: null, hunkCount: skipping }); skipping = 0; } result.push(allRows[k]); }
    else skipping++;
  }
  if (skipping > 0) result.push({ type: "hunk", left: null, right: null, hunkCount: skipping });
  return result;
}

const DiffViewer: React.FC<{
  original: string;
  fixed: string;
  startLine: number;
  filePath: string;
  maxHeight?: number | string;
}> = ({ original, fixed, startLine, filePath, maxHeight = 480 }) => {
  const trimLines = (s: string) => { const ls = s.split("\n"); if (ls[ls.length - 1] === "") ls.pop(); return ls; };
  const before = trimLines(original || "");
  const after  = trimLines(fixed   || "");

  // eslint-disable-next-line react-hooks/exhaustive-deps
  const splitRows = useMemo(() => buildSplitView(before, after), [original, fixed]);
  const base = startLine - 1;

  const renderChunks = (side: SplitSide) => {
    if (!side.chunks) return side.text || " ";
    return side.chunks.map((c, i) =>
      c.changed ? <mark key={i} className="diff-hl">{c.text}</mark> : <React.Fragment key={i}>{c.text}</React.Fragment>
    );
  };

  const renderCell = (side: SplitSide | null, cls: "del" | "ins" | "ctx" | "empty") => {
    if (cls === "empty" || !side) return <div className="diff-cell empty" />;
    return (
      <div className={`diff-cell ${cls}`}>
        <span className="diff-ln">{base + side.lineNum}</span>
        <span className="diff-code">{renderChunks(side)}</span>
      </div>
    );
  };

  return (
    <div className="diff" style={{ maxHeight, overflowY: "auto" }}>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1px 1fr", background: "var(--bg-soft)", borderBottom: "1px solid var(--border)", fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--fg-muted)" }}>
        <div style={{ padding: "7px 12px", display: "flex", alignItems: "center", gap: 6 }}>
          <span style={{ color: "var(--critical)", fontWeight: 700 }}>−</span>
          <span>before · <span style={{ color: "var(--fg)" }}>{filePath}</span></span>
        </div>
        <div style={{ background: "var(--border)" }} />
        <div style={{ padding: "7px 12px", display: "flex", alignItems: "center", gap: 6 }}>
          <span style={{ color: "var(--success)", fontWeight: 700 }}>+</span>
          <span>after · <span style={{ color: "var(--fg)" }}>{filePath}</span></span>
        </div>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1px 1fr" }}>
        {splitRows.map((row, idx) => {
          if (row.type === "hunk") {
            return <div key={idx} className="diff-hunk" style={{ gridColumn: "1 / -1" }}>···  {row.hunkCount} unchanged line{row.hunkCount === 1 ? "" : "s"}  ···</div>;
          }
          const isCtx = row.type === "ctx";
          return (
            <React.Fragment key={idx}>
              {renderCell(row.left,  isCtx ? "ctx" : row.left  ? "del" : "empty")}
              <div style={{ background: "var(--border)" }} />
              {renderCell(row.right, isCtx ? "ctx" : row.right ? "ins" : "empty")}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
};


// ============================================================================
// Detail pane
// ============================================================================

const FindingDetail: React.FC<{
  f: Finding;
  applying: boolean;
  onApply: () => void;
  originalCodeMap?: Record<string, string>;
}> = ({ f, applying, onApply, originalCodeMap }) => {
  const sev = (f.severity || "").toUpperCase();
  const sevColor = SEV_COLOR[sev] ?? "var(--fg-muted)";
  const hasFix = !!f.fixes?.code;
  const alreadyApplied = f.is_applied_in_remediation;
  const fileContent = originalCodeMap?.[f.file_path] ?? null;

  return (
    <div
      className="surface"
      style={{ padding: 24, overflow: "auto", alignSelf: "start" }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-start",
          gap: 16,
          marginBottom: 12,
        }}
      >
        <div style={{ flex: 1 }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              marginBottom: 8,
              flexWrap: "wrap",
            }}
          >
            <span className={"chip chip-" + sev.toLowerCase()}>
              <Icon.Alert size={10} /> {sev}
            </span>
            {f.cwe && (
              <span className="chip mono" style={{ fontSize: 10.5 }}>
                {f.cwe}
              </span>
            )}
            {typeof f.cvss_score === "number" && (
              <span
                className="chip"
                style={{
                  background: sevColor + "22",
                  color: sevColor,
                  border: "none",
                }}
              >
                CVSS {f.cvss_score.toFixed(1)}
              </span>
            )}
            {f.confidence && (
              <span className="chip" style={{ fontSize: 10.5 }}>
                {f.confidence} confidence
              </span>
            )}
          </div>
          <h2 style={{ marginBottom: 8, color: "var(--fg)" }}>{f.title}</h2>
          <div style={{ fontSize: 12.5, color: "var(--fg-muted)" }}>
            <span className="mono">{f.file_path}</span> · line{" "}
            <span className="mono">{f.line_number}</span>
            {f.corroborating_agents && f.corroborating_agents.length > 0 && (
              <>
                <span style={{ margin: "0 8px" }}>·</span>
                Corroborated by{" "}
                {f.corroborating_agents.map((a, i) => (
                  <span
                    key={i}
                    className="chip"
                    style={{
                      fontSize: 10,
                      padding: "1px 7px",
                      marginLeft: 4,
                    }}
                  >
                    {a}
                  </span>
                ))}
              </>
            )}
          </div>
        </div>
      </div>

      <div className="sccap-divider" />

      {/* Code snippet — shown for all findings that have source code available */}
      {(fileContent || f.fixes?.original_snippet) && (
        <div style={{ marginBottom: 18 }}>
          <CodeSnippet
            fileContent={fileContent}
            snippet={f.fixes?.original_snippet ?? null}
            lineNumber={f.line_number ?? 0}
            filePath={f.file_path}
            severityColor={sevColor}
          />
        </div>
      )}

      <div style={{ display: "grid", gap: 18 }}>
        {f.description && (
          <div>
            <h4
              style={{
                marginBottom: 6,
                color: "var(--fg-muted)",
                fontSize: 11,
                textTransform: "uppercase",
                letterSpacing: ".06em",
              }}
            >
              Description
            </h4>
            <div
              style={{
                fontSize: 13.5,
                lineHeight: 1.6,
                color: "var(--fg)",
                whiteSpace: "pre-wrap",
              }}
            >
              {f.description}
            </div>
          </div>
        )}

        {f.remediation && (
          <div>
            <h4
              style={{
                marginBottom: 6,
                color: "var(--fg-muted)",
                fontSize: 11,
                textTransform: "uppercase",
                letterSpacing: ".06em",
              }}
            >
              Remediation
            </h4>
            <div
              style={{
                fontSize: 13.5,
                lineHeight: 1.6,
                color: "var(--fg)",
                whiteSpace: "pre-wrap",
              }}
            >
              {f.remediation}
            </div>
          </div>
        )}

        {hasFix && (
          <div>
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                marginBottom: 10,
                flexWrap: "wrap",
                gap: 8,
              }}
            >
              <h4
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  color: "var(--fg)",
                  margin: 0,
                }}
              >
                <div
                  style={{
                    width: 20,
                    height: 20,
                    borderRadius: 5,
                    background: "var(--primary)",
                    color: "var(--primary-ink)",
                    display: "grid",
                    placeItems: "center",
                  }}
                >
                  <Icon.Sparkle size={11} />
                </div>
                AI-suggested fix
              </h4>
              <div style={{ display: "flex", gap: 6 }}>
                <button
                  className="sccap-btn sccap-btn-sm sccap-btn-primary"
                  onClick={onApply}
                  disabled={applying || alreadyApplied}
                >
                  {alreadyApplied ? (
                    <>
                      <Icon.Check size={12} /> Applied
                    </>
                  ) : applying ? (
                    "Applying…"
                  ) : (
                    <>
                      <Icon.Zap size={12} /> Apply fix
                    </>
                  )}
                </button>
              </div>
            </div>

            {f.fixes?.description && (
              <div
                style={{
                  background: "var(--primary-weak)",
                  borderRadius: 8,
                  padding: "10px 12px",
                  marginBottom: 10,
                  fontSize: 12.5,
                  color: "var(--fg)",
                  display: "flex",
                  gap: 10,
                  alignItems: "flex-start",
                }}
              >
                <Icon.Sparkle size={14} color="var(--primary)" />
                <div>
                  <b>Why this fix:</b> {f.fixes.description}
                </div>
              </div>
            )}

            <DiffViewer
              original={f.fixes?.original_snippet ?? ""}
              fixed={f.fixes?.code ?? ""}
              startLine={f.line_number ?? 1}
              filePath={f.file_path}
            />
          </div>
        )}

        {f.references && f.references.length > 0 && (
          <div>
            <h4
              style={{
                marginBottom: 8,
                color: "var(--fg-muted)",
                fontSize: 11,
                textTransform: "uppercase",
                letterSpacing: ".06em",
              }}
            >
              References
            </h4>
            <div style={{ display: "grid", gap: 4 }}>
              {f.references.map((r, i) =>
                isSafeHttpUrl(r) ? (
                  <a
                    key={i}
                    href={r}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{
                      color: "var(--primary)",
                      fontSize: 12.5,
                      wordBreak: "break-all",
                    }}
                  >
                    <Icon.Link size={11} /> {r}
                  </a>
                ) : (
                  // Reference came in with a non-http(s) scheme (e.g.
                  // `javascript:` from a tampered upstream advisory) —
                  // render as plain text instead of a clickable link.
                  <span
                    key={i}
                    title="Unsafe URL scheme — rendered as plain text"
                    style={{
                      color: "var(--fg-muted)",
                      fontSize: 12.5,
                      wordBreak: "break-all",
                    }}
                  >
                    <Icon.Link size={11} /> {r}
                  </span>
                ),
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

// ============================================================================
// File tree
// ============================================================================

interface FileTreeNode {
  name: string;
  fullPath: string;
  isLeaf: boolean;
  maxSeverity: string; // "" = no findings
  findingCount: number;
  children: FileTreeNode[];
}

function buildFileTree(files: SubmittedFile[], allFindings: Finding[]): FileTreeNode {
  // Count findings per file path
  const countByPath: Record<string, number> = {};
  const sevByPath: Record<string, string> = {};
  for (const f of allFindings) {
    countByPath[f.file_path] = (countByPath[f.file_path] ?? 0) + 1;
    const cur = sevByPath[f.file_path];
    if (!cur || severityRank(f.severity) > severityRank(cur)) {
      sevByPath[f.file_path] = f.severity?.toUpperCase() ?? "";
    }
  }

  const root: FileTreeNode = { name: "", fullPath: "", isLeaf: false, maxSeverity: "", findingCount: 0, children: [] };

  for (const file of files) {
    const parts = file.file_path.split("/").filter(Boolean);
    let node = root;
    let prefix = "";
    for (let i = 0; i < parts.length; i++) {
      prefix = prefix ? `${prefix}/${parts[i]}` : parts[i];
      const isLeaf = i === parts.length - 1;
      let child = node.children.find((c) => c.name === parts[i]);
      if (!child) {
        child = { name: parts[i], fullPath: prefix, isLeaf, maxSeverity: "", findingCount: 0, children: [] };
        node.children.push(child);
      }
      if (isLeaf) {
        child.findingCount = countByPath[file.file_path] ?? 0;
        child.maxSeverity = sevByPath[file.file_path] ?? "";
      }
      node = child;
    }
  }

  // Propagate severity and counts upward
  function propagate(n: FileTreeNode): void {
    for (const c of n.children) propagate(c);
    if (!n.isLeaf) {
      n.findingCount = n.children.reduce((s, c) => s + c.findingCount, 0);
      let best = "";
      for (const c of n.children) {
        if (severityRank(c.maxSeverity) > severityRank(best)) best = c.maxSeverity;
      }
      n.maxSeverity = best;
    }
  }
  propagate(root);

  // Sort: folders first, then files; within each group alphabetically
  function sortNode(n: FileTreeNode): void {
    n.children.sort((a, b) => {
      if (a.isLeaf !== b.isLeaf) return a.isLeaf ? 1 : -1;
      return a.name.localeCompare(b.name);
    });
    for (const c of n.children) sortNode(c);
  }
  sortNode(root);

  return root;
}

const FileTree: React.FC<{
  files: SubmittedFile[];
  allFindings: Finding[];
  selected: string | null;
  onSelect: (path: string | null) => void;
  onCollapse?: () => void;
}> = ({ files, allFindings, selected, onSelect, onCollapse }) => {
  const root = useMemo(() => buildFileTree(files, allFindings), [files, allFindings]);
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());

  const toggleCollapse = (path: string) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(path)) { next.delete(path); } else { next.add(path); }
      return next;
    });
  };

  const totalFindings = root.findingCount;

  const renderNode = (node: FileTreeNode, depth: number): React.ReactNode => {
    const sevColor = node.maxSeverity ? (SEV_COLOR[node.maxSeverity] ?? "var(--fg-muted)") : "var(--fg-subtle)";
    const isSelected = selected === node.fullPath || selected === node.fullPath + "/";
    const isCollapsed = collapsed.has(node.fullPath);

    if (node.isLeaf) {
      return (
        <div
          key={node.fullPath}
          onClick={() => onSelect(isSelected ? null : node.fullPath)}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 5,
            padding: "4px 8px 4px 0",
            paddingLeft: depth * 16 + 8,
            cursor: "pointer",
            borderLeft: isSelected ? "2px solid var(--primary)" : "2px solid transparent",
            background: isSelected ? "var(--bg-soft)" : "transparent",
            borderRadius: "0 var(--r-sm) var(--r-sm) 0",
            transition: "background .1s",
          }}
          onMouseEnter={(e) => { if (!isSelected) (e.currentTarget as HTMLElement).style.background = "var(--bg-soft)"; }}
          onMouseLeave={(e) => { if (!isSelected) (e.currentTarget as HTMLElement).style.background = "transparent"; }}
        >
          {/* file icon */}
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none" style={{ flexShrink: 0, color: sevColor }}>
            <rect x="1.5" y="0.5" width="7" height="11" rx="1" stroke="currentColor" strokeWidth="1" />
            <path d="M3.5 4h5M3.5 6h5M3.5 8h3" stroke="currentColor" strokeWidth="1" strokeLinecap="round" />
          </svg>
          <span style={{ flex: 1, fontSize: 11.5, color: sevColor, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {node.name}
          </span>
          {node.findingCount > 0 && (
            <span style={{ fontSize: 10, background: sevColor + "22", color: sevColor, borderRadius: 99, padding: "1px 5px", flexShrink: 0, fontWeight: 600 }}>
              {node.findingCount}
            </span>
          )}
        </div>
      );
    }

    return (
      <div key={node.fullPath}>
        <div
          onClick={() => {
            toggleCollapse(node.fullPath);
            onSelect(isSelected ? null : node.fullPath + "/");
          }}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 5,
            padding: "4px 8px 4px 0",
            paddingLeft: depth * 16 + 8,
            cursor: "pointer",
            borderLeft: isSelected ? "2px solid var(--primary)" : "2px solid transparent",
            background: isSelected ? "var(--bg-soft)" : "transparent",
            borderRadius: "0 var(--r-sm) var(--r-sm) 0",
            transition: "background .1s",
          }}
          onMouseEnter={(e) => { if (!isSelected) (e.currentTarget as HTMLElement).style.background = "var(--bg-soft)"; }}
          onMouseLeave={(e) => { if (!isSelected) (e.currentTarget as HTMLElement).style.background = "transparent"; }}
        >
          {/* chevron */}
          <svg width="10" height="10" viewBox="0 0 10 10" fill="none" style={{ flexShrink: 0, color: "var(--fg-subtle)", transform: isCollapsed ? "rotate(-90deg)" : "none", transition: "transform .15s" }}>
            <path d="M2 3.5l3 3 3-3" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          {/* folder icon */}
          <svg width="13" height="12" viewBox="0 0 13 12" fill="none" style={{ flexShrink: 0, color: sevColor }}>
            <path d="M1 3.5C1 2.67 1.67 2 2.5 2H5l1 1.5h4.5C11.33 3.5 12 4.17 12 5v4.5C12 10.33 11.33 11 10.5 11h-8C1.67 11 1 10.33 1 9.5V3.5z" stroke="currentColor" strokeWidth="1" fill={sevColor + "18"} />
          </svg>
          <span style={{ flex: 1, fontSize: 11.5, fontWeight: 500, color: sevColor, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {node.name}
          </span>
          {node.findingCount > 0 && (
            <span style={{ fontSize: 10, background: sevColor + "22", color: sevColor, borderRadius: 99, padding: "1px 5px", flexShrink: 0, fontWeight: 600 }}>
              {node.findingCount}
            </span>
          )}
        </div>
        {!isCollapsed && node.children.map((c) => renderNode(c, depth + 1))}
      </div>
    );
  };

  return (
    <div
      className="surface"
      style={{ padding: 0, overflow: "auto", alignSelf: "start", position: "sticky", top: 16 }}
    >
      {/* All files row */}
      <div
        onClick={() => onSelect(null)}
        style={{
          display: "flex",
          alignItems: "center",
          gap: 6,
          padding: "8px 10px",
          cursor: "pointer",
          borderBottom: "1px solid var(--border)",
          borderLeft: selected === null ? "2px solid var(--primary)" : "2px solid transparent",
          background: selected === null ? "var(--bg-soft)" : "transparent",
        }}
      >
        <svg width="13" height="12" viewBox="0 0 13 12" fill="none" style={{ color: "var(--fg-muted)", flexShrink: 0 }}>
          <rect x="1" y="1" width="11" height="10" rx="1.5" stroke="currentColor" strokeWidth="1" />
          <path d="M3.5 4.5h6M3.5 6.5h6M3.5 8.5h4" stroke="currentColor" strokeWidth="1" strokeLinecap="round" />
        </svg>
        <span style={{ flex: 1, fontSize: 11.5, fontWeight: 500, color: "var(--fg-muted)" }}>All files</span>
        {totalFindings > 0 && (
          <span style={{ fontSize: 10, background: "var(--bg-soft)", color: "var(--fg-muted)", borderRadius: 99, padding: "1px 5px", border: "1px solid var(--border)" }}>
            {totalFindings}
          </span>
        )}
        {onCollapse && (
          <button
            onClick={(e) => { e.stopPropagation(); onCollapse(); }}
            title="Collapse panel"
            style={{ background: "none", border: "none", cursor: "pointer", color: "var(--fg-subtle)", padding: "2px 4px", display: "flex", alignItems: "center", borderRadius: "var(--r-sm)", flexShrink: 0 }}
            onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.color = "var(--fg-muted)"; }}
            onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.color = "var(--fg-subtle)"; }}
          >
            <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
              <path d="M8 2L4 6l4 4" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </button>
        )}
      </div>
      <div style={{ padding: "4px 0" }}>
        {root.children.map((c) => renderNode(c, 0))}
      </div>
    </div>
  );
};

// ============================================================================
// Code snippet viewer
// ============================================================================

const CodeSnippet: React.FC<{
  fileContent: string | null;
  snippet: string | null;
  lineNumber: number;
  filePath: string;
  severityColor: string;
  contextLines?: number;
}> = ({ fileContent, snippet, lineNumber, filePath, severityColor, contextLines = 5 }) => {
  // Prefer full file content (from original_code_map) over snippet-only
  const source = useMemo(() => {
    if (fileContent) return fileContent;
    if (snippet) return snippet;
    return null;
  }, [fileContent, snippet]);

  if (!source || lineNumber <= 0) return null;

  const allLines = source.split("\n");
  // When using full file, extract context window; when using snippet, show as-is
  let displayLines: string[];
  let startLineNum: number;

  if (fileContent) {
    const start = Math.max(0, lineNumber - contextLines - 1);
    const end = Math.min(allLines.length, lineNumber + contextLines);
    displayLines = allLines.slice(start, end);
    startLineNum = start + 1;
  } else {
    // Snippet — show all, treat first line as the flagged one
    displayLines = allLines;
    if (displayLines[displayLines.length - 1] === "") displayLines.pop();
    startLineNum = lineNumber;
  }

  const flaggedLine = fileContent ? lineNumber : startLineNum;

  return (
    <div>
      {/* Header */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 6,
          marginBottom: 6,
          fontSize: 11,
          color: "var(--fg-muted)",
          fontFamily: "var(--font-mono)",
        }}
      >
        <svg width="11" height="11" viewBox="0 0 11 11" fill="none" style={{ color: "var(--fg-subtle)", flexShrink: 0 }}>
          <rect x="1" y="0.5" width="7" height="10" rx="1" stroke="currentColor" strokeWidth="1" />
          <path d="M2.5 3.5h5M2.5 5.5h5M2.5 7.5h3" stroke="currentColor" strokeWidth="1" strokeLinecap="round" />
        </svg>
        <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 240 }}>{filePath}</span>
        <span style={{ color: "var(--fg-subtle)" }}>·</span>
        <span style={{ color: severityColor, fontWeight: 600 }}>line {lineNumber}</span>
      </div>
      {/* Code block — reuses .diff container for consistent look */}
      <div className="diff" style={{ maxHeight: 220, overflowY: "auto" }}>
        {displayLines.map((line, i) => {
          const lineNum = startLineNum + i;
          const isFlagged = lineNum === flaggedLine;
          return (
            <div
              key={i}
              style={{
                display: "grid",
                gridTemplateColumns: "38px 1fr",
                minHeight: 22,
                background: isFlagged ? "var(--diff-del)" : "transparent",
                borderLeft: isFlagged ? `2px solid ${severityColor}` : "2px solid transparent",
              }}
            >
              <span
                className="diff-ln"
                style={{
                  padding: "0 8px",
                  color: isFlagged ? severityColor : "var(--fg-subtle)",
                  textAlign: "right",
                  userSelect: "none",
                  background: isFlagged ? "var(--diff-del)" : "var(--bg-soft)",
                  borderRight: "1px solid var(--border)",
                  fontSize: 11,
                  lineHeight: "22px",
                  fontWeight: isFlagged ? 700 : 400,
                }}
              >
                {lineNum}
              </span>
              <span
                className="diff-code"
                style={{
                  padding: "0 12px",
                  whiteSpace: "pre",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  lineHeight: "22px",
                  color: isFlagged ? "var(--fg)" : "var(--fg-muted)",
                  fontWeight: isFlagged ? 500 : 400,
                }}
              >
                {line || " "}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
};

// ============================================================================
// Remediation diff panel (Full Diff tab)
// ============================================================================

const RemediationDiffPanel: React.FC<{
  changedFiles: string[];
  originalCodeMap: Record<string, string>;
  fixedCodeMap: Record<string, string>;
  findingsByFile: Record<string, Finding[]>;
  selectedFile: string | null;
  onSelectFile: (path: string) => void;
}> = ({ changedFiles, originalCodeMap, fixedCodeMap, findingsByFile, selectedFile, onSelectFile }) => {
  const effectiveSelected = selectedFile ?? (changedFiles.length > 0 ? changedFiles[0] : null);

  // Stats for the selected file diff
  const diffStats = useMemo(() => {
    if (!effectiveSelected) return { added: 0, removed: 0 };
    const orig = (originalCodeMap[effectiveSelected] ?? "").split("\n");
    const fixed = (fixedCodeMap[effectiveSelected] ?? "").split("\n");
    const raw = computeLineDiff(orig, fixed);
    return {
      added: raw.filter((l) => l.type === "ins").length,
      removed: raw.filter((l) => l.type === "del").length,
    };
  }, [effectiveSelected, originalCodeMap, fixedCodeMap]);

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "200px 1fr",
        gap: 0,
        maxHeight: "calc(100vh - 280px)",
        overflow: "hidden",
        border: "1px solid var(--border)",
        borderRadius: "var(--r-lg)",
        background: "var(--bg-elev)",
      }}
    >
      {/* Left: file list */}
      <div
        style={{
          borderRight: "1px solid var(--border)",
          overflowY: "auto",
          display: "flex",
          flexDirection: "column",
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: "10px 12px",
            borderBottom: "1px solid var(--border)",
            display: "flex",
            alignItems: "center",
            gap: 8,
            background: "var(--bg-soft)",
          }}
        >
          <span style={{ fontSize: 11, color: "var(--fg-muted)", fontWeight: 500 }}>Changed files</span>
          <span className="chip" style={{ fontSize: 10, padding: "1px 6px" }}>{changedFiles.length}</span>
        </div>
        {changedFiles.map((path) => {
          const isActive = path === effectiveSelected;
          const filefindings = findingsByFile[path] ?? [];
          const maxSev = filefindings.reduce<string>((best, f) => {
            return severityRank((f.severity ?? "").toUpperCase()) > severityRank(best)
              ? (f.severity ?? "").toUpperCase()
              : best;
          }, "");
          const dotColor = maxSev ? (SEV_COLOR[maxSev] ?? "var(--fg-subtle)") : "var(--fg-subtle)";
          const shortName = path.split("/").pop() ?? path;
          const dir = path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "";
          return (
            <div
              key={path}
              onClick={() => onSelectFile(path)}
              style={{
                padding: "8px 12px",
                cursor: "pointer",
                borderLeft: isActive ? "2px solid var(--primary)" : "2px solid transparent",
                background: isActive ? "var(--bg-soft)" : "transparent",
                transition: "background .1s",
              }}
              onMouseEnter={(e) => { if (!isActive) (e.currentTarget as HTMLElement).style.background = "color-mix(in oklch, var(--bg-soft) 60%, transparent)"; }}
              onMouseLeave={(e) => { if (!isActive) (e.currentTarget as HTMLElement).style.background = "transparent"; }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <span style={{ width: 6, height: 6, borderRadius: 99, background: dotColor, flexShrink: 0 }} />
                <span
                  className="mono"
                  style={{ fontSize: 11, color: "var(--fg)", fontWeight: isActive ? 500 : 400, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                  title={path}
                >
                  {shortName}
                </span>
              </div>
              {dir && (
                <div className="mono" style={{ fontSize: 10, color: "var(--fg-subtle)", marginTop: 1, paddingLeft: 12, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {dir}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Right: diff viewer */}
      <div style={{ overflow: "hidden", display: "flex", flexDirection: "column" }}>
        {effectiveSelected ? (
          <>
            {/* File header */}
            <div
              style={{
                padding: "10px 14px",
                borderBottom: "1px solid var(--border)",
                background: "var(--bg-soft)",
                display: "flex",
                alignItems: "center",
                gap: 10,
                flexWrap: "wrap",
              }}
            >
              <span className="mono" style={{ fontSize: 12, color: "var(--fg)", fontWeight: 500 }}>{effectiveSelected}</span>
              <div style={{ display: "flex", gap: 6, marginLeft: "auto" }}>
                {diffStats.removed > 0 && (
                  <span className="chip" style={{ background: "var(--diff-del)", borderColor: "var(--diff-del-line)", color: "var(--critical)", fontSize: 10.5 }}>
                    −{diffStats.removed}
                  </span>
                )}
                {diffStats.added > 0 && (
                  <span className="chip" style={{ background: "var(--diff-add)", borderColor: "var(--diff-add-line)", color: "var(--success)", fontSize: 10.5 }}>
                    +{diffStats.added}
                  </span>
                )}
              </div>
            </div>
            {/* Scrollable diff */}
            <div style={{ flex: 1, overflowY: "auto" }}>
              <DiffViewer
                original={originalCodeMap[effectiveSelected] ?? ""}
                fixed={fixedCodeMap[effectiveSelected] ?? ""}
                startLine={1}
                filePath={effectiveSelected}
              />
            </div>
          </>
        ) : (
          <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--fg-muted)", fontSize: 13 }}>
            Select a file to view its diff
          </div>
        )}
      </div>
    </div>
  );
};

export default ResultsPage;
