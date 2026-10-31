// secure-code-ui/src/pages/compliance/CompliancePage.tsx
//
// Unified Compliance page. Single entry point for both roles:
//
// - Regular users: read-only posture view. See cards for every framework
//   (the 3 defaults + any customs), with real score / doc-count /
//   open-findings. Click a card to see its controls.
//
// - Admins: the same view plus inline ingestion and management —
//   upload ASVS CSVs, fetch Proactive/Cheatsheets from GitHub URLs,
//   add/edit/delete custom frameworks, view RAG documents, approve
//   pending ingestion jobs. Replaces the old /admin/rag page.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AxiosError } from "axios";
import { saveAs } from "file-saver";
import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  complianceService,
  type ComplianceFrameworkStats,
} from "../../shared/api/complianceService";
import { frameworkService } from "../../shared/api/frameworkService";
import { llmConfigService } from "../../shared/api/llmConfigService";
import { ragService } from "../../shared/api/ragService";
import type {
  EnrichedDocument,
  FrameworkRead,
  LLMConfiguration,
  PreprocessingResponse,
  RAGDocument,
  RAGJobStatusResponse,
} from "../../shared/types/api";
import { useAuth } from "../../shared/hooks/useAuth";
import { Icon } from "../../shared/ui/Icon";
import { Modal } from "../../shared/ui/Modal";
import { useToast } from "../../shared/ui/Toast";
import { SectionHead, SevBar } from "../../shared/ui/DashboardPrimitives";
import { FrameworkIngestionModal } from "../admin/FrameworkIngestionModal";

function axiosErrorDetail(err: unknown): string {
  const e = err as {
    response?: { data?: { detail?: string } };
    message?: string;
  };
  return e.response?.data?.detail || e.message || "Unknown error";
}

// Maximum file size for admin standard uploads (50 MB).
const MAX_INGEST_BYTES = 50 * 1024 * 1024;

// Minimum milliseconds between successive upload / fetch actions.
const UPLOAD_COOLDOWN_MS = 2000;

/**
 * Validate that a URL is a well-formed https://github.com/... URL
 * and does not exceed 512 characters.
 */
function isValidGithubUrl(value: string): boolean {
  if (!value || value.length > 512) return false;
  if (!value.startsWith("https://github.com/")) return false;
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
}

/**
 * CSV-safe escape: coerce to string, prefix formula-injection characters
 * with a single quote, double embedded quotes, and wrap in double quotes.
 */
function csvEscape(v: unknown): string {
  const s = String(v ?? "");
  const formulaChars = /^[=+\-@\t\0]/;
  const escaped = (formulaChars.test(s) ? `'${s}` : s).replace(/"/g, '""');
  return `"${escaped}"`;
}

function formatWhen(iso: string | null): string {
  if (!iso) return "Never scanned";
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

// -----------------------------------------------------------------------------
// Document viewer modal
// -----------------------------------------------------------------------------

const ViewDocumentsModal: React.FC<{
  frameworkName: string;
  open: boolean;
  onClose: () => void;
}> = ({ frameworkName, open, onClose }) => {
  const { data: documents, isLoading, isError } = useQuery<
    RAGDocument[],
    Error
  >({
    queryKey: ["ragDocuments", frameworkName],
    queryFn: () => ragService.getDocuments(frameworkName),
    enabled: open,
  });

  const metadataKeys = useMemo(
    () =>
      documents
        ? Array.from(
            new Set(documents.flatMap((d) => Object.keys(d.metadata))),
          )
        : [],
    [documents],
  );

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={`Documents in "${frameworkName}"`}
      width="min(1100px, 95vw)"
      footer={
        <button className="sccap-btn sccap-btn-sm" onClick={onClose}>
          Close
        </button>
      }
    >
      {isLoading ? (
        <div
          style={{
            padding: 40,
            textAlign: "center",
            color: "var(--fg-muted)",
          }}
        >
          Loading documents…
        </div>
      ) : isError ? (
        <div
          style={{
            padding: 20,
            color: "var(--critical)",
            fontSize: 13,
          }}
        >
          Error loading documents.
        </div>
      ) : !documents || documents.length === 0 ? (
        <div
          style={{
            padding: 20,
            color: "var(--fg-muted)",
            fontSize: 13,
          }}
        >
          No documents for this framework.
        </div>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table className="sccap-t">
            <thead>
              <tr>
                <th>ID</th>
                <th style={{ minWidth: 280 }}>Content</th>
                {metadataKeys.map((k) => (
                  <th key={k}>{k.replace(/_/g, " ")}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {documents.map((d) => (
                <tr key={d.id} style={{ cursor: "default" }}>
                  <td className="mono" style={{ fontSize: 11 }}>
                    {d.id}
                  </td>
                  <td
                    style={{
                      fontSize: 12,
                      maxWidth: 420,
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                    title={d.document}
                  >
                    {d.document}
                  </td>
                  {metadataKeys.map((k) => {
                    const val = (d.metadata as Record<string, unknown>)[k];
                    if (typeof val === "boolean") {
                      return (
                        <td key={k}>
                          <span
                            className={`chip ${val ? "chip-success" : ""}`}
                          >
                            {val ? "Yes" : "No"}
                          </span>
                        </td>
                      );
                    }
                    return (
                      <td
                        key={k}
                        style={{
                          fontSize: 12,
                          color: "var(--fg-muted)",
                        }}
                      >
                        {val !== undefined && val !== null
                          ? String(val)
                          : "—"}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Modal>
  );
};

// -----------------------------------------------------------------------------
// Framework card
// -----------------------------------------------------------------------------

const FrameworkCard: React.FC<{
  stats: ComplianceFrameworkStats;
  isAdmin: boolean;
  active: boolean;
  adminLoading?: boolean;
  onClick: () => void;
  onView: () => void;
  onEdit: () => void;
  onIngest: () => void;
  onDelete: () => void;
}> = ({
  stats,
  isAdmin,
  active,
  adminLoading,
  onClick,
  onView,
  onEdit,
  onIngest,
  onDelete,
}) => {
  const isCustom = stats.framework_type === "custom";
  return (
    <div
      className="sccap-card"
      onClick={onClick}
      style={{
        cursor: "pointer",
        borderColor: active ? "var(--primary)" : "var(--border)",
        boxShadow: active ? "var(--shadow-sm)" : undefined,
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-start",
          marginBottom: 12,
        }}
      >
        <div>
          <div
            style={{
              fontSize: 10.5,
              color: "var(--fg-subtle)",
              textTransform: "uppercase",
              letterSpacing: ".06em",
            }}
          >
            {isCustom ? "Custom" : "Default"}
          </div>
          <h3 style={{ marginTop: 2, color: "var(--fg)", fontSize: 15 }}>
            {stats.display_name}
          </h3>
        </div>
      </div>

      {stats.description && (
        <div
          style={{
            fontSize: 12.5,
            color: "var(--fg-muted)",
            marginBottom: 10,
            lineHeight: 1.5,
            minHeight: 36,
            display: "-webkit-box",
            WebkitLineClamp: 2,
            WebkitBoxOrient: "vertical",
            overflow: "hidden",
          }}
        >
          {stats.description}
        </div>
      )}

      <div
        style={{
          display: "flex",
          gap: 6,
          flexWrap: "wrap",
          marginBottom: 10,
        }}
      >
        {stats.is_installed ? (
          <span className="chip chip-success">
            <Icon.Check size={10} /> Installed
          </span>
        ) : (
          <span
            className="chip"
            style={{ color: "var(--fg-subtle)", borderStyle: "dashed" }}
          >
            Not configured
          </span>
        )}
        {stats.doc_count > 0 && (
          <span className="chip chip-info">{stats.doc_count} docs</span>
        )}
        {stats.open_findings > 0 && (
          <span className="chip chip-critical">
            {stats.open_findings} open finding
            {stats.open_findings === 1 ? "" : "s"}
          </span>
        )}
      </div>

      {stats.findings_matched > 0 && <SevBar />}

      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginTop: 10,
          paddingTop: 10,
          borderTop: "1px solid var(--border)",
          fontSize: 11.5,
          color: "var(--fg-subtle)",
        }}
      >
        <span>
          <Icon.Clock size={10} /> {formatWhen(stats.last_scanned_at)}
        </span>

        {isAdmin ? (
          <div style={{ display: "flex", gap: 4 }}>
            {stats.is_installed && (
              <>
                <button
                  className="sccap-btn sccap-btn-icon sccap-btn-ghost sccap-btn-sm"
                  aria-label="View documents"
                  title="View documents"
                  onClick={(e) => {
                    e.stopPropagation();
                    onView();
                  }}
                >
                  <Icon.Eye size={13} />
                </button>
                <button
                  className="sccap-btn sccap-btn-icon sccap-btn-ghost sccap-btn-sm"
                  aria-label="Edit / re-ingest"
                  title="Edit / re-ingest"
                  onClick={(e) => {
                    e.stopPropagation();
                    onEdit();
                  }}
                >
                  <Icon.Edit size={13} />
                </button>
              </>
            )}
            <button
              className={
                stats.is_installed
                  ? "sccap-btn sccap-btn-ghost sccap-btn-sm"
                  : "sccap-btn sccap-btn-primary sccap-btn-sm"
              }
              title={stats.is_installed ? "Re-upload source" : "Upload framework"}
              onClick={(e) => {
                e.stopPropagation();
                onIngest();
              }}
              disabled={adminLoading}
            >
              <Icon.Upload size={11} />{" "}
              {adminLoading
                ? "Working…"
                : stats.is_installed
                  ? "Re-upload"
                  : "Configure"}
            </button>
            {stats.is_installed && (
              <button
                className="sccap-btn sccap-btn-icon sccap-btn-ghost sccap-btn-sm"
                aria-label="Delete"
                title="Delete documents"
                onClick={(e) => {
                  e.stopPropagation();
                  onDelete();
                }}
                style={{ color: "var(--critical)" }}
              >
                <Icon.Trash size={13} />
              </button>
            )}
          </div>
        ) : (
          stats.is_installed && (
            <button
              className="sccap-btn sccap-btn-ghost sccap-btn-sm"
              onClick={(e) => {
                e.stopPropagation();
                onClick();
              }}
            >
              View controls <Icon.ChevronR size={11} />
            </button>
          )
        )}
      </div>
    </div>
  );
};

// -----------------------------------------------------------------------------
// Main page
// -----------------------------------------------------------------------------

const CompliancePage: React.FC = () => {
  const toast = useToast();
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const isAdmin = !!user?.is_superuser;

  // Compliance stats (all roles)
  const { data: statsList, isLoading, isError } = useQuery<
    ComplianceFrameworkStats[]
  >({
    queryKey: ["compliance", "stats"],
    queryFn: complianceService.getStats,
    refetchOnWindowFocus: false,
  });

  // ---------- Admin state ----------
  const [pollingJobId, setPollingJobId] = useState<string | null>(null);
  const [ingestionModalOpen, setIngestionModalOpen] = useState(false);
  const [ingestionInitialValues, setIngestionInitialValues] = useState<
    { frameworkName: string; isEdit?: boolean } | undefined
  >(undefined);
  const [ingestLoading, setIngestLoading] = useState<string | null>(null);
  const [proactiveOpen, setProactiveOpen] = useState(false);
  const [cheatsheetOpen, setCheatsheetOpen] = useState(false);
  const [proactiveUrl, setProactiveUrl] = useState(
    "https://github.com/OWASP/www-project-proactive-controls/tree/master/docs/the-top-10",
  );
  const [cheatsheetUrl, setCheatsheetUrl] = useState(
    "https://github.com/OWASP/CheatSheetSeries/tree/master/cheatsheets",
  );
  const [scanReady, setScanReady] = useState(true);
  const [viewName, setViewName] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<{
    name: string;
    isCustom: boolean;
    id?: string;
  } | null>(null);
  const [typedDeleteName, setTypedDeleteName] = useState("");

  // Ref to track the timestamp of the last upload action for cooldown enforcement.
  const lastUploadRef = useRef<number>(0);

  useEffect(() => {
    if (!isAdmin) return;
    const stored = sessionStorage.getItem("rag_processing_job_id");
    if (stored) setPollingJobId(stored);
  }, [isAdmin]);

  // Admin-only data. useQuery's `enabled` gates the request on isAdmin so
  // a regular user never triggers a 403 during mount.
  const { data: llmConfigs = [] } = useQuery<LLMConfiguration[]>({
    queryKey: ["llmConfigs"],
    queryFn: llmConfigService.getLlmConfigs,
    enabled: isAdmin,
  });

  const { data: jobStatus, isFetching: isPolling, refetch: pollStatus } =
    useQuery<RAGJobStatusResponse, Error>({
      queryKey: ["ragJobStatus", pollingJobId],
      queryFn: () => {
        if (!pollingJobId) throw new Error("No job ID to poll");
        return ragService.getJobStatus(pollingJobId);
      },
      enabled: !!pollingJobId && isAdmin,
      refetchOnWindowFocus: true,
      refetchInterval: (query) => {
        const status = query.state.data?.status;
        return status === "PROCESSING" || status === "PENDING_APPROVAL"
          ? 3000
          : false;
      },
    });

  const approveMutation = useMutation({
    mutationFn: (jobId: string) => ragService.approveJob(jobId),
    onSuccess: () => {
      toast.success("Job approved; processing in background.");
      pollStatus();
    },
  });

  const ingestMutation = useMutation({
    mutationFn: (payload: PreprocessingResponse) =>
      ragService.ingestProcessed(payload),
    onSuccess: (data: { message: string }) => {
      toast.success(data.message);
      queryClient.invalidateQueries({ queryKey: ["compliance", "stats"] });
      queryClient.invalidateQueries({ queryKey: ["frameworks"] });
      handleJobReset();
    },
    onError: (error: AxiosError) => {
      const detail =
        (error.response?.data as { detail?: string })?.detail || error.message;
      toast.error(`Ingestion failed: ${detail}`);
    },
  });

  const deleteCustomMutation = useMutation({
    mutationFn: (id: string) => frameworkService.deleteFramework(id),
    onSuccess: () => {
      toast.success("Custom framework deleted.");
      queryClient.invalidateQueries({ queryKey: ["compliance", "stats"] });
      queryClient.invalidateQueries({ queryKey: ["frameworks"] });
    },
    onError: (error: AxiosError) =>
      toast.error(`Delete failed: ${error.message}`),
  });

  const refreshAfterAdminAction = () => {
    queryClient.invalidateQueries({ queryKey: ["compliance", "stats"] });
    queryClient.invalidateQueries({ queryKey: ["frameworks"] });
    queryClient.invalidateQueries({ queryKey: ["ragStats"] });
  };

  const handleOpenIngestionModal = (
    frameworkName?: string,
    isEdit = false,
  ) => {
    setIngestionInitialValues(
      frameworkName ? { frameworkName, isEdit } : undefined,
    );
    setIngestionModalOpen(true);
  };

  const handleIngestionSuccess = (jobId: string) => {
    setPollingJobId(jobId);
    sessionStorage.setItem("rag_processing_job_id", jobId);
    pollStatus();
  };

  const handleJobReset = () => {
    setPollingJobId(null);
    sessionStorage.removeItem("rag_processing_job_id");
    setScanReady(true);
  };

  const handleDownload = () => {
    if (!jobStatus?.processed_documents?.length) return;
    const { processed_documents, framework_name } = jobStatus;
    const metaKeys = Object.keys(processed_documents[0].metadata || {}).sort();
    const header = ["id", "document", ...metaKeys].map(csvEscape).join(",");
    const rows = processed_documents.map((doc: EnrichedDocument) => {
      const metaVals = metaKeys.map((k) => {
        const v = doc.metadata[k as keyof typeof doc.metadata] ?? "";
        return csvEscape(v);
      });
      return [
        csvEscape(doc.id),
        csvEscape(doc.enriched_content),
        ...metaVals,
      ].join(",");
    });
    const csv = `${header}\n${rows.join("\n")}`;
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    saveAs(blob, `${framework_name}_processed.csv`);
  };

  const handleUploadASVS = async (file: File) => {
    if (Date.now() - lastUploadRef.current < UPLOAD_COOLDOWN_MS) {
      toast.error("Please wait a moment before uploading again.");
      return;
    }
    if (file.size > MAX_INGEST_BYTES) {
      toast.error("File exceeds 50 MB limit.");
      return;
    }
    const allowedCsvTypes = ["text/csv", "application/vnd.ms-excel", ""];
    if (!allowedCsvTypes.includes(file.type)) {
      toast.error("Invalid file type. Expected a CSV file.");
      return;
    }
    lastUploadRef.current = Date.now();
    setIngestLoading("asvs");
    try {
      const res = await ragService.ingestASVS(
        file as unknown as Parameters<typeof ragService.ingestASVS>[0],
      );
      toast.success(res.message);
      refreshAfterAdminAction();
    } catch (error) {
      toast.error(`ASVS ingestion failed: ${axiosErrorDetail(error)}`);
    } finally {
      setIngestLoading(null);
    }
  };

  const handleUploadLLMTop10 = async (file: File) => {
    if (Date.now() - lastUploadRef.current < UPLOAD_COOLDOWN_MS) {
      toast.error("Please wait a moment before uploading again.");
      return;
    }
    if (file.size > MAX_INGEST_BYTES) {
      toast.error("File exceeds 50 MB limit.");
      return;
    }
    const allowedJsonTypes = ["application/json", "text/plain", ""];
    if (!allowedJsonTypes.includes(file.type)) {
      toast.error("Invalid file type. Expected a JSON file.");
      return;
    }
    lastUploadRef.current = Date.now();
    setIngestLoading("llm_top10");
    try {
      const res = await ragService.ingestLLMTop10(file);
      toast.success(res.message);
      refreshAfterAdminAction();
    } catch (error) {
      toast.error(`LLM Top-10 ingestion failed: ${axiosErrorDetail(error)}`);
    } finally {
      setIngestLoading(null);
    }
  };

  const handleUploadAgenticTop10 = async (file: File) => {
    if (Date.now() - lastUploadRef.current < UPLOAD_COOLDOWN_MS) {
      toast.error("Please wait a moment before uploading again.");
      return;
    }
    if (file.size > MAX_INGEST_BYTES) {
      toast.error("File exceeds 50 MB limit.");
      return;
    }
    const allowedJsonTypes = ["application/json", "text/plain", ""];
    if (!allowedJsonTypes.includes(file.type)) {
      toast.error("Invalid file type. Expected a JSON file.");
      return;
    }
    lastUploadRef.current = Date.now();
    setIngestLoading("agentic_top10");
    try {
      const res = await ragService.ingestAgenticTop10(file);
      toast.success(res.message);
      refreshAfterAdminAction();
    } catch (error) {
      toast.error(`Agentic Top-10 ingestion failed: ${axiosErrorDetail(error)}`);
    } finally {
      setIngestLoading(null);
    }
  };

  const handleFetchProactive = async () => {
    if (!isValidGithubUrl(proactiveUrl)) {
      toast.error("Enter an https://github.com/... URL (max 512 chars).");
      return;
    }
    if (Date.now() - lastUploadRef.current < UPLOAD_COOLDOWN_MS) {
      toast.error("Please wait a moment before fetching again.");
      return;
    }
    lastUploadRef.current = Date.now();
    setIngestLoading("proactive");
    try {
      const res = await ragService.ingestProactiveControls(proactiveUrl);
      toast.success(res.message);
      refreshAfterAdminAction();
      setProactiveOpen(false);
    } catch (error) {
      toast.error(
        `Proactive Controls fetch failed: ${axiosErrorDetail(error)}`,
      );
    } finally {
      setIngestLoading(null);
    }
  };

  const handleFetchCheatsheets = async () => {
    if (!isValidGithubUrl(cheatsheetUrl)) {
      toast.error("Enter an https://github.com/... URL (max 512 chars).");
      return;
    }
    if (Date.now() - lastUploadRef.current < UPLOAD_COOLDOWN_MS) {
      toast.error("Please wait a moment before fetching again.");
      return;
    }
    lastUploadRef.current = Date.now();
    setIngestLoading("cheatsheet");
    try {
      const res = await ragService.ingestCheatsheet(cheatsheetUrl);
      toast.success(res.message);
      refreshAfterAdminAction();
      setCheatsheetOpen(false);
    } catch (error) {
      toast.error(`Cheatsheets fetch failed: ${axiosErrorDetail(error)}`);
    } finally {
      setIngestLoading(null);
    }
  };

  const handleDeleteStandard = async (frameworkName: string) => {
    try {
      const docs = await ragService.getDocuments(frameworkName);
      if (docs && docs.length > 0) {
        await ragService.deleteDocuments(docs.map((d) => d.id));
        toast.success(`Deleted ${docs.length} documents for ${frameworkName}.`);
        refreshAfterAdminAction();
      } else {
        toast.info("No documents to delete.");
      }
    } catch (error) {
      toast.error(`Delete failed: ${axiosErrorDetail(error)}`);
    }
  };

  // ---------- Admin card actions ----------
  // Helper: map a framework name to the action that opens its ingest UI.
  // Both Edit and Ingest go through the same path — the OWASP-AppSec
  // frameworks have a CSV / GitHub-URL UX; the AI frameworks (§3.11)
  // accept a JSON upload (canonical samples in `data/owasp/*.json`);
  // custom frameworks open the ingestion modal.
  const triggerIngestForFramework = (name: string) => {
    if (name === "asvs") {
      document.getElementById("hidden-asvs-input")?.click();
    } else if (name === "proactive_controls") {
      setProactiveOpen(true);
    } else if (name === "cheatsheets") {
      setCheatsheetOpen(true);
    } else if (name === "llm_top10") {
      document.getElementById("hidden-llm-top10-input")?.click();
    } else if (name === "agentic_top10") {
      document.getElementById("hidden-agentic-top10-input")?.click();
    } else {
      handleOpenIngestionModal(name, true);
    }
  };

  const adminActions = (stats: ComplianceFrameworkStats) => ({
    onView: () => setViewName(stats.name),
    onEdit: () => triggerIngestForFramework(stats.name),
    onIngest: () => triggerIngestForFramework(stats.name),
    onDelete: () => {
      const isCustom = stats.framework_type === "custom";
      // Find the custom framework ID from the frameworkService cache if needed.
      const cached = queryClient.getQueryData<FrameworkRead[]>(["frameworks"]);
      const match = cached?.find((f) => f.name === stats.name);
      setConfirmDelete({
        name: stats.name,
        isCustom,
        id: match?.id,
      });
    },
  });

  // ---------- Job banner ----------
  const renderJobBanner = () => {
    if (!isAdmin || !pollingJobId || !jobStatus) return null;

    if (jobStatus.status === "PENDING_APPROVAL") {
      return (
        <div
          className="sccap-card"
          style={{
            background: "var(--medium-weak)",
            borderColor: "var(--medium)",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            padding: 16,
          }}
        >
          <div>
            <div
              style={{
                fontSize: 11,
                textTransform: "uppercase",
                letterSpacing: ".06em",
                color: "var(--medium)",
                fontWeight: 600,
              }}
            >
              Pending approval
            </div>
            <div style={{ color: "var(--fg)", marginTop: 2 }}>
              {jobStatus.framework_name}
            </div>
          </div>
          <button
            className="sccap-btn sccap-btn-primary sccap-btn-sm"
            onClick={() => approveMutation.mutate(pollingJobId)}
            disabled={approveMutation.isPending}
          >
            <Icon.Check size={12} /> Approve
          </button>
        </div>
      );
    }

    if (jobStatus.status === "PROCESSING" || isPolling) {
      return (
        <div
          className="sccap-card"
          style={{
            background: "var(--info-weak)",
            borderColor: "var(--info)",
            padding: 16,
          }}
        >
          <div
            style={{
              fontSize: 11,
              textTransform: "uppercase",
              letterSpacing: ".06em",
              color: "var(--info)",
              fontWeight: 600,
            }}
          >
            Processing
          </div>
          <div style={{ color: "var(--fg)", marginTop: 2 }}>
            {jobStatus.framework_name || "…"}
          </div>
          <div
            style={{ fontSize: 12.5, color: "var(--fg-muted)", marginTop: 4 }}
          >
            Enriching documents with LLM patterns. This may take a few minutes.
          </div>
        </div>
      );
    }

    if (jobStatus.status === "COMPLETED") {
      const finalPayload: PreprocessingResponse = {
        framework_name: jobStatus.framework_name,
        llm_config_name: "",
        processed_documents: jobStatus.processed_documents || [],
        scan_ready: scanReady,
      };
      return (
        <div
          className="sccap-card"
          style={{
            borderColor: "var(--success)",
            padding: 16,
            display: "grid",
            gap: 12,
          }}
        >
          <div>
            <div
              style={{
                fontSize: 11,
                textTransform: "uppercase",
                letterSpacing: ".06em",
                color: "var(--success)",
                fontWeight: 600,
              }}
            >
              Preprocessing complete
            </div>
            <div style={{ color: "var(--fg)", marginTop: 2 }}>
              {jobStatus.framework_name}
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div
              className={`sccap-switch ${scanReady ? "on" : ""}`}
              role="switch"
              aria-checked={scanReady}
              tabIndex={0}
              onClick={() => setScanReady(!scanReady)}
              onKeyDown={(e) => {
                if (e.key === " " || e.key === "Enter") {
                  e.preventDefault();
                  setScanReady(!scanReady);
                }
              }}
            />
            <span style={{ fontSize: 13, color: "var(--fg)" }}>
              {scanReady
                ? "Scan-ready (used by the scanner agent)"
                : "Chat-context only"}
            </span>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={handleDownload}
            >
              <Icon.Download size={12} /> Download CSV
            </button>
            <button
              className="sccap-btn sccap-btn-primary sccap-btn-sm"
              onClick={() => ingestMutation.mutate(finalPayload)}
              disabled={ingestMutation.isPending}
            >
              <Icon.Plus size={12} /> Finalize ingestion
            </button>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={handleJobReset}
            >
              Cancel
            </button>
          </div>
        </div>
      );
    }

    if (jobStatus.status === "FAILED") {
      return (
        <div
          className="sccap-card"
          style={{
            background: "var(--critical-weak)",
            borderColor: "var(--critical)",
            padding: 16,
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <div>
            <div
              style={{
                fontSize: 11,
                textTransform: "uppercase",
                letterSpacing: ".06em",
                color: "var(--critical)",
                fontWeight: 600,
              }}
            >
              Job failed
            </div>
            <div style={{ color: "var(--fg)", marginTop: 2, fontSize: 13 }}>
              {jobStatus.error_message}
            </div>
          </div>
          <button className="sccap-btn sccap-btn-sm" onClick={handleJobReset}>
            Close
          </button>
        </div>
      );
    }
    return null;
  };

  // ---------- Render ----------
  const defaults = (statsList ?? []).filter(
    (f) => f.framework_type === "default",
  );
  const customs = (statsList ?? []).filter(
    (f) => f.framework_type === "custom",
  );

  return (
    <div className="fade-in" style={{ display: "grid", gap: 20 }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-end",
          gap: 12,
        }}
      >
        <div>
          <h1 style={{ color: "var(--fg)" }}>Compliance</h1>
          <div style={{ color: "var(--fg-muted)", marginTop: 4 }}>
            {isAdmin
              ? "Manage security standards used across scans and advisor. Users reference the same frameworks from their scans and chats."
              : "Security standards used across your scans and the advisor. Your admin manages ingestion."}
          </div>
        </div>
      </div>

      {renderJobBanner()}

      {isError && (
        <div
          className="sccap-card"
          style={{
            padding: 14,
            background: "var(--critical-weak)",
            borderColor: "var(--critical)",
            color: "var(--critical)",
            fontSize: 13,
          }}
        >
          Failed to load compliance stats.
        </div>
      )}

      {isLoading ? (
        <div
          className="sccap-card"
          style={{
            padding: 40,
            textAlign: "center",
            color: "var(--fg-muted)",
          }}
        >
          Loading frameworks…
        </div>
      ) : (
        <>
          <SectionHead
            title={
              <>
                <Icon.Shield size={16} /> Default frameworks
              </>
            }
          />
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
              gap: 14,
            }}
          >
            {defaults.map((fw) => (
              <FrameworkCard
                key={fw.name}
                stats={fw}
                isAdmin={isAdmin}
                active={viewName === fw.name}
                adminLoading={ingestLoading === fw.name.split("_")[0]}
                onClick={() => setViewName(fw.name)}
                {...adminActions(fw)}
              />
            ))}
          </div>

          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 12,
              marginBottom: 14,
            }}
          >
            <h3
              style={{
                margin: 0,
                display: "flex",
                alignItems: "center",
                gap: 10,
                color: "var(--fg)",
              }}
            >
              <Icon.Layers size={16} /> Custom frameworks
            </h3>
            {isAdmin && (
              <button
                className="sccap-btn sccap-btn-primary sccap-btn-sm"
                onClick={() => handleOpenIngestionModal()}
              >
                <Icon.Plus size={12} /> Add framework
              </button>
            )}
          </div>
          {customs.length === 0 ? (
            <div
              className="sccap-card"
              style={{
                padding: 30,
                textAlign: "center",
                color: "var(--fg-muted)",
                fontSize: 13,
                borderStyle: "dashed",
              }}
            >
              No custom frameworks yet.
              {isAdmin && (
                <>
                  {" "}
                  Click{" "}
                  <span style={{ color: "var(--primary)" }}>Add framework</span>{" "}
                  to ingest one from a CSV.
                </>
              )}
            </div>
          ) : (
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
                gap: 14,
              }}
            >
              {customs.map((fw) => (
                <FrameworkCard
                  key={fw.name}
                  stats={fw}
                  isAdmin={isAdmin}
                  active={viewName === fw.name}
                  onClick={() => setViewName(fw.name)}
                  {...adminActions(fw)}
                />
              ))}
            </div>
          )}

        </>
      )}

      {/* Admin-only dialogs + hidden inputs below. Mount unconditionally
          so state updates don't race against role flips; the isAdmin
          gates prevent them from being user-reachable. */}
      {isAdmin && (
        <>
          {/* Admin upload limits (visible note for screen readers + admins inspecting DOM) */}
          <p
            id="admin-upload-limits"
            style={{
              position: "absolute",
              width: 1,
              height: 1,
              padding: 0,
              margin: -1,
              overflow: "hidden",
              clip: "rect(0,0,0,0)",
              whiteSpace: "nowrap",
              border: 0,
            }}
          >
            ASVS upload: CSV file (columns: id, document, …), max 50 MB.
            LLM Top-10 upload: JSON file matching data/owasp/llm_top10_2025.json schema, max 50 MB.
            Agentic Top-10 upload: JSON file matching the Agentic Top-10 schema, max 50 MB.
          </p>

          {/* ASVS CSV upload — max 50 MB, CSV only */}
          <input
            type="file"
            id="hidden-asvs-input"
            accept=".csv"
            aria-describedby="admin-upload-limits"
            style={{ display: "none" }}
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) {
                if (file.size > MAX_INGEST_BYTES) {
                  toast.error("File exceeds 50 MB limit.");
                  e.target.value = "";
                  return;
                }
                const allowedCsvTypes = ["text/csv", "application/vnd.ms-excel", ""];
                if (!allowedCsvTypes.includes(file.type)) {
                  toast.error("Invalid file type. Expected a CSV file.");
                  e.target.value = "";
                  return;
                }
                handleUploadASVS(file);
              }
              e.target.value = "";
            }}
          />
          {/* LLM Top-10 JSON upload — max 50 MB, JSON only */}
          <input
            type="file"
            id="hidden-llm-top10-input"
            accept=".json,application/json"
            style={{ display: "none" }}
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) {
                if (file.size > MAX_INGEST_BYTES) {
                  toast.error("File exceeds 50 MB limit.");
                  e.target.value = "";
                  return;
                }
                const allowedJsonTypes = ["application/json", "text/plain", ""];
                if (!allowedJsonTypes.includes(file.type)) {
                  toast.error("Invalid file type. Expected a JSON file.");
                  e.target.value = "";
                  return;
                }
                handleUploadLLMTop10(file);
              }
              e.target.value = "";
            }}
          />
          {/* Agentic Top-10 JSON upload — max 50 MB, JSON only */}
          <input
            type="file"
            id="hidden-agentic-top10-input"
            accept=".json,application/json"
            style={{ display: "none" }}
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) {
                if (file.size > MAX_INGEST_BYTES) {
                  toast.error("File exceeds 50 MB limit.");
                  e.target.value = "";
                  return;
                }
                const allowedJsonTypes = ["application/json", "text/plain", ""];
                if (!allowedJsonTypes.includes(file.type)) {
                  toast.error("Invalid file type. Expected a JSON file.");
                  e.target.value = "";
                  return;
                }
                handleUploadAgenticTop10(file);
              }
              e.target.value = "";
            }}
          />

          {viewName && (
            <ViewDocumentsModal
              frameworkName={viewName}
              open={viewName !== null}
              onClose={() => setViewName(null)}
            />
          )}

          <FrameworkIngestionModal
            visible={ingestionModalOpen}
            onCancel={() => setIngestionModalOpen(false)}
            onSuccess={handleIngestionSuccess}
            initialValues={ingestionInitialValues}
            llmConfigs={llmConfigs}
          />

          <Modal
            open={proactiveOpen}
            onClose={() => setProactiveOpen(false)}
            title="Fetch Proactive Controls"
            footer={
              <>
                <button
                  className="sccap-btn sccap-btn-sm"
                  onClick={() => setProactiveOpen(false)}
                >
                  Cancel
                </button>
                <button
                  className="sccap-btn sccap-btn-primary sccap-btn-sm"
                  onClick={handleFetchProactive}
                  disabled={ingestLoading === "proactive" || !isValidGithubUrl(proactiveUrl)}
                >
                  {ingestLoading === "proactive" ? "Fetching…" : "Start fetch"}
                </button>
              </>
            }
          >
            <label style={{ display: "grid", gap: 6 }}>
              <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
                GitHub URL
              </span>
              <input
                className="sccap-input mono"
                value={proactiveUrl}
                onChange={(e) => setProactiveUrl(e.target.value)}
                style={{ fontSize: 12 }}
              />
              <span style={{ fontSize: 11, color: "var(--fg-subtle)" }}>
                Must be an https://github.com/… URL (max 512 characters).
              </span>
            </label>
          </Modal>

          <Modal
            open={cheatsheetOpen}
            onClose={() => setCheatsheetOpen(false)}
            title="Fetch Cheatsheets"
            footer={
              <>
                <button
                  className="sccap-btn sccap-btn-sm"
                  onClick={() => setCheatsheetOpen(false)}
                >
                  Cancel
                </button>
                <button
                  className="sccap-btn sccap-btn-primary sccap-btn-sm"
                  onClick={handleFetchCheatsheets}
                  disabled={ingestLoading === "cheatsheet" || !isValidGithubUrl(cheatsheetUrl)}
                >
                  {ingestLoading === "cheatsheet"
                    ? "Fetching…"
                    : "Start fetch"}
                </button>
              </>
            }
          >
            <label style={{ display: "grid", gap: 6 }}>
              <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
                GitHub URL
              </span>
              <input
                className="sccap-input mono"
                value={cheatsheetUrl}
                onChange={(e) => setCheatsheetUrl(e.target.value)}
                style={{ fontSize: 12 }}
              />
              <span style={{ fontSize: 11, color: "var(--fg-subtle)" }}>
                Must be an https://github.com/… URL (max 512 characters).
              </span>
            </label>
          </Modal>

          <Modal
            open={confirmDelete !== null}
            onClose={() => { setConfirmDelete(null); setTypedDeleteName(""); }}
            title={
              confirmDelete?.isCustom
                ? "Delete custom framework?"
                : "Delete standard documents?"
            }
            width={460}
            footer={
              <>
                <button
                  className="sccap-btn sccap-btn-sm"
                  onClick={() => { setConfirmDelete(null); setTypedDeleteName(""); }}
                  disabled={deleteCustomMutation.isPending}
                >
                  Cancel
                </button>
                <button
                  className="sccap-btn sccap-btn-danger sccap-btn-sm"
                  onClick={() => {
                    if (!confirmDelete) return;
                    if (confirmDelete.isCustom && confirmDelete.id) {
                      deleteCustomMutation.mutate(confirmDelete.id);
                    } else {
                      handleDeleteStandard(confirmDelete.name);
                    }
                    setConfirmDelete(null);
                    setTypedDeleteName("");
                  }}
                  disabled={deleteCustomMutation.isPending || typedDeleteName !== confirmDelete?.name}
                >
                  {deleteCustomMutation.isPending ? "Deleting…" : "Delete"}
                </button>
              </>
            }
          >
            <div style={{ color: "var(--fg-muted)", fontSize: 13, marginBottom: 12 }}>
              {confirmDelete?.isCustom
                ? `This removes the framework "${confirmDelete?.name}" and all of its ingested documents. The action cannot be undone.`
                : `This removes every ingested document for "${confirmDelete?.name}". You can re-ingest from source at any time.`}
            </div>
            <label style={{ display: "grid", gap: 4 }}>
              <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
                Type <strong>{confirmDelete?.name}</strong> to confirm:
              </span>
              <input
                className="sccap-input"
                value={typedDeleteName}
                onChange={(e) => setTypedDeleteName(e.target.value)}
                placeholder={confirmDelete?.name ?? ""}
              />
            </label>
          </Modal>
        </>
      )}

    </div>
  );
};

export default CompliancePage;
