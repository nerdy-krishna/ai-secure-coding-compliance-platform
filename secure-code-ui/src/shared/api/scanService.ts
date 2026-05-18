import {
  type BulkFindingDispositionResponse,
  type FindingDisposition,
  type FindingDispositionEvent,
  type FindingDispositionResponse,
  type GitRepoPreviewRequest,
  type LLMInteractionResponse,
  type PaginatedProjectHistoryResponse,
  type PaginatedScanHistoryResponse,
  type PrescanReviewResponse,
  type ScanResponse,
  type ScanResultResponse
} from "../types/api";
import apiClient from "./apiClient";

// V02.2.1 / V15.2.2: URL validation helper — only http(s), max 512 chars.
function assertHttpUrl(u: string): void {
  try {
    const url = new URL(u);
    if (!/^https?:$/.test(url.protocol)) throw new Error();
    if (u.length > 512) throw new Error();
  } catch {
    throw new Error("repo_url must be http(s) and <=512 chars");
  }
}

// V02.2.1 / V15.2.2: Maximum allowed archive size (500 MB).
const MAX_ARCHIVE_BYTES = 500 * 1024 * 1024;

// V02.2.1: Clamp pagination parameters to safe ranges.
function clampPagination(
  page: number | undefined,
  pageSize: number | undefined
): { page: number; pageSize: number } {
  return {
    page: Math.max(1, Math.trunc(page || 1)),
    pageSize: Math.max(1, Math.min(200, Math.trunc(pageSize || 25))),
  };
}

// V15.2.2: In-flight guard so concurrent createScan calls share one request.
let createScanInFlight: Promise<ScanResponse> | null = null;

export const scanService = {
  /**
   * Submits code for a new scan under a project.
   * V02.2.1 / V15.2.2 / V15.3.3: validates scalar fields and archive size;
   * deduplicates concurrent calls via an in-flight guard.
   */
  createScan: async (payload: FormData): Promise<ScanResponse> => {
    // V02.2.1 / V15.3.3: validate known scalar fields in the FormData.
    const projectName = payload.get("project_name");
    if (typeof projectName === "string" && projectName.length > 100) {
      throw new Error("project_name must be <=100 characters");
    }
    const scanType = payload.get("scan_type");
    const allowedScanTypes = new Set(["AUDIT", "SUGGEST", "REMEDIATE"]);
    if (typeof scanType === "string" && !allowedScanTypes.has(scanType)) {
      throw new Error("scan_type must be one of AUDIT, SUGGEST, REMEDIATE");
    }
    const frameworks = payload.getAll("frameworks");
    if (frameworks.length > 10) {
      throw new Error("frameworks must have <=10 items");
    }
    for (const fw of frameworks) {
      if (typeof fw === "string" && fw.length > 64) {
        throw new Error("Each framework name must be <=64 characters");
      }
    }
    // V02.2.1 / V15.2.2: guard archive file size.
    for (const value of payload.values()) {
      if (value instanceof File) {
        if (value.size === 0 || value.size > MAX_ARCHIVE_BYTES) {
          throw new Error("Archive must be 1B-500MB");
        }
      }
    }
    // V15.2.2: in-flight guard — reuse an active request instead of racing.
    if (createScanInFlight) return createScanInFlight;
    createScanInFlight = apiClient
      .post<ScanResponse>("/scans", payload)
      .then((r) => r.data)
      .finally(() => { createScanInFlight = null; });
    return createScanInFlight;
  },

  /**
   * Fetches the file list from a remote Git repository for preview.
   * V02.2.1: validates repoUrl is http(s) and <=512 chars to prevent SSRF.
   */
  previewGitRepo: async (repoUrl: string): Promise<string[]> => {
    assertHttpUrl(repoUrl); // V02.2.1: SSRF guard
    const requestPayload: GitRepoPreviewRequest = { repo_url: repoUrl };
    const response = await apiClient.post<{ files: string[] }>(
      "/scans/preview-git",
      requestPayload
    );
    return response.data.files;
  },

  /**
   * Fetches the file list from an uploaded archive for preview.
   * V02.2.1 / V15.2.2: rejects empty files or files exceeding 500 MB.
   */
  previewArchive: async (archiveFile: File): Promise<string[]> => {
    if (archiveFile.size === 0 || archiveFile.size > MAX_ARCHIVE_BYTES) {
      throw new Error("Archive must be 1B-500MB");
    }
    const formData = new FormData();
    formData.append("archive_file", archiveFile);
    const response = await apiClient.post<{ files: string[] }>(
      "/scans/preview-archive",
      formData
    );
    return response.data.files;
  },

  /**
   * Fetches the full analysis result for a given scan.
   * V01.2.2: scanId is encoded to prevent URL path injection.
   */
  getScanResult: async (scanId: string): Promise<ScanResultResponse> => {
    const response = await apiClient.get<ScanResultResponse>(`/scans/${encodeURIComponent(scanId)}/result?include_source=true`);
    return response.data;
  },

  /**
   * Fetches a paginated list of all projects for the current user.
   * V02.2.1: pagination parameters are clamped; free-text search is truncated.
   */
  getProjectHistory: async (
    page: number,
    pageSize: number,
    search?: string,
  ): Promise<PaginatedProjectHistoryResponse> => {
    const clamped = clampPagination(page, pageSize); // V02.2.1
    let safeSearch = search;
    if (safeSearch && safeSearch.length > 200) safeSearch = safeSearch.slice(0, 200); // V02.2.1
    const response = await apiClient.get<PaginatedProjectHistoryResponse>("/projects", {
      params: {
        skip: (clamped.page - 1) * clamped.pageSize,
        limit: clamped.pageSize,
        search: safeSearch || undefined,
      }
    });
    return response.data;
  },

  /**
   * Searches for projects by name for autocomplete.
   */
  searchProjects: async (query: string): Promise<string[]> => {
    if (!query) return [];
    const response = await apiClient.get<string[]>("/projects/search", {
      params: { q: query },
    });
    return response.data;
  },

  /**
   * Fetches a paginated list of all scans for the current user.
   * V02.2.1: pagination clamped; search truncated; sortOrder and status allow-listed.
   */
  getScanHistory: async (
    page: number,
    pageSize: number,
    search?: string,
    sortOrder?: string,
    status?: string,
  ): Promise<PaginatedScanHistoryResponse> => {
    const clamped = clampPagination(page, pageSize); // V02.2.1
    let safeSearch = search;
    if (safeSearch && safeSearch.length > 200) safeSearch = safeSearch.slice(0, 200); // V02.2.1
    const allowedSortOrders = new Set(["asc", "desc"]);
    const safeSortOrder = sortOrder && allowedSortOrders.has(sortOrder) ? sortOrder : undefined;
    const allowedStatuses = new Set([
      "PENDING", "RUNNING", "COMPLETED", "FAILED", "CANCELLED",
      "PENDING_COST_APPROVAL", "PENDING_PRESCAN_APPROVAL",
      "BLOCKED_PRE_LLM", "BLOCKED_USER_DECLINE", "REMEDIATION_COMPLETED",
    ]);
    const safeStatus = status && status !== "All" && allowedStatuses.has(status) ? status : undefined;
    const response = await apiClient.get<PaginatedScanHistoryResponse>("/scans/history", {
      params: {
        page: clamped.page,
        page_size: clamped.pageSize,
        search: safeSearch || undefined,
        sort_order: safeSortOrder,
        status: safeStatus,
      }
    });
    return response.data;
  },

  /**
   * Fetches a paginated list of scans for a specific project.
   * V01.2.2: projectId encoded. V02.2.1: pagination clamped.
   */
  getScansForProject: async (
    projectId: string,
    page: number,
    pageSize: number
  ): Promise<PaginatedScanHistoryResponse> => {
    const clamped = clampPagination(page, pageSize); // V02.2.1
    const response = await apiClient.get<PaginatedScanHistoryResponse>(`/projects/${encodeURIComponent(projectId)}/scans`, {
      params: {
        skip: (clamped.page - 1) * clamped.pageSize,
        limit: clamped.pageSize,
      },
    });
    return response.data;
  },

  /**
   * Fetches deterministic-scanner findings for the prescan-approval card.
   *
   * Only valid while the scan is at PENDING_PRESCAN_APPROVAL (gate) or
   * already in one of the prescan-terminal states (BLOCKED_PRE_LLM /
   * BLOCKED_USER_DECLINE). Other statuses return 400. ADR-009 / G6.
   */
  getPrescanReview: async (scanId: string): Promise<PrescanReviewResponse> => {
    const response = await apiClient.get<PrescanReviewResponse>(
      `/scans/${encodeURIComponent(scanId)}/prescan-findings`, // V01.2.2
    );
    return response.data;
  },

  /**
   * Resume a scan paused at one of the worker-graph interrupt points.
   *
   * Three interrupt points exist: the prescan-approval gate (status
   * PENDING_PRESCAN_APPROVAL, ADR-009), the profiling-cost gate
   * (status PENDING_PROFILING_APPROVAL, #71), and the cost-approval
   * gate (status PENDING_COST_APPROVAL). The body's `kind` field
   * discriminates; missing body defaults to `cost_approval` for
   * backward-compat with older callers.
   *
   * V01.2.2: scanId encoded. V02.3.4: idempotency key forwarded as header.
   * V15.3.3: sanity guard rejects prescan_approval with override_critical_secret=true
   * when approved is not explicitly true. Backend MUST treat duplicate
   * X-Idempotency-Key values as a no-op to prevent double-submission.
   */
  approveScan: async (
    scanId: string,
    payload?: {
      kind?: "prescan_approval" | "profiling_approval" | "cost_approval";
      approved?: boolean;
      override_critical_secret?: boolean;
    },
    idempotencyKey?: string,
  ): Promise<{ message: string }> => {
    // V15.3.3: reject logically incoherent prescan override without explicit approval.
    if (
      payload?.kind === "prescan_approval" &&
      payload?.override_critical_secret === true &&
      payload?.approved !== true
    ) {
      throw new Error("override_critical_secret requires approved=true");
    }
    const body =
      payload && (payload.kind || payload.approved !== undefined || payload.override_critical_secret !== undefined)
        ? {
            kind: payload.kind ?? "cost_approval",
            approved: payload.approved ?? true,
            override_critical_secret: payload.override_critical_secret ?? false,
          }
        : undefined;
    const response = await apiClient.post<{ message: string }>(
      `/scans/${encodeURIComponent(scanId)}/approve`, // V01.2.2
      body,
      { headers: { "X-Idempotency-Key": idempotencyKey ?? crypto.randomUUID() } }, // V02.3.4
    );
    return response.data;
  },

  /**
   * Fetches the LLM interactions for a specific scan.
   * V01.2.2: scanId encoded.
   */
  getLlmInteractionsForScan: async (scanId: string): Promise<LLMInteractionResponse[]> => {
    const response = await apiClient.get<LLMInteractionResponse[]>(`/scans/${encodeURIComponent(scanId)}/llm-interactions`);
    return response.data;
  },

  /**
   * Sets a finding's operator triage disposition (PRD #96 / #97).
   * `note` is required by the backend for false_positive / risk_accepted.
   */
  setFindingDisposition: async (
    scanId: string,
    findingId: number,
    disposition: FindingDisposition,
    note?: string,
  ): Promise<FindingDispositionResponse> => {
    const response = await apiClient.patch<FindingDispositionResponse>(
      `/scans/${encodeURIComponent(scanId)}/findings/${findingId}/disposition`,
      { disposition, note: note ?? null },
    );
    return response.data;
  },

  /**
   * Applies one triage disposition to many findings of a scan at once
   * (PRD #96 / #100). All-or-nothing on the backend.
   */
  setFindingDispositionsBulk: async (
    scanId: string,
    findingIds: number[],
    disposition: FindingDisposition,
    note?: string,
  ): Promise<BulkFindingDispositionResponse> => {
    const response = await apiClient.patch<BulkFindingDispositionResponse>(
      `/scans/${encodeURIComponent(scanId)}/findings/disposition`,
      { finding_ids: findingIds, disposition, note: note ?? null },
    );
    return response.data;
  },

  /** The disposition-change history for a finding, oldest first. */
  getFindingDispositionEvents: async (
    scanId: string,
    findingId: number,
  ): Promise<FindingDispositionEvent[]> => {
    const response = await apiClient.get<FindingDispositionEvent[]>(
      `/scans/${encodeURIComponent(scanId)}/findings/${findingId}/disposition-events`,
    );
    return response.data;
  },

  /**
   * Downloads the scan's findings report in the given format and
   * triggers a browser save. Goes through apiClient so the request
   * carries the Authorization header (a plain <a download> would not).
   */
  downloadReport: async (
    scanId: string,
    format: "html" | "csv" | "pdf",
  ): Promise<void> => {
    const response = await apiClient.get(
      `/scans/${encodeURIComponent(scanId)}/report`,
      { params: { format }, responseType: "blob" },
    );
    const disposition = String(response.headers["content-disposition"] ?? "");
    const match = /filename="?([^"]+)"?/.exec(disposition);
    const filename = match ? match[1] : `scan-${scanId}-report.${format}`;
    const url = URL.createObjectURL(response.data as Blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  },

  /**
   * Cancels a scan that is pending approval.
   * V01.2.2: scanId encoded.
   */
  cancelScan: async (scanId: string): Promise<{ message: string }> => {
    const response = await apiClient.post<{ message: string }>(`/scans/${encodeURIComponent(scanId)}/cancel`);
    return response.data;
  },

  /**
   * Mints a short-TTL JWT for the SSE stream of a scan. EventSource
   * cannot send Authorization headers, so the backend accepts this
   * token via ?access_token=… on the stream URL. The token is
   * audience-tagged "sse:scan-stream", scan-id-bound, and 60s-TTL —
   * leaked tokens cannot be replayed against other scans or other
   * endpoints.
   */
  getStreamToken: async (
    scanId: string,
  ): Promise<{ access_token: string; expires_in: number }> => {
    const response = await apiClient.post<{
      access_token: string;
      expires_in: number;
    }>(`/scans/${encodeURIComponent(scanId)}/stream-token`);
    return response.data;
  },

  createProject: async (name: string): Promise<{ id: string; name: string }> => {
    const response = await apiClient.post<{ id: string; name: string }>("/projects", { name });
    return response.data;
  },

  deleteScan: async (scanId: string): Promise<void> => {
    await apiClient.delete(`/scans/${encodeURIComponent(scanId)}`); // V01.2.2
  },

  deleteProject: async (projectId: string): Promise<void> => {
    await apiClient.delete(`/projects/${encodeURIComponent(projectId)}`); // V01.2.2
  },
};