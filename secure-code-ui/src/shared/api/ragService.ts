// src/shared/api/ragService.ts
import type {
  JsonValue,
  PreprocessingResponse,
  RAGDocument,
  RAGJobStartResponse,
  RAGJobStatusResponse,
} from "../types/api";
import apiClient from "./apiClient";

// ---- Input-validation constants & helpers (V02.2.1) ----

/** Maximum allowed ingest file size: 50 MB. */
const MAX_INGEST_BYTES = 50 * 1024 * 1024;

/** UUID v4 pattern used to validate jobId and llmConfigId parameters. */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Safe framework-name character set — alphanumerics, underscores, hyphens, dots. */
const FRAMEWORK_NAME_RE = /^[A-Za-z0-9_.-]+$/;

/**
 * Asserts that `url` is an https://github.com/… link no longer than 512 chars.
 * Throws if the check fails (V02.2.1 SSRF guard).
 */
function assertGitHubUrl(url: string): void {
  if (url.length > 512) throw new Error("URL must be <=512 chars");
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new Error("URL must be an https://github.com/... link <=512 chars");
  }
  if (u.protocol !== "https:" || u.host !== "github.com") {
    throw new Error("URL must be an https://github.com/... link <=512 chars");
  }
}

/**
 * Guards a File argument against empty and oversized uploads (V02.2.1).
 */
function assertIngestFile(file: File): void {
  if (file.size === 0) throw new Error("Empty file");
  if (file.size > MAX_INGEST_BYTES) throw new Error("File exceeds 50 MB limit");
}

/**
 * Validates a framework name string (V02.2.1 / V01.2.2).
 */
function assertFrameworkName(name: string): void {
  if (!name || name.length > 100) throw new Error("frameworkName must be 1-100 chars");
  if (!FRAMEWORK_NAME_RE.test(name)) throw new Error("frameworkName contains invalid characters");
}

/**
 * Validates a UUID-format job/config id (V02.2.1 / V01.2.2).
 */
function assertUUID(id: string, label: string): void {
  if (!UUID_RE.test(id)) throw new Error(`${label} must be a valid UUID`);
}

// ---- In-flight deduplication maps (V15.2.2) ----
// Single-flight per framework / job prevents accidental duplicate LLM-spend
// submissions from rapid user clicks. The backend remains the authority on
// serialization; this is documented availability defense per V15.2.2.

const _preprocessInFlight = new Map<string, Promise<RAGJobStartResponse>>();
const _approveInFlight = new Map<string, Promise<{ message: string }>>();

interface GetDocumentsResponse {
  ids: string[];
  documents: string[];
  metadatas: Record<string, JsonValue>[];
}

export const ragService = {
  /**
   * Ingests a CSV file for a specific framework.
   */
  ingestDocuments: async (
    frameworkName: string,
    file: File,
  ): Promise<{ message: string }> => {
    // V02.2.1: validate file and framework name before upload
    assertIngestFile(file);
    assertFrameworkName(frameworkName);

    const formData = new FormData();
    formData.append("framework_name", frameworkName);
    formData.append("file", file);

    const response = await apiClient.post<{ message: string }>(
      "/admin/rag/ingest",
      formData,
    );
    return response.data;
  },

  /**
   * Gets all documents for a specific framework.
   */
  getDocuments: async (frameworkName: string): Promise<RAGDocument[]> => {
    // V02.2.1 / V01.2.2: validate and encode frameworkName before URL interpolation
    assertFrameworkName(frameworkName);
    const response = await apiClient.get<GetDocumentsResponse>(
      `/admin/rag/frameworks/${encodeURIComponent(frameworkName)}`,
    );
    // Ensure we handle cases where parts of the response might be null or undefined
    const ids = response.data?.ids || [];
    const documents = response.data?.documents || [];
    const metadatas = response.data?.metadatas || [];

    return ids.map((id: string, index: number) => ({
      id,
      document: documents[index] || "",
      metadata: metadatas[index] || {},
    }));
  },

  /**
   * Deletes a list of documents by their IDs.
   */
  deleteDocuments: async (documentIds: string[]): Promise<void> => {
    await apiClient.delete("/admin/rag/documents", {
      data: { document_ids: documentIds },
    });
  },

  ingestProcessed: async (
    payload: PreprocessingResponse,
  ): Promise<{ message: string }> => {
    const response = await apiClient.post<{ message: string }>(
      "/admin/rag/ingest-processed",
      payload,
    );
    return response.data;
  },

  // Resource-heavy preprocessing jobs (V15.1.3). startPreprocessing /
  // reprocessFramework kick off long-running LLM jobs (minutes to tens of
  // minutes) that bill against the configured llm_config. Callers MUST poll
  // getJobStatus with backoff (recommended: 5s for first 30s, then 15s) and
  // debounce user-initiated retriggers. The backend runs at most one job per
  // framework at a time; the UI must reflect that to avoid wasted spend.
  //
  // V15.3.3: accepts typed primitives; FormData is assembled from an explicit
  // allow-list to prevent injection of unexpected fields.
  startPreprocessing: async (
    file: File,
    frameworkName: string,
    targetLanguages: string[] = [],
    llmConfigId: string,
    rawContentRetentionConsent: boolean = false,
  ): Promise<RAGJobStartResponse> => {
    // V02.2.1 validations
    assertIngestFile(file);
    assertFrameworkName(frameworkName);
    if (targetLanguages.length > 10) throw new Error("targetLanguages must have at most 10 entries");
    for (const lang of targetLanguages) {
      if (!lang || lang.length > 32) throw new Error("Each targetLanguage must be 1-32 chars");
    }
    assertUUID(llmConfigId, "llmConfigId");

    // V15.2.2: single-flight per framework — return existing promise if in progress
    const key = frameworkName;
    const existing = _preprocessInFlight.get(key);
    if (existing) return existing;

    // Build FormData from explicit allow-list only (V15.3.3)
    const formData = new FormData();
    formData.append("file", file);
    formData.append("framework_name", frameworkName);
    for (const lang of targetLanguages) formData.append("target_languages", lang);
    formData.append("llm_config_id", llmConfigId);
    // V14.2.8: explicit consent for raw upload retention. Backend defaults to
    // false (no storage); we only forward the field when the operator opted in.
    formData.append("raw_content_retention_consent", String(!!rawContentRetentionConsent));

    const promise = apiClient
      .post<RAGJobStartResponse>("/admin/rag/preprocess/start", formData)
      .then((r) => r.data)
      .finally(() => _preprocessInFlight.delete(key));

    _preprocessInFlight.set(key, promise);
    return promise;
  },

  reprocessFramework: async (
    frameworkName: string,
    targetLanguages: string[],
    llmConfigId: string,
  ): Promise<RAGJobStartResponse> => {
    // V02.2.1 validations
    assertFrameworkName(frameworkName);
    if (targetLanguages.length > 10) throw new Error("targetLanguages must have at most 10 entries");
    for (const lang of targetLanguages) {
      if (!lang || lang.length > 32) throw new Error("Each targetLanguage must be 1-32 chars");
    }
    assertUUID(llmConfigId, "llmConfigId");

    // V15.2.2: single-flight per framework — return existing promise if in progress
    const key = `reprocess:${frameworkName}`;
    const existing = _preprocessInFlight.get(key);
    if (existing) return existing;

    const promise = apiClient
      .post<RAGJobStartResponse>("/admin/rag/preprocess/reprocess", {
        framework_name: frameworkName,
        target_languages: targetLanguages,
        llm_config_id: llmConfigId,
      })
      .then((r) => r.data)
      .finally(() => _preprocessInFlight.delete(key));

    _preprocessInFlight.set(key, promise);
    return promise;
  },

  approveJob: async (jobId: string): Promise<{ message: string }> => {
    // V02.2.1 / V01.2.2: validate UUID format before interpolating into URL
    assertUUID(jobId, "jobId");

    // V15.2.2: single-flight per job to prevent accidental duplicate approvals
    const existing = _approveInFlight.get(jobId);
    if (existing) return existing;

    const promise = apiClient
      .post<{ message: string }>(
        `/admin/rag/preprocess/${encodeURIComponent(jobId)}/approve`,
      )
      .then((r) => r.data)
      .finally(() => _approveInFlight.delete(jobId));

    _approveInFlight.set(jobId, promise);
    return promise;
  },

  // V15.1.3: poll with backoff — recommended 5 s for the first 30 s, then 15 s.
  getJobStatus: async (jobId: string): Promise<RAGJobStatusResponse> => {
    // V02.2.1 / V01.2.2: validate UUID format before interpolating into URL
    assertUUID(jobId, "jobId");

    const response = await apiClient.get<RAGJobStatusResponse>(
      `/admin/rag/preprocess/${encodeURIComponent(jobId)}/status`,
    );
    return response.data;
  },

  // --- Security Standards Ingestion ---
  //
  // DANGEROUS FUNCTIONALITY (V15.1.5):
  // 1. ingestProactiveControls / ingestCheatsheet accept caller-supplied
  //    URLs that the backend fetches server-side. This is an SSRF surface;
  //    backend MUST allow-list domains (owasp.org / cheatsheetseries) and
  //    deny private/loopback/link-local IPs. Do not relax the backend filter.
  // 2. ingestASVS / ingestLLMTop10 / ingestAgenticTop10 accept JSON/CSV
  //    that becomes RAG context the LLM treats as authoritative. A poisoned
  //    payload can rewrite agent guidance for every downstream scan; admin
  //    UI must surface a confirmation dialog per ingest.

  /**
   * Ingest an ASVS CSV/JSON file into the RAG knowledge base.
   *
   * WARNING (V15.1.5): uploaded content becomes authoritative RAG context for
   * every downstream LLM scan. Admin UI must show a confirmation dialog before
   * calling this method to guard against accidental or malicious poisoning.
   */
  ingestASVS: async (file: File): Promise<{ message: string; count: number }> => {
    // V02.2.1: reject empty or oversized files
    assertIngestFile(file);

    const formData = new FormData();
    formData.append("file", file);
    const response = await apiClient.post<{ message: string; count: number }>(
      "/admin/rag/ingest/standards/asvs",
      formData,
    );
    return response.data;
  },

  /**
   * Ingest the OWASP Proactive Controls document from a GitHub URL.
   *
   * WARNING (V15.1.5): the backend fetches the supplied URL server-side (SSRF
   * surface). Only https://github.com/... links are accepted by this client;
   * the backend must additionally allow-list the owasp.org / github.com domains
   * and deny all private/loopback/link-local targets.
   */
  ingestProactiveControls: async (url: string): Promise<{ message: string; count: number }> => {
    // V02.2.1: validate URL scheme, host, and length before forwarding to backend
    assertGitHubUrl(url);

    const formData = new FormData();
    formData.append("url", url);
    const response = await apiClient.post<{ message: string; count: number }>(
      "/admin/rag/ingest/standards/proactive-controls",
      formData,
    );
    return response.data;
  },

  /**
   * Ingest an OWASP Cheat Sheet from a GitHub URL.
   *
   * WARNING (V15.1.5): the backend fetches the supplied URL server-side (SSRF
   * surface). Only https://github.com/... links are accepted by this client;
   * the backend must additionally allow-list the cheatsheetseries / github.com
   * domains and deny all private/loopback/link-local targets.
   */
  ingestCheatsheet: async (url: string): Promise<{ message: string; count: number }> => {
    // V02.2.1: validate URL scheme, host, and length before forwarding to backend
    assertGitHubUrl(url);

    const formData = new FormData();
    formData.append("url", url);
    const response = await apiClient.post<{ message: string; count: number }>(
      "/admin/rag/ingest/standards/cheatsheets",
      formData,
    );
    return response.data;
  },

  /**
   * Ingest the OWASP LLM Top-10 (2025) JSON file. Format documented at
   * `data/owasp/llm_top10_2025.json` in the SCCAP repo. (§3.11)
   *
   * WARNING (V15.1.5): uploaded content becomes authoritative RAG context for
   * every downstream LLM scan. Admin UI must show a confirmation dialog before
   * calling this method to guard against accidental or malicious poisoning.
   */
  ingestLLMTop10: async (file: File): Promise<{ message: string; count: number }> => {
    // V02.2.1: reject empty or oversized files
    assertIngestFile(file);

    const formData = new FormData();
    formData.append("file", file);
    const response = await apiClient.post<{ message: string; count: number }>(
      "/admin/rag/ingest/standards/llm-top10",
      formData,
    );
    return response.data;
  },

  /**
   * Ingest the OWASP Top-10 for Agentic AI (2026) JSON file. Format documented
   * at `data/owasp/agentic_top10_2026.json` in the SCCAP repo. (§3.11)
   *
   * WARNING (V15.1.5): uploaded content becomes authoritative RAG context for
   * every downstream LLM scan. Admin UI must show a confirmation dialog before
   * calling this method to guard against accidental or malicious poisoning.
   */
  ingestAgenticTop10: async (file: File): Promise<{ message: string; count: number }> => {
    // V02.2.1: reject empty or oversized files
    assertIngestFile(file);

    const formData = new FormData();
    formData.append("file", file);
    const response = await apiClient.post<{ message: string; count: number }>(
      "/admin/rag/ingest/standards/agentic-top10",
      formData,
    );
    return response.data;
  },

  getStats: async (): Promise<Record<string, number>> => {
    const response = await apiClient.get<Record<string, number>>("/admin/rag/ingest/stats");
    return response.data;
  },
};
