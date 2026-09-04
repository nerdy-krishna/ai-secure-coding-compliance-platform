import apiClient from "./apiClient";
import type {
  AttemptSummary,
  C13CockpitSnapshot,
  C13Filters,
  CreateEngagementInput,
  CursorPage,
  EngagementSummary,
  EngagementDetail,
  EngagementCreatedReceipt,
  ExportProjection,
  ExportRequestInput,
  FreshRetestReceipt,
  GovernanceDecisionInput,
  GovernanceRequestInput,
  OwnerTuple,
  ReportProjection,
  ReportPublicationInput,
  ReportRequestInput,
  SafeProjectionRow,
  RetestRequestInput,
  SourcePin,
  SourceCutoff,
  StopEngagementReceipt,
} from "../lib/capability13/types";

const apiRoot = `${import.meta.env.VITE_API_BASE_URL || "/api/v1"}/pentesting`;
const part = (value: string) => encodeURIComponent(value);
const attemptPath = (engagementId: string, attemptId: string) =>
  `/pentesting/engagements/${part(engagementId)}/attempts/${part(attemptId)}`;

type ApiSafeItem = SafeProjectionRow;
interface ApiPin {
  owner: SourcePin["owner"]; projection_id: string; revision_or_generation: number;
  source_cutoff: SourceCutoff; projection_digest: string; freshness: "current" | "stale" | "unknown";
  completeness: "complete" | "partial" | "unavailable" | "inconclusive"; limitation_codes: string[];
}
interface ApiOwnerSummary {
  owner: SourcePin["owner"]; category: string; state_counts: Record<string, number>;
}
interface ApiSnapshot {
  schema_version: "sccap.pentest.c13-cockpit-snapshot.v1";
  snapshot_id: string; owner_tuple: OwnerTuple; attempt_generation: number;
  attempt_state: string; attempt_is_terminal: boolean; source_cutoff: SourceCutoff;
  source_pins: ApiPin[]; owner_summaries: ApiOwnerSummary[];
  projection_state: C13CockpitSnapshot["projection_state"]; limitation_codes: string[];
  snapshot_digest: string; can_create_report: boolean; can_publish_report: boolean;
  can_export_evidence: boolean; can_request_governance: boolean;
  can_approve_governance: boolean; can_create_retest: boolean;
}

interface ApiReportDetail {
  id: string; request_id: string; version: number; state: "validated";
  profile: string; completeness: ReportProjection["completeness"];
  source_manifest_digest: string; content_manifest_digest: string;
  created_at: string; publication_state: ReportProjection["publication_state"];
  predecessor_id: string | null; limitation_codes: string[]; digest: string;
  artifacts: ReportProjection["artifacts"];
}

const summary = (snapshot: ApiSnapshot, owner: string, key?: string) => snapshot.owner_summaries
  .filter((item) => item.owner === owner)
  .flatMap((item) => Object.entries(item.state_counts))
  .filter(([label]) => !key || label === key)
  .map(([label, count]) => ({ label, count }));

const adaptSnapshot = (value: ApiSnapshot): C13CockpitSnapshot => ({
  contract_major: value.schema_version.endsWith(".v1") ? 1 : 0,
  snapshot_id: value.snapshot_id, owner: value.owner_tuple,
  attempt_generation: value.attempt_generation, attempt_state: value.attempt_state,
  attempt_is_terminal: value.attempt_is_terminal, source_cutoff: value.source_cutoff,
  source_pins: value.source_pins.map((pin) => ({
    owner: pin.owner, projection_id: pin.projection_id,
    revision_or_generation: pin.revision_or_generation,
    cutoff: pin.source_cutoff.aggregate_sequence, digest: pin.projection_digest,
    freshness: pin.freshness === "unknown" ? "unavailable" : pin.freshness,
    completeness: pin.completeness === "unavailable" || pin.completeness === "inconclusive" ? "partial" : pin.completeness,
    limitations: pin.limitation_codes,
  })),
  objective: null, current_decision: null, active_executions: [], waiting_executions: [], unresolved_questions: [],
  observation_summary: summary(value, "C6", "observations"),
  finding_summary: summary(value, "C6", "findings"), coverage_summary: summary(value, "C9"),
  cleanup_summary: summary(value, "C10"), callback_summary: summary(value, "C11"), usage_summary: [],
  timeline: [], edges: [], projection_state: value.projection_state,
  limitation_codes: value.limitation_codes, snapshot_digest: value.snapshot_digest,
  actions: {
    can_create_report: value.can_create_report, can_publish_report: value.can_publish_report,
    can_export_evidence: value.can_export_evidence, can_request_governance: value.can_request_governance,
    can_approve_governance: value.can_approve_governance, can_create_retest: value.can_create_retest,
    disabled_reasons: {},
  },
});

const genericPath = (engagementId: string, attemptId: string, resource: string) =>
  `${attemptPath(engagementId, attemptId)}/c13-projections/${resource}`;
const safePage = async (engagementId: string, attemptId: string, resource: string, filters: C13Filters, signal?: AbortSignal) =>
  (await apiClient.get<CursorPage<ApiSafeItem>>(genericPath(engagementId, attemptId, resource), { params: params(filters), signal })).data;
const params = (filters: C13Filters = {}) => ({
  ...(filters.cursor ? { cursor: filters.cursor } : {}),
  ...(filters.state ? { state: filters.state } : {}),
  ...(filters.kind ? { kind: filters.kind } : {}),
  ...(filters.query ? { query: filters.query } : {}),
});

const idempotencyHeaders = (idempotencyKey: string, expectedDigest: string) => ({
  "Idempotency-Key": idempotencyKey,
  "If-Match": `"${expectedDigest}"`,
});

export const capability13Service = {
  createEngagement: async (input: CreateEngagementInput) =>
    (await apiClient.post<EngagementCreatedReceipt>("/pentesting/engagements", input)).data,

  listEngagements: async (filters: C13Filters = {}, signal?: AbortSignal) =>
    (await apiClient.get<CursorPage<EngagementSummary>>("/pentesting/engagements", { params: params(filters), signal })).data,

  listAttempts: async (engagementId: string, signal?: AbortSignal) =>
    (await apiClient.get<CursorPage<AttemptSummary>>(`/pentesting/engagements/${part(engagementId)}/attempts`, { signal })).data,

  getEngagement: async (engagementId: string, signal?: AbortSignal) =>
    (await apiClient.get<EngagementDetail>(`/pentesting/engagements/${part(engagementId)}`, { signal })).data,

  stopEngagement: async (engagementId: string, expectedStateVersion: number) =>
    (await apiClient.post<StopEngagementReceipt>(`/pentesting/engagements/${part(engagementId)}/commands/stop`, {
      schema_version: "sccap.pentest.v1",
      command_idempotency_key: `ui-stop-${crypto.randomUUID()}`,
      expected_state_version: expectedStateVersion,
    })).data,

  getSnapshot: async (engagementId: string, attemptId: string, signal?: AbortSignal) =>
    adaptSnapshot((await apiClient.get<ApiSnapshot>(`${attemptPath(engagementId, attemptId)}/cockpit-snapshot`, { signal })).data),

  listActivity: async (engagementId: string, attemptId: string, filters: C13Filters = {}, signal?: AbortSignal) =>
    safePage(engagementId, attemptId, "activity", filters, signal),

  listObservations: async (engagementId: string, attemptId: string, filters: C13Filters = {}, signal?: AbortSignal) =>
    safePage(engagementId, attemptId, "observations", filters, signal),

  listFindings: async (engagementId: string, attemptId: string, filters: C13Filters = {}, signal?: AbortSignal) =>
    safePage(engagementId, attemptId, "findings", filters, signal),

  listCanonical: async (engagementId: string, attemptId: string, kind: "tests" | "operations" | "frameworks" | "coverage", filters: C13Filters = {}, signal?: AbortSignal) =>
    safePage(engagementId, attemptId, kind, filters, signal),

  listCleanup: async (engagementId: string, attemptId: string, filters: C13Filters = {}, signal?: AbortSignal) =>
    safePage(engagementId, attemptId, "cleanup", filters, signal),

  listCallbacks: async (engagementId: string, attemptId: string, filters: C13Filters = {}, signal?: AbortSignal) =>
    safePage(engagementId, attemptId, "callbacks", filters, signal),

  listEvidenceExports: async (engagementId: string, attemptId: string, filters: C13Filters = {}, signal?: AbortSignal) =>
    safePage(engagementId, attemptId, "exports", filters, signal),

  listReports: async (engagementId: string, attemptId: string, filters: C13Filters = {}, signal?: AbortSignal) =>
    safePage(engagementId, attemptId, "reports", filters, signal),

  getReport: async (engagementId: string, attemptId: string, reportId: string, signal?: AbortSignal) =>
    (await apiClient.get<ApiReportDetail>(`${attemptPath(engagementId, attemptId)}/reports/${part(reportId)}`, { signal })).data,

  listGovernance: async (engagementId: string, attemptId: string, filters: C13Filters = {}, signal?: AbortSignal) =>
    safePage(engagementId, attemptId, "governance", filters, signal),

  listRetests: async (engagementId: string, attemptId: string, filters: C13Filters = {}, signal?: AbortSignal) =>
    safePage(engagementId, attemptId, "retests", filters, signal),

  listDeltas: async (engagementId: string, attemptId: string, filters: C13Filters = {}, signal?: AbortSignal) =>
    safePage(engagementId, attemptId, "deltas", filters, signal),

  getDeltaReference: async (engagementId: string, attemptId: string, deltaId: string, signal?: AbortSignal) => {
    let cursor: string | undefined;
    for (let pageNumber = 0; pageNumber < 20; pageNumber += 1) {
      if (signal?.aborted) throw new DOMException("Aborted", "AbortError");
      const page = await safePage(engagementId, attemptId, "deltas", cursor ? { cursor } : {}, signal);
      const match = page.items.find((item) => item.id === deltaId);
      if (match) return match;
      if (!page.next_cursor) return null;
      cursor = page.next_cursor;
    }
    throw new Error("Delta lookup exceeded its bounded page limit");
  },

  listAudit: async (engagementId: string, attemptId: string, filters: C13Filters = {}, signal?: AbortSignal) =>
    safePage(engagementId, attemptId, "audit", filters, signal),

  createReport: async (engagementId: string, attemptId: string, input: ReportRequestInput) =>
    (await apiClient.post<SafeProjectionRow>(`${attemptPath(engagementId, attemptId)}/report-requests`, input, {
      headers: idempotencyHeaders(input.idempotency_key, input.expected_digest),
    })).data,

  publishReport: async (engagementId: string, attemptId: string, reportId: string, input: ReportPublicationInput) =>
    (await apiClient.post<ReportProjection>(`${attemptPath(engagementId, attemptId)}/reports/${part(reportId)}/publication-decisions`, input, {
      headers: idempotencyHeaders(input.idempotency_key, input.expected_digest),
    })).data,

  createExport: async (engagementId: string, attemptId: string, input: ExportRequestInput) =>
    (await apiClient.post<SafeProjectionRow>(`${attemptPath(engagementId, attemptId)}/evidence-export-requests`, input, {
      headers: idempotencyHeaders(input.idempotency_key, input.expected_digest),
    })).data,

  getExportRequest: async (engagementId: string, attemptId: string, requestId: string, signal?: AbortSignal) =>
    (await apiClient.get<ExportProjection>(`${attemptPath(engagementId, attemptId)}/evidence-export-requests/${part(requestId)}`, { signal })).data,

  requestGovernance: async (engagementId: string, attemptId: string, input: GovernanceRequestInput) =>
    (await apiClient.post<SafeProjectionRow>(`${attemptPath(engagementId, attemptId)}/governance-requests`, input, {
      headers: idempotencyHeaders(input.idempotency_key, input.expected_digest),
    })).data,

  decideGovernance: async (engagementId: string, attemptId: string, requestId: string, input: GovernanceDecisionInput) =>
    (await apiClient.post<SafeProjectionRow>(`${attemptPath(engagementId, attemptId)}/governance-requests/${part(requestId)}/decisions`, input, {
      headers: idempotencyHeaders(input.idempotency_key, input.expected_digest),
    })).data,

  createRetest: async (engagementId: string, attemptId: string, input: RetestRequestInput) =>
    (await apiClient.post<FreshRetestReceipt>(`${attemptPath(engagementId, attemptId)}/retest-requests`, input, {
      headers: { "Idempotency-Key": input.idempotency_key },
    })).data,

  authorizeEvidenceExport: async (engagementId: string, attemptId: string, exportId: string, purposeCode: string) =>
    apiClient.post(`${attemptPath(engagementId, attemptId)}/evidence-exports/${part(exportId)}/grants`, {
      purpose_code: purposeCode,
      ttl_seconds: 60,
    }),

  downloadReportArtifact: async (engagementId: string, attemptId: string, reportId: string, artifactId: string, authorizationActionRef: string) =>
    apiClient.get(`${attemptPath(engagementId, attemptId)}/reports/${part(reportId)}/artifacts/${part(artifactId)}/download`, {
      responseType: "blob",
      headers: { "X-Authorization-Action": authorizationActionRef },
    }),
};

export function evidenceExportDownloadUrl(engagementId: string, attemptId: string, exportId: string, artifactId: string): string {
  const url = new URL(`${apiRoot}/engagements/${part(engagementId)}/attempts/${part(attemptId)}/evidence-exports/${part(exportId)}/artifacts/${part(artifactId)}/download`, window.location.origin);
  if (url.origin !== window.location.origin) throw new Error("Protected downloads require same-origin delivery");
  return url.toString();
}

export function capability13StreamUrl(engagementId: string, attemptId: string, cursor: number): string {
  const url = new URL(`${apiRoot}/engagements/${part(engagementId)}/attempts/${part(attemptId)}/cockpit-stream`, window.location.origin);
  if (url.origin !== window.location.origin) {
    throw new Error("Live updates require a same-origin HttpOnly browser session");
  }
  if (cursor > 0) url.searchParams.set("cursor", String(cursor));
  return url.toString();
}
