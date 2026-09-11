import type { AssessmentSummary } from "../lib/capability13/types";
import apiClient from "./apiClient";
import type { components } from "../types/api-generated";
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
  ThreatModelView,
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

export interface AttemptToolRun {
  tool: string;
  status: "completed" | "failed";
  observations: number;
  requests: number;
  duration_ms: number;
  authority: "observation_only";
}

export interface WorkLedgerSummary {
  pending_untried: number;
  running_units: number;
  blocked_units: number;
  inconclusive_units: number;
  completed_units: number;
  terminal_reason: string;
  may_complete: boolean;
  outcome: string;
  truth: "execution_work_not_security_coverage";
}

export interface AttemptRuntimeSummary {
  limitations?: string[];
  state: string;
  outcome: string | null;
  bootstrap: { status?: string };
  local_blackbox_tools: AttemptToolRun[];
  work_ledger?: WorkLedgerSummary | null;
}

export interface OperationInventoryItemView {
  origin: string;
  method: string;
  path: string;
  parameters: string[];
  content_type: string | null;
  auth_context: string;
  side_effect_class: string;
  applicable_test_categories: string[];
  source: string;
  discovery_metadata?: {
    parameter_hints?: { name: string; location: string; type: string; required: boolean }[];
    protocol_selector?: string;
    state_refs?: string[];
  };
}

export interface OperationInventoryRecordView {
  operation: OperationInventoryItemView;
  outcome: "applicable" | "passed" | "failed" | "blocked" | "inapplicable";
  reason_code: string | null;
  digest: string;
}

export interface OperationInventoryView {
  schema_version: string;
  engagement_id: string;
  attempt_id: string;
  items: OperationInventoryRecordView[];
  coverage: Record<string, number>;
}

export interface AttemptActivityItem {
  id: string;
  source: "assessment" | "workflow" | "orchestrator" | "findings";
  sequence: number;
  occurred_at: string;
  title: string;
  detail: string;
  status: string;
  command: string | null;
  result: string | null;
  is_current: boolean;
}

export interface AttemptActivityFeed {
  schema_version: "sccap.pentest.activity-feed.v1";
  engagement_id: string;
  attempt_id: string;
  attempt_state: string;
  is_terminal: boolean;
  items: AttemptActivityItem[];
}

export interface AttemptToolObservation {
  id: string;
  tool: components["schemas"]["AttemptToolObservationV1"]["tool"];
  category: components["schemas"]["AttemptToolObservationV1"]["category"];
  title: string;
  detail: string;
  severity: string | null;
  status: string | null;
  fields: { label: string; value: string }[];
  evidence_refs?: string[];
}

export interface AttemptToolCommand {
  tool: components["schemas"]["AttemptToolCommandV1"]["tool"];
  command: string;
  result: string;
  status: string;
}

export interface AttemptToolObservations {
  schema_version: "sccap.pentest.tool-observations.v1";
  engagement_id: string;
  attempt_id: string;
  total_observations: number;
  detail_status: "available" | "partial" | "unavailable";
  commands: AttemptToolCommand[];
  items: AttemptToolObservation[];
  evidence?: { id: string; execution_id: string; evidence_type: string; media_type: string; size_bytes: number; committed_at: string }[];
  limitation: string;
}

export interface FindingSurface {
  target_ref: string;
  operation_ref: string;
  opaque_identity_ref: string | null;
  component_ref: string | null;
  object_ref: string | null;
}

export interface FindingCandidate {
  candidate_finding_id: string;
  current_revision_id: string;
  current_revision: number;
  lifecycle_state: string;
  truth_disposition: string;
  title: string;
  claim_kind: string;
  verification_route: "deterministic_predicate" | "independent_reproduction";
  confidence: "low" | "moderate" | "high";
  affected_surfaces: FindingSurface[];
  supporting_evidence_refs: string[];
  refuting_evidence_refs: string[];
  contradiction_state: "none" | "suspected" | "material";
  limitations: string[];
  updated_at: string;
}

export interface FindingVerification {
  verification_request_id: string;
  candidate_finding_id: string;
  candidate_revision_id: string;
  cycle: number;
  trigger: string;
  route: "deterministic_predicate" | "independent_reproduction";
  state: string;
  disposition: string;
  reason_code: string | null;
  limitations: string[];
  created_at: string;
  expires_at: string;
}

export interface ConfirmedFinding {
  confirmed_finding_id: string;
  candidate_finding_id: string;
  current_revision_id: string;
  current_revision: number;
  current_state: "active" | "contested" | "invalidated" | "superseded";
  verification_assurance: "deterministic_exact_fact" | "independent_behavioral_reproduction";
  title: string;
  expected_behavior: string;
  observed_behavior: string;
  security_impact: string;
  surfaces: FindingSurface[];
  evidence_refs: string[];
  severity: {
    technical_score: number;
    technical_vector: string;
    technical_band: "informational" | "low" | "medium" | "high" | "critical";
    business_impact: string;
    final_band: "informational" | "low" | "medium" | "high" | "critical";
    reason_codes: string[];
  };
  created_at: string;
  updated_at: string;
}

interface FindingTruthPage<T> {
  items: T[];
  next_cursor: string | null;
}

export interface FindingObservation {
  observation_id: string;
  lifecycle_state: string;
  observation_type: string;
  title: string;
  evidence_refs: string[];
  limitations: string[];
  observed_at: string;
  committed_at: string;
}

export interface FindingLifecycle {
  candidates: FindingCandidate[];
  verifications: FindingVerification[];
  confirmed: ConfirmedFinding[];
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

  listAssessments: async (filters: C13Filters & { project_id?: string; engagement_id?: string } = {}, signal?: AbortSignal) =>
    (await apiClient.get<CursorPage<AssessmentSummary>>("/pentesting/assessments", { params: { ...params(filters), project_id: filters.project_id, engagement_id: filters.engagement_id }, signal })).data,
  restartEngagement: async (engagementId: string, expectedStateVersion: number, commandKey: string) =>
    (await apiClient.post<{ engagement_id: string; attempt_id: string }>(`/pentesting/engagements/${part(engagementId)}/commands/restart`, {
      schema_version: "sccap.pentest.v1", command_version: "sccap.pentest.attempt-command.v2", command_idempotency_key: commandKey,
      expected_state_version: expectedStateVersion,
    })).data,
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

  getAttemptSummary: async (engagementId: string, attemptId: string, signal?: AbortSignal) =>
    (await apiClient.get<AttemptRuntimeSummary>(`${attemptPath(engagementId, attemptId)}/summary`, { signal })).data,

  getActivityFeed: async (engagementId: string, attemptId: string, signal?: AbortSignal) =>
    (await apiClient.get<AttemptActivityFeed>(`${attemptPath(engagementId, attemptId)}/activity-feed`, { signal })).data,

  getToolObservations: async (engagementId: string, attemptId: string, signal?: AbortSignal) =>
    (await apiClient.get<AttemptToolObservations>(`${attemptPath(engagementId, attemptId)}/tool-observations`, { signal })).data,

  getThreatModel: async (engagementId: string, attemptId: string, signal?: AbortSignal) =>
    (await apiClient.get<ThreatModelView>(`${attemptPath(engagementId, attemptId)}/threat-model`, { signal })).data,

  getOperationInventory: async (engagementId: string, attemptId: string, signal?: AbortSignal) =>
    (await apiClient.get<OperationInventoryView>(`${attemptPath(engagementId, attemptId)}/operation-inventory`, { signal })).data,

  getFindingObservations: async (engagementId: string, attemptId: string, signal?: AbortSignal): Promise<FindingObservation[]> => {
    const items: FindingObservation[] = [];
    let cursor: string | null = null;
    do {
      const { data }: { data: FindingTruthPage<FindingObservation> } = await apiClient.get(`${attemptPath(engagementId, attemptId)}/observations`, { params: { limit: 200, ...(cursor ? { cursor } : {}) }, signal });
      items.push(...data.items);
      cursor = data.next_cursor;
    } while (cursor);
    return items;
  },

  getFindingLifecycle: async (engagementId: string, attemptId: string, signal?: AbortSignal): Promise<FindingLifecycle> => {
    const path = attemptPath(engagementId, attemptId);
    const [candidates, verifications, confirmed] = await Promise.all([
      apiClient.get<FindingTruthPage<FindingCandidate>>(`${path}/candidates`, { params: { limit: 200 }, signal }),
      apiClient.get<FindingTruthPage<FindingVerification>>(`${path}/verifications`, { params: { limit: 200 }, signal }),
      apiClient.get<FindingTruthPage<ConfirmedFinding>>(`${path}/confirmed-findings`, { params: { limit: 200 }, signal }),
    ]);
    return {
      candidates: candidates.data.items,
      verifications: verifications.data.items,
      confirmed: confirmed.data.items,
    };
  },

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
