import type { components, operations } from "../types/api-generated";

type Schemas = components["schemas"];
type JsonResponse<Operation extends { responses: unknown }> =
  Operation extends {
    responses: { 200: { content: { "application/json": infer Response } } };
  }
    ? Response
    : never;

export type CreateScanRequest =
  operations["create_scan_api_v1_scans_post"]["requestBody"]["content"]["multipart/form-data"];
export type CreateScanResponse = JsonResponse<
  operations["create_scan_api_v1_scans_post"]
>;
export type ScanResultWire = JsonResponse<
  operations["get_scan_result_details_api_v1_scans__scan_id__result_get"]
>;
export type ScanResultQuery = NonNullable<
  operations["get_scan_result_details_api_v1_scans__scan_id__result_get"]["parameters"]["query"]
>;
export type ScanReportQuery = NonNullable<
  operations["download_scan_report_api_v1_scans__scan_id__report_get"]["parameters"]["query"]
>;
export type ScanValidationError =
  operations["create_scan_api_v1_scans_post"]["responses"][422]["content"]["application/json"];

/** Keep multipart field names coupled to the generated request schema. */
export function appendScanField(
  form: FormData,
  field: keyof CreateScanRequest,
  value: string | Blob,
): void {
  form.append(field, value);
}

export type FindingDisposition =
  | "open"
  | "confirmed"
  | "false_positive"
  | "remediated"
  | "risk_accepted";

export interface SuggestedFix {
  description?: string;
  original_snippet?: string;
  code?: string;
}

export interface AffectedLocation {
  line_number: number;
  snippet?: string | null;
}

type FindingWire = Schemas["VulnerabilityFindingResponse"];
export type Finding = Omit<
  FindingWire,
  | "affected_locations"
  | "fixes"
  | "cross_file_status"
  | "disposition"
> & {
  affected_locations?: AffectedLocation[] | null;
  fixes?: SuggestedFix | null;
  cross_file_status?: "confirmed" | "mitigated" | "unconfirmed" | null;
  disposition: FindingDisposition;
};

type SubmittedFileWire = Schemas["SubmittedFileReportItem"];
export type SubmittedFile = Omit<SubmittedFileWire, "findings"> & {
  findings: Finding[];
};

type SummaryReportWire = Schemas["SummaryReportResponse"];
export type SummaryReport = Omit<SummaryReportWire, "files_analyzed"> & {
  files_analyzed: SubmittedFile[];
};

export type Summary = Schemas["SummaryResponse"];
export type OverallRiskScore = Schemas["OverallRiskScoreResponse"];
export type LLMUsageItem = Schemas["LLMUsageItem"];
export type ConsolidationStats = Schemas["ConsolidationStats"];

export interface CostSlot {
  total_estimated_cost?: number;
  expected_estimated_cost?: number;
  upper_bound_estimated_cost?: number;
}

export interface CostDetails {
  input_cost?: number;
  predicted_output_cost?: number;
  total_estimated_cost?: number;
  expected_estimated_cost?: number;
  upper_bound_estimated_cost?: number;
  predicted_output_tokens?: number;
  total_input_tokens?: number;
  upper_bound_input_tokens?: number;
  upper_bound_output_tokens?: number;
  expected_request_count?: number;
  upper_bound_request_count?: number;
  estimate_confidence?: "low" | "medium" | "high";
  estimate_source?: string;
  estimate_price_source?: string;
  estimate_sample_count?: number;
  estimate_assumptions?: string[];
  planned_request_count?: number;
  rendered_envelope_includes?: string[];
  slots?: Record<string, CostSlot>;
}

export interface ScannerProvenance {
  status: "verified" | "degraded";
  immutable: boolean;
  reasons: string[];
  binary?: {
    version?: string | null;
    sha256?: string | null;
  };
  rules?: {
    status?: "verified" | "degraded";
    selected_rule_count?: number;
    ruleset_sha256?: string;
    sources?: Array<{
      slug?: string;
      configured_ref?: string;
      resolved_commit_sha?: string | null;
    }>;
  };
  advisory_database?: {
    mode?: string;
    immutable?: boolean;
    status?: string;
    reason?: string;
  };
}

export type ToolchainProvenance = Record<string, ScannerProvenance>;

export type ScannerCoverageStatus =
  | "planned"
  | "completed"
  | "clean"
  | "skipped"
  | "failed"
  | "timeout"
  | "unsupported"
  | "truncated";

export interface ScannerCoverageEntry {
  id: string;
  scanner_name: string;
  input_path: string;
  status: ScannerCoverageStatus;
  reason_code?: string | null;
  reason?: string | null;
  finding_count: number;
  native_evidence_available: boolean;
  provenance_status?: string | null;
}

export interface ScannerCoverageManifest {
  attempt_id: string;
  overall_status: "unavailable" | "complete" | "degraded";
  is_complete: boolean;
  counts: Record<string, number>;
  entries: ScannerCoverageEntry[];
  latest_policy_decision?: {
    id: string;
    outcome: "pass" | "fail" | "waived";
    failing_states: string[];
    matching_entry_ids: string[];
    audit_reason: string;
    actor_user_id?: number | null;
    created_at: string;
  } | null;
}

export interface FindingGovernanceItem {
  finding_id?: number | null;
  fingerprint: string;
  baseline_state: "new" | "fixed" | "unchanged" | "reintroduced";
  exact_ranges: Array<Record<string, unknown>>;
  source_provenance: Record<string, unknown>;
  producer_provenance: Record<string, unknown>;
  coverage_entry_ids: string[];
  evidence_object_ids: string[];
  remediation_state: Record<string, unknown>;
}

export interface FindingGovernanceSummary {
  counts: Record<"new" | "fixed" | "unchanged" | "reintroduced", number>;
  items: FindingGovernanceItem[];
  policy_evaluation?: {
    outcome: "pass" | "fail";
    coverage_complete: boolean;
    blocking_fingerprints: string[];
    waived_fingerprints: string[];
    policy_version_id: string;
  } | null;
}

export interface ApprovalGate {
  gate_id: string;
  scan_id: string;
  node_name: string;
  kind: "prescan_approval" | "profiling_approval" | "cost_approval";
  sequence: number;
  display_name: string;
  purpose: string;
  evidence_hash: string;
  state: "pending" | "decided" | "resume_claimed" | "completed" | "expired" | "cancelled";
  version: number;
  decision?: boolean | null;
  created_at: string;
  decided_at?: string | null;
  completed_at?: string | null;
}

export type ScanResultResponse = Omit<
  ScanResultWire,
  | "summary_report"
  | "cost_details"
  | "stage_temperatures"
  | "toolchain_provenance"
  | "active_approval_gate"
> & {
  summary_report?: SummaryReport | null;
  cost_details?: CostDetails | null;
  stage_temperatures?: Record<string, number> | null;
  toolchain_provenance: ToolchainProvenance;
  active_approval_gate?: ApprovalGate | null;
  scanner_coverage?: ScannerCoverageManifest | null;
  finding_governance: FindingGovernanceSummary;
};

const COVERAGE_STATES = new Set<ScannerCoverageStatus>([
  "planned", "completed", "clean", "skipped", "failed", "timeout",
  "unsupported", "truncated",
]);

function normalizeScannerCoverage(value: unknown): ScannerCoverageManifest | null {
  if (!isRecord(value) || !Array.isArray(value.entries)) return null;
  const entries = value.entries.flatMap((raw): ScannerCoverageEntry[] => {
    if (!isRecord(raw) || !COVERAGE_STATES.has(raw.status as ScannerCoverageStatus)) {
      return [];
    }
    return [{
      id: String(raw.id ?? ""),
      scanner_name: String(raw.scanner_name ?? "unknown"),
      input_path: String(raw.input_path ?? "unknown"),
      status: raw.status as ScannerCoverageStatus,
      reason_code: raw.reason_code === null ? null : optionalString(raw.reason_code),
      reason: raw.reason === null ? null : optionalString(raw.reason),
      finding_count: finiteNumber(raw.finding_count) ?? 0,
      native_evidence_available: raw.native_evidence_available === true,
      provenance_status:
        raw.provenance_status === null ? null : optionalString(raw.provenance_status),
    }];
  });
  const status = value.overall_status === "complete"
    ? "complete"
    : value.overall_status === "degraded"
      ? "degraded"
      : "unavailable";
  const decision = isRecord(value.latest_policy_decision)
    ? {
        id: String(value.latest_policy_decision.id ?? ""),
        outcome: value.latest_policy_decision.outcome === "pass"
          ? "pass" as const
          : value.latest_policy_decision.outcome === "waived"
            ? "waived" as const
            : "fail" as const,
        failing_states: Array.isArray(value.latest_policy_decision.failing_states)
          ? value.latest_policy_decision.failing_states.filter(
              (item): item is string => typeof item === "string",
            )
          : [],
        matching_entry_ids: Array.isArray(value.latest_policy_decision.matching_entry_ids)
          ? value.latest_policy_decision.matching_entry_ids.filter(
              (item): item is string => typeof item === "string",
            )
          : [],
        audit_reason: String(value.latest_policy_decision.audit_reason ?? ""),
        actor_user_id: finiteNumber(value.latest_policy_decision.actor_user_id),
        created_at: String(value.latest_policy_decision.created_at ?? ""),
      }
    : null;
  return {
    attempt_id: String(value.attempt_id ?? ""),
    overall_status: status,
    is_complete: value.is_complete === true,
    counts: normalizeNumberRecord(isRecord(value.counts) ? value.counts : undefined) ?? {},
    entries,
    latest_policy_decision: decision,
  };
}

function normalizeFindingGovernance(value: unknown): FindingGovernanceSummary {
  const emptyCounts = { new: 0, fixed: 0, unchanged: 0, reintroduced: 0 };
  if (!isRecord(value)) return { counts: emptyCounts, items: [] };
  const rawCounts = isRecord(value.counts) ? value.counts : {};
  const counts = {
    new: finiteNumber(rawCounts.new) ?? 0,
    fixed: finiteNumber(rawCounts.fixed) ?? 0,
    unchanged: finiteNumber(rawCounts.unchanged) ?? 0,
    reintroduced: finiteNumber(rawCounts.reintroduced) ?? 0,
  };
  const items = Array.isArray(value.items)
    ? value.items.flatMap((raw): FindingGovernanceItem[] => {
        if (!isRecord(raw) || ![
          "new", "fixed", "unchanged", "reintroduced",
        ].includes(String(raw.baseline_state))) return [];
        return [{
          finding_id: finiteNumber(raw.finding_id),
          fingerprint: String(raw.fingerprint ?? ""),
          baseline_state: raw.baseline_state as FindingGovernanceItem["baseline_state"],
          exact_ranges: Array.isArray(raw.exact_ranges)
            ? raw.exact_ranges.filter(isRecord)
            : [],
          source_provenance: isRecord(raw.source_provenance) ? raw.source_provenance : {},
          producer_provenance: isRecord(raw.producer_provenance) ? raw.producer_provenance : {},
          coverage_entry_ids: Array.isArray(raw.coverage_entry_ids)
            ? raw.coverage_entry_ids.map(String)
            : [],
          evidence_object_ids: Array.isArray(raw.evidence_object_ids)
            ? raw.evidence_object_ids.map(String)
            : [],
          remediation_state: isRecord(raw.remediation_state) ? raw.remediation_state : {},
        }];
      })
    : [];
  const rawEvaluation = isRecord(value.policy_evaluation)
    ? value.policy_evaluation
    : null;
  const policyEvaluation = rawEvaluation && ["pass", "fail"].includes(String(rawEvaluation.outcome))
    ? {
        outcome: rawEvaluation.outcome as "pass" | "fail",
        coverage_complete: rawEvaluation.coverage_complete === true,
        blocking_fingerprints: Array.isArray(rawEvaluation.blocking_fingerprints)
          ? rawEvaluation.blocking_fingerprints.map(String)
          : [],
        waived_fingerprints: Array.isArray(rawEvaluation.waived_fingerprints)
          ? rawEvaluation.waived_fingerprints.map(String)
          : [],
        policy_version_id: String(rawEvaluation.policy_version_id ?? ""),
      }
    : null;
  return { counts, items, policy_evaluation: policyEvaluation };
}

const DISPOSITIONS = new Set<FindingDisposition>([
  "open",
  "confirmed",
  "false_positive",
  "remediated",
  "risk_accepted",
]);
const CROSS_FILE_STATUSES = new Set([
  "confirmed",
  "mitigated",
  "unconfirmed",
] as const);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function finiteNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value)
    ? value
    : undefined;
}

function normalizeFinding(finding: FindingWire): Finding {
  const rawFix = finding.fixes;
  const fixes = isRecord(rawFix)
    ? {
        description: optionalString(rawFix.description),
        original_snippet: optionalString(rawFix.original_snippet),
        code: optionalString(rawFix.code),
      }
    : rawFix === null
      ? null
      : undefined;
  const affectedLocations = Array.isArray(finding.affected_locations)
    ? finding.affected_locations.flatMap((location) => {
        if (!isRecord(location) || typeof location.line_number !== "number") {
          return [];
        }
        return [{
          line_number: location.line_number,
          snippet:
            location.snippet === null
              ? null
              : optionalString(location.snippet),
        }];
      })
    : finding.affected_locations === null
      ? null
      : undefined;
  const disposition = DISPOSITIONS.has(finding.disposition as FindingDisposition)
    ? (finding.disposition as FindingDisposition)
    : "open";
  const crossFileStatus = CROSS_FILE_STATUSES.has(
    finding.cross_file_status as (typeof CROSS_FILE_STATUSES extends Set<infer T> ? T : never),
  )
    ? (finding.cross_file_status as "confirmed" | "mitigated" | "unconfirmed")
    : null;

  return {
    ...finding,
    affected_locations: affectedLocations,
    fixes,
    cross_file_status: crossFileStatus,
    disposition,
  };
}

function normalizeSummaryReport(
  report: SummaryReportWire | null | undefined,
): SummaryReport | null | undefined {
  if (report === null || report === undefined) return report;
  return {
    ...report,
    files_analyzed: report.files_analyzed.map((file) => ({
      ...file,
      findings: file.findings.map(normalizeFinding),
    })),
  };
}

function normalizeCostDetails(
  value: Record<string, unknown> | null | undefined,
): CostDetails | null | undefined {
  if (value === null || value === undefined) return value;
  const result = Object.fromEntries(
    [
      ["input_cost", finiteNumber(value.input_cost)],
      ["predicted_output_cost", finiteNumber(value.predicted_output_cost)],
      ["total_estimated_cost", finiteNumber(value.total_estimated_cost)],
      ["expected_estimated_cost", finiteNumber(value.expected_estimated_cost)],
      ["upper_bound_estimated_cost", finiteNumber(value.upper_bound_estimated_cost)],
      ["predicted_output_tokens", finiteNumber(value.predicted_output_tokens)],
      ["total_input_tokens", finiteNumber(value.total_input_tokens)],
      ["upper_bound_input_tokens", finiteNumber(value.upper_bound_input_tokens)],
      ["upper_bound_output_tokens", finiteNumber(value.upper_bound_output_tokens)],
      ["expected_request_count", finiteNumber(value.expected_request_count)],
      ["upper_bound_request_count", finiteNumber(value.upper_bound_request_count)],
      ["estimate_sample_count", finiteNumber(value.estimate_sample_count)],
      ["planned_request_count", finiteNumber(value.planned_request_count)],
    ].filter((entry) => entry[1] !== undefined),
  ) as CostDetails;
  if (["low", "medium", "high"].includes(String(value.estimate_confidence))) {
    result.estimate_confidence = value.estimate_confidence as CostDetails["estimate_confidence"];
  }
  if (typeof value.estimate_source === "string") {
    result.estimate_source = value.estimate_source;
  }
  if (typeof value.estimate_price_source === "string") {
    result.estimate_price_source = value.estimate_price_source;
  }
  if (Array.isArray(value.estimate_assumptions)) {
    result.estimate_assumptions = value.estimate_assumptions.filter(
      (item): item is string => typeof item === "string",
    );
  }
  if (Array.isArray(value.rendered_envelope_includes)) {
    result.rendered_envelope_includes = value.rendered_envelope_includes.filter(
      (item): item is string => typeof item === "string",
    );
  }
  if (isRecord(value.slots)) {
    const slots = Object.fromEntries(
      Object.entries(value.slots).flatMap(([name, slot]) => {
        if (!isRecord(slot)) return [];
        const normalizedSlot = Object.fromEntries(
          [
            ["total_estimated_cost", finiteNumber(slot.total_estimated_cost)],
            ["expected_estimated_cost", finiteNumber(slot.expected_estimated_cost)],
            ["upper_bound_estimated_cost", finiteNumber(slot.upper_bound_estimated_cost)],
          ].filter((entry) => entry[1] !== undefined),
        ) as CostSlot;
        return Object.keys(normalizedSlot).length === 0
          ? []
          : [[name, normalizedSlot]];
      }),
    ) as Record<string, CostSlot>;
    if (Object.keys(slots).length > 0) result.slots = slots;
  }
  return Object.keys(result).length > 0 ? result : null;
}

function normalizeNumberRecord(
  value: Record<string, unknown> | null | undefined,
): Record<string, number> | null | undefined {
  if (value === null || value === undefined) return value;
  const entries = Object.entries(value).filter(
    (entry): entry is [string, number] =>
      typeof entry[1] === "number" && Number.isFinite(entry[1]),
  );
  return entries.length > 0 ? Object.fromEntries(entries) : null;
}

function normalizeToolchainProvenance(
  value: Record<string, unknown> | undefined,
): ToolchainProvenance {
  if (!value) return {};
  return Object.fromEntries(
    Object.entries(value).flatMap(([scanner, raw]) => {
      if (!isRecord(raw)) return [];
      const status = raw.status === "verified" ? "verified" : "degraded";
      const binary = isRecord(raw.binary)
        ? {
            version:
              raw.binary.version === null
                ? null
                : optionalString(raw.binary.version),
            sha256:
              raw.binary.sha256 === null
                ? null
                : optionalString(raw.binary.sha256),
          }
        : undefined;
      const rules = isRecord(raw.rules)
        ? {
            status:
              raw.rules.status === "verified" ? "verified" as const : "degraded" as const,
            selected_rule_count: finiteNumber(raw.rules.selected_rule_count),
            ruleset_sha256: optionalString(raw.rules.ruleset_sha256),
            sources: Array.isArray(raw.rules.sources)
              ? raw.rules.sources.flatMap((source) =>
                  isRecord(source)
                    ? [{
                        slug: optionalString(source.slug),
                        configured_ref: optionalString(source.configured_ref),
                        resolved_commit_sha:
                          source.resolved_commit_sha === null
                            ? null
                            : optionalString(source.resolved_commit_sha),
                      }]
                    : [],
                )
              : undefined,
          }
        : undefined;
      const advisory = isRecord(raw.advisory_database)
        ? {
            mode: optionalString(raw.advisory_database.mode),
            immutable:
              typeof raw.advisory_database.immutable === "boolean"
                ? raw.advisory_database.immutable
                : undefined,
            status: optionalString(raw.advisory_database.status),
            reason: optionalString(raw.advisory_database.reason),
          }
        : undefined;
      return [[scanner, {
        status,
        immutable: raw.immutable === true,
        reasons: Array.isArray(raw.reasons)
          ? raw.reasons.filter((reason): reason is string => typeof reason === "string")
          : [],
        binary,
        rules,
        advisory_database: advisory,
      } satisfies ScannerProvenance]];
    }),
  );
}

/**
 * Narrows the two intentionally free-form JSON objects in the backend schema
 * before UI code renders them. All other fields remain tied directly to the
 * generated operation response, including nullable report and error states.
 */
export function normalizeScanResult(wire: ScanResultWire): ScanResultResponse {
  const gate = (wire as ScanResultWire & {
    active_approval_gate?: ApprovalGate | null;
  }).active_approval_gate;
  const coverage = (wire as ScanResultWire & {
    scanner_coverage?: unknown;
  }).scanner_coverage;
  const governance = (wire as ScanResultWire & {
    finding_governance?: unknown;
  }).finding_governance;
  return {
    ...wire,
    summary_report: normalizeSummaryReport(wire.summary_report),
    cost_details: normalizeCostDetails(wire.cost_details),
    stage_temperatures: normalizeNumberRecord(wire.stage_temperatures),
    toolchain_provenance: normalizeToolchainProvenance(
      wire.toolchain_provenance,
    ),
    active_approval_gate: gate,
    scanner_coverage: normalizeScannerCoverage(coverage),
    finding_governance: normalizeFindingGovernance(governance),
  };
}
