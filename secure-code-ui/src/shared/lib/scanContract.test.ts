import { describe, expect, it } from "vitest";

import { normalizeScanResult } from "./scanContract";

describe("normalizeScanResult", () => {
  it("preserves nullable terminal responses without inventing a report", () => {
    const result = normalizeScanResult({
      status: "FAILED",
      error_message: "Scanner process exited unexpectedly",
      project_id: "0c5c37a3-6a03-4b60-8991-3416780efe06",
      project_name: "broken-build",
      summary_report: null,
      cost_details: null,
      original_code_map: null,
      fixed_code_map: null,
      cross_file_validation: false,
      deep_vendor_scan: false,
      scan_type: "AUDIT",
      disable_temperature: false,
      stage_temperatures: null,
      repository_url: null,
      source_type: null,
      has_resumable_artifacts: false,
      toolchain_provenance: {},
    });

    expect(result.summary_report).toBeNull();
    expect(result.cost_details).toBeNull();
    expect(result.original_code_map).toBeNull();
    expect(result.error_message).toBe("Scanner process exited unexpectedly");
  });

  it("narrows free-form cost and temperature objects to safe numeric values", () => {
    const result = normalizeScanResult({
      status: "PENDING_COST_APPROVAL",
      error_message: "",
      project_id: "0c5c37a3-6a03-4b60-8991-3416780efe06",
      project_name: "cost-review",
      cost_details: {
        total_estimated_cost: 0.42,
        expected_estimated_cost: 0.42,
        upper_bound_estimated_cost: 0.91,
        total_input_tokens: 1200,
        upper_bound_input_tokens: 2400,
        predicted_output_tokens: "not-a-number",
        estimate_confidence: "medium",
        estimate_source: "canonical_usage_ledger",
        estimate_sample_count: 24,
        estimate_assumptions: ["Uses historical median.", 42],
        planned_request_count: 12,
        slots: {
          reasoning: {
            total_estimated_cost: 0.4,
            upper_bound_estimated_cost: 0.88,
          },
          malformed: "ignore-me",
        },
      },
      cross_file_validation: false,
      deep_vendor_scan: false,
      scan_type: "AUDIT",
      disable_temperature: false,
      stage_temperatures: { analysis: 0.1, invalid: "warm" },
      has_resumable_artifacts: false,
      toolchain_provenance: {
        osv: {
          status: "degraded",
          immutable: false,
          reasons: ["advisory_snapshot_identifier_unavailable", 42],
          binary: { version: "2.3.5", sha256: "b".repeat(64) },
          advisory_database: { mode: "live_osv_api", immutable: false },
        },
        malformed: "ignore-me",
      },
    });

    expect(result.cost_details).toEqual({
      total_estimated_cost: 0.42,
      expected_estimated_cost: 0.42,
      upper_bound_estimated_cost: 0.91,
      total_input_tokens: 1200,
      upper_bound_input_tokens: 2400,
      estimate_confidence: "medium",
      estimate_source: "canonical_usage_ledger",
      estimate_sample_count: 24,
      estimate_assumptions: ["Uses historical median."],
      planned_request_count: 12,
      slots: {
        reasoning: {
          total_estimated_cost: 0.4,
          upper_bound_estimated_cost: 0.88,
        },
      },
    });
    expect(result.stage_temperatures).toEqual({ analysis: 0.1 });
    expect(result.toolchain_provenance.osv).toMatchObject({
      status: "degraded",
      reasons: ["advisory_snapshot_identifier_unavailable"],
      binary: { version: "2.3.5" },
    });
    expect(result.toolchain_provenance.malformed).toBeUndefined();
  });

  it("keeps degraded scanner coverage independent from zero findings", () => {
    const wire = {
      status: "COMPLETED",
      error_message: "",
      project_id: "0c5c37a3-6a03-4b60-8991-3416780efe06",
      project_name: "partial-coverage",
      summary_report: null,
      cross_file_validation: false,
      deep_vendor_scan: false,
      scan_type: "AUDIT",
      disable_temperature: false,
      has_resumable_artifacts: false,
      toolchain_provenance: {},
      scanner_coverage: {
        attempt_id: "09db83ad-ef90-4f82-9957-54795a68c469",
        overall_status: "degraded",
        is_complete: false,
        counts: { clean: 1, timeout: 1 },
        entries: [
          {
            id: "665d7919-3452-4452-9415-d16b21002ad2",
            scanner_name: "semgrep",
            input_path: "src/app.py",
            status: "timeout",
            finding_count: 0,
            native_evidence_available: false,
            reason: "Scanner timed out.",
          },
        ],
      },
    } as unknown as Parameters<typeof normalizeScanResult>[0];

    const result = normalizeScanResult(wire);

    expect(result.scanner_coverage).toMatchObject({
      overall_status: "degraded",
      is_complete: false,
      counts: { clean: 1, timeout: 1 },
    });
    expect(result.scanner_coverage?.entries[0]).toMatchObject({
      scanner_name: "semgrep",
      status: "timeout",
    });
  });
});
