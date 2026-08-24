import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { Finding, PatchPlanArtifact } from "../../shared/lib/scanContract";
import { ActionableRemediationPanel } from "./ActionableRemediationPanel";

const finding = {
  id: 1, file_path: "src/app.py", line_number: 7, title: "Unsafe call",
  description: "Unsafe", severity: "High", remediation: "Use safe API",
  confidence: "High", references: [], disposition: "open",
  canonical_finding_id: "canonical-1", contributing_raw_finding_ids: [],
  coverage_entry_ids: [], is_applied_in_remediation: false,
} as Finding;

function render(scanType: string, patchPlan?: PatchPlanArtifact | null) {
  return renderToStaticMarkup(
    <QueryClientProvider client={new QueryClient()}>
      <ActionableRemediationPanel scanId="scan-1" scanType={scanType} finding={finding} patchPlan={patchPlan} />
    </QueryClientProvider>,
  );
}

describe("ActionableRemediationPanel", () => {
  it("never claims an audit generated a patch", () => {
    const html = render("AUDIT");
    expect(html).toContain("did not generate, validate, or apply");
    expect(html).not.toContain("git apply");
  });

  it("renders exact persisted ranges and quarantines manual-review diffs", () => {
    const patchPlan = {
      schema_version: 2, scan_id: "scan-1", candidate_decisions: [],
      files: [{
        file_path: "src/app.py", source_snapshot_hash: "a".repeat(64),
        output_hash: "b".repeat(64), status: "manual_review_required",
        hunks: [{ patch_hunk_id: "hunk-1", candidate_ids: ["candidate-1"],
          resolved_range: { start_byte: 4, end_byte: 9, start_line: 7, start_column: 3, end_line: 7, end_column: 8 },
          context_fingerprint: "c".repeat(64), original_text: "bad()", replacement_text: "safe()" }],
        requirements: [{ candidate_id: "candidate-1", required_imports: ["from secure import safe"],
          required_dependencies: [], configuration_changes: [], migration_changes: [],
          required_commands: ["pytest -q"], manual_steps: ["Review conflict"] }],
        validation_checks: [{ stage: "python_pytest", profile: "python_pytest", status: "failed",
          blocking: true, tool: "pytest", tool_version: "pytest 9.0", completed_at: "2026-08-24T12:00:00Z",
          detail: "One test failed." }], unified_diff: "--- a/src/app.py\n+++ b/src/app.py\n",
      }],
    } as PatchPlanArtifact;
    const html = render("SUGGEST", patchPlan);
    expect(html).toContain("Manual review required · no validated patch");
    expect(html).toContain("Exact resolved range 7:3–7:8");
    expect(html).toContain("pytest -q");
    expect(html).toContain("pytest 9.0");
    expect(html).toContain("failed");
    expect(html).toContain("Review-only diff · not apply-ready");
    expect(html).toContain("Do not apply automatically");
    expect(html).not.toContain("git apply scan-scan-1.patch");
  });

  it("offers apply instructions only for validated planned diffs", () => {
    const patchPlan = {
      schema_version: 2, scan_id: "scan-1", candidate_decisions: [],
      files: [{ file_path: "src/app.py", source_snapshot_hash: "a".repeat(64),
        output_hash: "b".repeat(64), status: "planned", hunks: [],
        requirements: [], validation_checks: [],
        unified_diff: "--- a/src/app.py\n+++ b/src/app.py\n" }],
    } as PatchPlanArtifact;
    const html = render("SUGGEST", patchPlan);
    expect(html).toContain("Validated apply-ready unified diff");
    expect(html).toContain("git apply --check scan-scan-1.patch");
  });

  it("marks legacy suggestions approximate instead of validated", () => {
    expect(render("SUGGEST", null)).toContain("approximate");
  });
});
