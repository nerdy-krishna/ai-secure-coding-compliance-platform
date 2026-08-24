import { expect, test, type Page } from "@playwright/test";

const candidateId = "11111111-1111-4111-8111-111111111111";
const conflictedCandidateId = "77777777-7777-4777-8777-777777777777";
const canonicalId = "22222222-2222-4222-8222-222222222222";

async function login(page: Page) {
  const email = process.env.SCCAP_BROWSER_EMAIL;
  const password = process.env.SCCAP_BROWSER_PASSWORD;
  if (!email || !password) throw new Error("Task33 browser credentials are required");
  await page.goto("/login");
  await page.getByLabel("Username or email").fill(email);
  await page.getByLabel("Password", { exact: false }).fill(password);
  await page.waitForTimeout(800);
  await page.getByRole("button", { name: "Log in" }).click();
  await expect(page).toHaveURL(/\/account\/dashboard$/);
  await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Dashboard", exact: true })).toBeVisible();
}

function result(scanId: string, mode: "SUGGEST" | "REMEDIATE", legacy = false) {
  const finding = {
    id: 33, coverage_entry_ids: [], raw_finding_id: null,
    canonical_finding_id: canonicalId, contributing_raw_finding_ids: ["33333333-3333-4333-8333-333333333333"],
    source_snapshot_hash: "a".repeat(64), fix_selection_status: "selected",
    file_path: "src/app.py", title: "Repeated unsafe call", cwe: "CWE-89",
    description: "The second repeated call is unsafe.", severity: "High", line_number: 3,
    vulnerable_snippet: "danger(value)", affected_locations: [], remediation: "Use the safe API.",
    confidence: "High", source: "semgrep", corroborating_agents: [], detected_by_llms: [],
    cvss_score: 8.1, cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    references: [], fixes: legacy ? { original_snippet: "danger(value)", code: "safe(value)" } : null,
    is_applied_in_remediation: mode === "REMEDIATE", fix_verified: mode === "REMEDIATE",
    disposition: mode === "REMEDIATE" ? "remediated" : "open",
  };
  return {
    status: mode === "REMEDIATE" ? "REMEDIATION_COMPLETED" : "COMPLETED",
    error_message: "", project_id: "44444444-4444-4444-8444-444444444444", project_name: "Task33",
    scan_type: mode, cross_file_validation: false, deep_vendor_scan: false,
    disable_temperature: false, has_resumable_artifacts: false, source_counts: { semgrep: 1 },
    toolchain_provenance: {}, finding_governance: { counts: { new: 1, fixed: 0, unchanged: 0, reintroduced: 0 }, items: [] },
    summary_report: {
      submission_id: scanId, project_id: "44444444-4444-4444-8444-444444444444", project_name: "Task33",
      scan_type: mode, selected_frameworks: [], summary: { total_findings_count: mode === "REMEDIATE" ? 0 : 1, files_analyzed_count: 1, severity_counts: { HIGH: mode === "REMEDIATE" ? 0 : 1 } },
      overall_risk_score: { score: mode === "REMEDIATE" ? 0 : 8.1, severity: mode === "REMEDIATE" ? "None" : "High" },
      files_analyzed: [{ file_path: "src/app.py", findings: [finding], language: "python" }],
      remediation: legacy ? null : { outcome: mode === "REMEDIATE" ? "partial_remediation" : "validated_suggestion", candidates: { proposed: 2, planned: 1, validated: 1, deduplicated: 0, conflicted: 1, rejected: 0, unverified: 1, applied: mode === "REMEDIATE" ? 1 : 0 }, files: { total: 2, planned: 1, manual_review: 1 }, validation_checks: { passed: 1, failed: 1 } },
    },
    original_code_map: { "src/app.py": "danger(value)\nokay()\ndanger(value)\n" },
    fixed_code_map: mode === "REMEDIATE" ? { "src/app.py": "danger(value)\nokay()\nsafe(value)\n" } : null,
    patch_plan: legacy ? null : {
      schema_version: 2, scan_id: scanId,
      files: [{ file_path: "src/app.py", source_snapshot_hash: "a".repeat(64), output_hash: "b".repeat(64), status: "planned",
        hunks: [
          { patch_hunk_id: "66666666-6666-4666-8666-666666666666", candidate_ids: ["99999999-9999-4999-8999-999999999999"], resolved_range: { start_byte: 0, end_byte: 13, start_line: 1, start_column: 1, end_line: 1, end_column: 14 }, context_fingerprint: "d".repeat(64), original_text: "danger(value)", replacement_text: "other(value)" },
          { patch_hunk_id: "55555555-5555-4555-8555-555555555555", candidate_ids: [candidateId], resolved_range: { start_byte: 21, end_byte: 34, start_line: 3, start_column: 1, end_line: 3, end_column: 14 }, context_fingerprint: "c".repeat(64), original_text: "danger(value)", replacement_text: "safe(value)" },
        ],
        requirements: [{ candidate_id: candidateId, required_imports: ["from secure import safe"], required_dependencies: [], configuration_changes: [], migration_changes: [], required_commands: [], manual_steps: [] }],
        validation_checks: [
          { stage: "python_compile", profile: "python_compile", status: "passed", blocking: true, tool: "python", tool_version: "Python 3.13.7", completed_at: "2026-08-24T12:00:00Z", detail: "Compiled." },
          { stage: "python_pytest", profile: "python_pytest", status: "passed", blocking: true, tool: "pytest", tool_version: "pytest 9.0", completed_at: "2026-08-24T12:00:01Z", detail: "Tests passed." },
        ], unified_diff: "--- a/src/app.py\n+++ b/src/app.py\n@@ -3 +3 @@\n-danger(value)\n+safe(value)\n", conflict_components: [] },
        ...(mode === "REMEDIATE" ? [{ file_path: "src/legacy.py", source_snapshot_hash: "e".repeat(64), output_hash: "e".repeat(64), status: "manual_review_required",
          hunks: [{ patch_hunk_id: "88888888-8888-4888-8888-888888888888", candidate_ids: [conflictedCandidateId], resolved_range: { start_byte: 0, end_byte: 8, start_line: 1, start_column: 1, end_line: 1, end_column: 9 }, context_fingerprint: "f".repeat(64), original_text: "legacy()", replacement_text: "secure()" }],
          requirements: [{ candidate_id: conflictedCandidateId, required_imports: [], required_dependencies: [], configuration_changes: [], migration_changes: [], required_commands: ["pytest legacy"], manual_steps: ["Resolve the competing edit"] }],
          validation_checks: [{ stage: "python_pytest", profile: "python_pytest", status: "failed", blocking: true, tool: "pytest", tool_version: "pytest 9.0", completed_at: "2026-08-24T12:00:02Z", detail: "Legacy test failed." }],
          unified_diff: "--- a/src/legacy.py\n+++ b/src/legacy.py\n@@ -1 +1 @@\n-legacy()\n+secure()\n", conflict_components: [[conflictedCandidateId]] }] : [])],
      candidate_decisions: [
        { candidate_id: candidateId, status: "planned", reason: "Anchor resolved", resolved_range: { start_byte: 21, end_byte: 34, start_line: 3, start_column: 1, end_line: 3, end_column: 14 } },
        ...(mode === "REMEDIATE" ? [{ candidate_id: conflictedCandidateId, status: "conflict", reason: "Competing edit", resolved_range: { start_byte: 0, end_byte: 8, start_line: 1, start_column: 1, end_line: 1, end_column: 9 } }] : []),
      ],
    },
    events: [], llms_used: [], scanner_coverage: null, cost_details: null,
  };
}

async function mockScan(page: Page, scanId: string, payload: ReturnType<typeof result>) {
  await page.route(`**/api/v1/scans/${scanId}/result*`, (route) => route.fulfill({ json: payload }));
  await page.route(`**/api/v1/scans/${scanId}/finding-lineage`, (route) => route.fulfill({ json: {
    nodes: [], edges: [], lineage_quality: "exact", warnings: [], available_expansions: {},
    fix_candidates: [{ candidate_id: candidateId, raw_finding_id: "33333333-3333-4333-8333-333333333333", canonical_finding_id: canonicalId,
      source_snapshot_hash: "a".repeat(64), anchor_fingerprint: "b".repeat(64), patch_fingerprint: "c".repeat(64),
      resolved_range: { start_byte: 21, end_byte: 34, start_line: 3, start_column: 1, end_line: 3, end_column: 14 }, patch_hunk_id: "55555555-5555-4555-8555-555555555555",
      applicability_status: "planned", required_imports: ["from secure import safe"], required_dependencies: [], configuration_changes: [], migration_changes: [], required_commands: ["pytest -q"], manual_steps: [], file_path: "src/app.py", line_number: 3,
      suggestion: {}, disposition: "selected", decision_reason: "Persisted anchor validated.", contributing_agents: [], contributing_models: [], validation_status: "passed", is_applied: payload.scan_type === "REMEDIATE" },
      ...(payload.scan_type === "REMEDIATE" ? [{ candidate_id: conflictedCandidateId, raw_finding_id: "33333333-3333-4333-8333-333333333333", canonical_finding_id: canonicalId,
        source_snapshot_hash: "e".repeat(64), anchor_fingerprint: "f".repeat(64), patch_fingerprint: "0".repeat(64), resolved_range: { start_byte: 0, end_byte: 8, start_line: 1, start_column: 1, end_line: 1, end_column: 9 }, patch_hunk_id: "88888888-8888-4888-8888-888888888888",
        applicability_status: "conflict", required_imports: [], required_dependencies: [], configuration_changes: [], migration_changes: [], required_commands: ["pytest legacy"], manual_steps: ["Resolve the competing edit"], file_path: "src/legacy.py", line_number: 1,
        suggestion: {}, disposition: "conflict", decision_reason: "Competing edit requires review.", contributing_agents: [], contributing_models: [], validation_status: "failed", is_applied: false }] : [])],
  } }));
}

test("authenticated results present exact actionable suggestion and partial remediation truth", async ({ page }) => {
  await login(page);
  await mockScan(page, "task33-suggest", result("task33-suggest", "SUGGEST"));
  await page.goto("/analysis/results/task33-suggest");
  const panel = page.getByTestId("actionable-remediation");
  await expect(panel).toContainText("Validated suggestion · not applied");
  await expect(panel).toContainText("Exact resolved range 3:1–3:14");
  await expect(panel).toContainText("from secure import safe");
  await expect(panel).toContainText("pytest 9.0");
  await expect(panel).toContainText("Python 3.13.7");
  await expect(panel).toContainText("passed");
  await expect(panel.locator('[data-candidate-state="security-verified"]')).toBeVisible();
  await expect(panel.locator('[data-candidate-state="applied"]')).toHaveCount(0);

  await mockScan(page, "task33-remediate", result("task33-remediate", "REMEDIATE"));
  await page.goto("/analysis/results/task33-remediate");
  await expect(page.getByText(
    "PARTIAL REMEDIATION — manual review remains",
    { exact: true },
  )).toBeVisible();
  await expect(page.getByTestId("actionable-remediation").locator('[data-candidate-state="applied"]')).toBeVisible();
  await expect(page.getByTestId("actionable-remediation").locator('[data-candidate-state="conflicted"]')).toBeVisible();
  await expect(page.getByTestId("actionable-remediation").locator('[data-candidate-state="manual-review"]')).toBeVisible();
  await expect(page.getByTestId("actionable-remediation")).toContainText("Legacy test failed.");
  await expect(page.getByTestId("actionable-remediation")).toContainText("Review-only diff · not apply-ready");
});

test("authenticated legacy finding is explicitly approximate", async ({ page }) => {
  await login(page);
  await mockScan(page, "task33-legacy", result("task33-legacy", "SUGGEST", true));
  await page.goto("/analysis/results/task33-legacy");
  await expect(page.getByTestId("legacy-fix-evidence")).toContainText("approximate");
  await expect(page.getByText("approximate / legacy evidence")).toBeVisible();
});
