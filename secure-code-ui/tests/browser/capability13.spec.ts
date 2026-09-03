import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { login } from "./support";

const installSnapshot = (page: import("@playwright/test").Page) => page.route("**/api/v1/pentesting/engagements/e-1/attempts/a-1/cockpit-snapshot", (route) => route.fulfill({ json: {
  contract_major: 1, snapshot_id: "s-1", owner: { tenant_id: "00000000-0000-0000-0000-000000000001", project_id: "p-1", engagement_id: "e-1", attempt_id: "a-1" }, attempt_generation: 1, attempt_state: "completed", attempt_is_terminal: true,
  source_cutoff: { aggregate_sequence: 8, event_digest: "event-digest", captured_at: "2026-09-03T00:00:00Z" }, source_pins: [], objective: null, current_decision: null, active_executions: [], waiting_executions: [], unresolved_questions: [], observation_summary: [{ label: "observed", count: 1 }], finding_summary: [{ label: "confirmed", count: 1 }], coverage_summary: [], cleanup_summary: [], callback_summary: [], usage_summary: [], timeline: [], edges: [], projection_state: "partial", limitation_codes: ["C9_PROJECTION_PENDING"], snapshot_digest: "snapshot-digest", actions: { can_create_report: false, can_publish_report: false, can_export_evidence: false, can_request_governance: false, can_approve_governance: false, can_create_retest: false, disabled_reasons: {} },
} }));

test("C13 cockpit separates authority, remains usable at 390px, and exposes no URL credential", async ({ page }) => {
  await login(page);
  await installSnapshot(page);
  const streamRequests: string[] = [];
  page.on("request", (request) => { if (request.url().includes("cockpit-stream")) streamRequests.push(request.url()); });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/pentesting/engagements/e-1/attempts/a-1/overview");
  await expect(page.getByRole("heading", { name: "Causal cockpit" })).toBeVisible();
  await expect(page.getByText("Attempt ended; owner projections are still settling")).toBeVisible();
  await expect(page.getByRole("tab", { name: "Observations" })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Findings" })).toBeVisible();
  expect(streamRequests.every((url) => !/[?&](token|access_token|stream_token)=/i.test(url))).toBe(true);
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  expect(results.violations.filter((item) => item.impact === "serious" || item.impact === "critical")).toEqual([]);
});

test("C13 attempt tabs support arrow-key traversal", async ({ page }) => {
  await login(page);
  await installSnapshot(page);
  await page.goto("/pentesting/engagements/e-1/attempts/a-1/overview");
  const overview = page.getByRole("tab", { name: "Overview" });
  await overview.focus();
  await page.keyboard.press("ArrowRight");
  await expect(page.getByRole("tab", { name: "Activity" })).toBeFocused();
});
