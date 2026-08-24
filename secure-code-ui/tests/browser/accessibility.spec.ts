import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { getBrowserFixture, login } from "./support";

const STATIC_AUTHENTICATED_ROUTES = [
  "/account/dashboard",
  "/submission/submit",
  "/analysis/results",
  "/advisor",
  "/compliance",
  "/account/history",
  "/usage",
  "/account/settings/appearance",
  "/account/settings/security",
  "/admin/system",
  "/admin/features",
  "/admin/appearance",
  "/account/settings/llm",
  "/admin/smtp",
  "/admin/agents",
  "/admin/frameworks",
  "/admin/prompts",
  "/admin/authorization",
  "/admin/findings",
  "/admin/sso/audit",
  "/admin/users",
  "/admin/user-groups",
  "/admin/sso/providers",
  "/admin/scim/tokens",
  "/admin/tenants",
] as const;

// FeatureRoute explicitly redirects disabled modules to the dashboard. No
// other redirect is accepted here: permission, lazy-load, and route wiring
// regressions must fail the inventory instead of passing on a healthy shell.
const FEATURE_GUARDED_ROUTES = new Set<string>([
  "/advisor",
  "/compliance",
  "/admin/smtp",
  "/admin/agents",
  "/admin/frameworks",
  "/admin/prompts",
  "/admin/sso/audit",
  "/admin/users",
  "/admin/user-groups",
  "/admin/sso/providers",
  "/admin/scim/tokens",
  "/admin/tenants",
]);

async function expectRouteDestination(page: Page, route: string): Promise<void> {
  const allowedPaths = FEATURE_GUARDED_ROUTES.has(route)
    ? new Set([route, "/account/dashboard"])
    : new Set([route]);
  await expect
    .poll(() => allowedPaths.has(new URL(page.url()).pathname))
    .toBe(true);
}

async function expectShellContract(page: Page): Promise<void> {
  await expect(page.locator("main#main-content")).toBeVisible();
  await expect(page.locator('[aria-label="Loading page…"]')).toHaveCount(0);
  await expect(
    page.getByRole("heading", { name: "This page could not be loaded" }),
  ).toHaveCount(0);
  await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible();
  await expect(page.locator("button:not([aria-label]):not([aria-labelledby])").filter({ has: page.locator("svg:only-child") })).toHaveCount(0);
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(overflow).toBeLessThanOrEqual(1);
}

test("every authenticated route preserves landmarks, names, and responsive actions", async ({
  page,
}) => {
  test.setTimeout(120_000);
  await login(page);
  const fixture = getBrowserFixture();
  const routes = [
    ...STATIC_AUTHENTICATED_ROUTES,
    `/analysis/scanning/${fixture.gate_scan_id}`,
    `/analysis/projects/${fixture.result_project_id}`,
    `/analysis/results/${fixture.result_scan_id}`,
    `/scans/${fixture.result_scan_id}/diagnostics`,
  ];

  for (const route of routes) {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto(route);
    await expectShellContract(page);
    await expectRouteDestination(page, route);

    await page.setViewportSize({ width: 390, height: 844 });
    await expectShellContract(page);
    await expect(page.getByRole("button", { name: /theme/i })).toBeVisible();
    await expect(page.getByRole("button", { name: /account menu/i })).toBeVisible();
  }
});

test("critical workflows have no serious WCAG A/AA violations", async ({ page }) => {
  await login(page);
  const fixture = getBrowserFixture();
  for (const route of [
    "/account/dashboard",
    "/submission/submit",
    `/analysis/results/${fixture.result_scan_id}`,
    `/scans/${fixture.result_scan_id}/diagnostics`,
    "/usage",
  ]) {
    await page.goto(route);
    await expect(page.locator("main#main-content")).toBeVisible();
    await expect(page.locator('[aria-label="Loading page…"]')).toHaveCount(0);
    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .analyze();
    const blocking = results.violations.filter((violation) =>
      violation.impact === "serious" || violation.impact === "critical",
    );
    expect(blocking, `${route}: ${blocking.map((item) => item.id).join(", ")}`).toEqual([]);
  }
});

test("keyboard users can bypass navigation and dismiss account controls", async ({ page }) => {
  await login(page);
  await page.keyboard.press("Home");
  await page.keyboard.press("Tab");
  const skip = page.getByRole("link", { name: "Skip to main content" });
  await expect(skip).toBeFocused();
  await skip.press("Enter");
  await expect(page.locator("main#main-content")).toBeFocused();

  const account = page.getByRole("button", { name: /account menu/i });
  await account.focus();
  await account.press("Enter");
  const accountMenu = page.getByRole("menu", { name: "Account" });
  await expect(accountMenu).toBeVisible();
  await page.keyboard.press("Tab");
  await expect(accountMenu.getByRole("menuitem").first()).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(accountMenu).toBeHidden();
  await expect(account).toBeFocused();

  const search = page.getByRole("combobox", { name: "Global search" });
  await search.fill("scan");
  await search.press("Escape");
  await expect(search).toBeFocused();
});
