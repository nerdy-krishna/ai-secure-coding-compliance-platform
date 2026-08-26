import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import type { Page } from "@playwright/test";
import { expect } from "@playwright/test";

export const SUBMITTED_SOURCE_SECRET =
  "BROWSER_SUBMITTED_SECRET_DO_NOT_RETAIN_7f4c21";

export interface BrowserFixture {
  llm_config_id: string;
  framework_name: string;
  gate_scan_id: string;
  gate_id: string;
  replay_scan_id: string;
  replay_attempt_id: string;
  first_event_id: number;
  second_event_id: number;
  result_project_id: string;
  result_scan_id: string;
}

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../../");
const DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001";

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required for the browser suite`);
  return value;
}

export function runBrowserFixture(
  action: "setup" | "advance" | "cleanup",
  scanId?: string,
): Record<string, unknown> {
  const email = requiredEnvironment("SCCAP_BROWSER_EMAIL");
  const password = requiredEnvironment("SCCAP_BROWSER_PASSWORD");
  const args = [
    "compose",
    "exec",
    "-T",
    "-e",
    `SCCAP_BROWSER_EMAIL=${email}`,
    "-e",
    `SCCAP_BROWSER_PASSWORD=${password}`,
    "app",
    "python",
    "-m",
    "tests.browser.user_fixture",
    action,
  ];
  if (scanId) args.push(scanId);
  const result = spawnSync("docker", args, {
    cwd: repoRoot,
    encoding: "utf8",
    env: process.env,
  });
  if (result.status !== 0) {
    throw new Error(
      `browser fixture ${action} failed: ${(result.stderr || result.stdout).trim()}`,
    );
  }
  const jsonLine = result.stdout
    .trim()
    .split(/\r?\n/)
    .reverse()
    .find((line) => line.startsWith("{"));
  if (!jsonLine) throw new Error(`browser fixture ${action} returned no JSON`);
  return JSON.parse(jsonLine) as Record<string, unknown>;
}

export function getBrowserFixture(): BrowserFixture {
  const raw = requiredEnvironment("SCCAP_BROWSER_FIXTURE_JSON");
  return JSON.parse(raw) as BrowserFixture;
}

export async function login(page: Page): Promise<void> {
  const email = requiredEnvironment("SCCAP_BROWSER_EMAIL");
  const password = requiredEnvironment("SCCAP_BROWSER_PASSWORD");
  await page.goto("/login");
  await page.getByLabel("Username or email").fill(email);
  await page.getByLabel("Password", { exact: false }).fill(password);
  await page.waitForTimeout(800);
  await page.getByRole("button", { name: "Log in" }).click();
  // A platform owner has no implicit tenant scope. Dashboard requests may
  // therefore route to tenant selection before this helper obtains its
  // explicit fixture grant.
  await expect(page).toHaveURL(/\/(account\/dashboard|admin\/tenants)$/);
  await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible();
  await expect(
    page.getByRole("link", { name: "Dashboard", exact: true }),
  ).toBeVisible();

  // The browser fixture is a platform owner so it can exercise the complete
  // authenticated route inventory. In multi-tenant mode, platform owners must
  // explicitly enter a tenant before tenant-scoped scan APIs will authorize.
  const tenantEntry = await page.evaluate(
    async ({ password: fixturePassword, tenantId }) => {
      const csrfResponse = await fetch("/api/v1/auth/session/csrf", {
        credentials: "include",
      });
      const csrfBody = (await csrfResponse.json()) as { csrf_token?: string };
      if (!csrfResponse.ok || !csrfBody.csrf_token) {
        return { status: csrfResponse.status, detail: "CSRF token unavailable" };
      }
      const response = await fetch("/api/v1/admin/tenants/entry", {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfBody.csrf_token,
        },
        body: JSON.stringify({
          tenant_id: tenantId,
          password: fixturePassword,
          reason: "Automated browser acceptance fixture",
        }),
      });
      const body = (await response.json()) as {
        detail?: string;
        entry_token?: string;
      };
      return { status: response.status, ...body };
    },
    { password, tenantId: DEFAULT_TENANT_ID },
  );
  if (tenantEntry.status !== 200 || !tenantEntry.entry_token) {
    throw new Error(
      `browser tenant entry failed (${tenantEntry.status}): ${tenantEntry.detail ?? "missing grant"}`,
    );
  }
  await page.context().setExtraHTTPHeaders({
    "X-SCCAP-Tenant-Entry": tenantEntry.entry_token,
  });
  await page.goto("/account/dashboard");
  await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible();
}
