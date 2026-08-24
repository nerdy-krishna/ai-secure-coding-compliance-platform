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
  await expect(page).toHaveURL(/\/account\/dashboard$/);
  await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Dashboard" })).toBeVisible();
}
