import { expect, test, type Page } from "@playwright/test";

const tenant = "00000000-0000-0000-0000-000000000001";
const project = "00000000-0000-0000-0000-000000000002";
const primary = "00000000-0000-0000-0000-000000000003";
const secondary = "00000000-0000-0000-0000-000000000004";
const model = "00000000-0000-0000-0000-000000000005";

async function entry(page: Page) {
  const submissions: Record<string, unknown>[] = [];
  // Browser contract only: no real login, backend calls, model calls or scans.
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname.replace("/api/v1", "");
    let body: unknown = {};
    if (path === "/setup/status") body = { is_setup_completed: true };
    else if (path === "/features") body = { enabled_features: ["scan", "pentesting", "pentesting_capability13"] };
    else if (path === "/auth/session/me") body = { id: 42, email: "fixture@example.invalid", is_active: true, is_verified: true, is_superuser: false, permissions: ["pentest.read", "pentest.create"], role_keys: ["analyst"], active_tenant_id: tenant, tenant_id: tenant };
    else if (path === "/auth/sessions") body = [{ id: "fixture-session", current: true, last_seen_at: new Date().toISOString(), idle_expires_at: new Date(Date.now() + 3600000).toISOString(), absolute_expires_at: new Date(Date.now() + 7200000).toISOString() }];
    else if (path === "/pentesting/projects") body = { items: [{ id: project, name: "Owned test project", owner_user_id: 42 }] };
    else if (path === `/pentesting/projects/${project}`) body = { id: project, name: "Owned test project", owner_user_id: 42, defaults: { mode: "gray_box" } };
    else if (path.endsWith("/credentials")) body = { items: [{ id: primary, name: "Account A", credential_kind: "username_password", revoked: false }, { id: secondary, name: "Account B", credential_kind: "username_password", revoked: false }] };
    else if (path === "/pentesting/model-options") body = { items: [{ id: model, name: "Offline fixture model", provider: "fixture", model_name: "never-called" }] };
    else if (path === "/pentesting/configuration") body = { default_duration_minutes: 3, maximum_duration_minutes: 10, default_response_mebibytes: 1, maximum_response_mebibytes: 8, revision: 1 };
    else if (path === "/pentesting/readiness") body = { profiles: [], testing_intensities: ["discovery_only"] };
    else if (path === "/pentesting/engagements") body = { items: [], projection_state: "complete", limitation_codes: [] };
    else if (path.endsWith("/gray-box-engagements")) {
      submissions.push(route.request().postDataJSON());
      await route.fulfill({ status: 202, json: { engagement_id: "fixture-engagement", attempt_id: "fixture-attempt" } });
      return;
    } else if (path !== "/auth/session/csrf") {
      await route.fulfill({ status: 404, json: { detail: "Not in this browser fixture" } });
      return;
    }
    await route.fulfill({ json: body, headers: { "X-CSRF-Token": "fixture-csrf" } });
  });
  await page.goto(`/pentesting/engagements/new?project=${project}`);
  await page.getByRole("radio", { name: /^Gray box/ }).click();
  await page.getByLabel("Primary project credential").selectOption(primary);
  await page.getByLabel("Engagement name").fill("Two-identity read-only fixture");
  await page.getByLabel("Assessment AI model").selectOption(model);
  await page.getByRole("textbox", { name: "Exact target origin", exact: true }).fill("http://fixture.test:8080/");
  await page.getByLabel(/I confirm I am authorized/).check();
  return submissions;
}

test("gray-box submits two opaque identities and explicit owner-only read context", async ({ page }) => {
  const submissions = await entry(page);
  await page.getByLabel("Second identity (optional)").selectOption(secondary);
  await page.getByText("Read-only authorization context (optional)", { exact: true }).click();
  await page.getByLabel("Primary account owner-only resources").fill("/records/report-7");
  await page.getByRole("button", { name: "Authorize and start" }).click();
  await expect.poll(() => submissions.length).toBe(1);
  expect(submissions[0]).toMatchObject({ credential_id: primary, second_credential_id: secondary, execution_options: { form_submission_enabled: false, state_changing_tests_enabled: false, readonly_access: { owner_only_resources: [{ path: "/records/report-7", owner: "primary" }] } } });
  const options = submissions[0].execution_options as { enabled_scanners: string[] };
  expect(options.enabled_scanners).toContain("authorization_readonly");
  expect(JSON.stringify(submissions[0])).not.toContain("secret");
});

test("one assessment declares private resources for both account owners", async ({ page }) => {
  const submissions = await entry(page);
  await page.getByLabel("Second identity (optional)").selectOption(secondary);
  await page.getByText("Read-only authorization context (optional)", { exact: true }).click();
  await expect(page.getByLabel("Secondary account owner-only resources")).toBeVisible({ timeout: 3000 });
  await page.getByLabel("Primary account owner-only resources").fill("/records/report-7");
  await page.getByLabel("Secondary account owner-only resources").fill("/documents/ledger-42");
  await page.getByRole("button", { name: "Authorize and start" }).click();
  await expect.poll(() => submissions.length).toBe(1);
  expect(submissions[0]).toMatchObject({ execution_options: { readonly_access: { owner_only_resources: [
    { path: "/records/report-7", owner: "primary" },
    { path: "/documents/ledger-42", owner: "secondary" },
  ] } } });
});

test("changing the primary account clears the second selection and excludes duplicates", async ({ page }) => {
  await entry(page);
  await page.getByLabel("Second identity (optional)").selectOption(secondary);
  await page.getByLabel("Primary project credential").selectOption(secondary);
  await expect(page.getByLabel("Second identity (optional)")).toHaveValue("");
  await expect(page.getByLabel("Second identity (optional)").locator(`option[value="${secondary}"]`)).toHaveCount(0);
});

test("changing account authority clears stale ownership declarations", async ({ page }) => {
  await entry(page);
  await page.getByLabel("Second identity (optional)").selectOption(secondary);
  await page.getByText("Read-only authorization context (optional)", { exact: true }).click();
  await page.getByLabel("Primary account owner-only resources").fill("/records/report-7");
  await page.getByLabel("Secondary account owner-only resources").fill("/documents/ledger-42");
  await page.getByLabel("Primary project credential").selectOption(secondary);
  await expect(page.getByLabel("Primary account owner-only resources")).toHaveValue("", { timeout: 3000 });
  await expect(page.getByLabel("Secondary account owner-only resources")).toHaveValue("");
  await expect(page.getByLabel("Secondary account owner-only resources")).toBeDisabled();
});

test("clearing and reselecting the secondary account never restores stale private paths", async ({ page }) => {
  const submissions = await entry(page);
  await page.getByLabel("Second identity (optional)").selectOption(secondary);
  await page.getByText("Read-only authorization context (optional)", { exact: true }).click();
  await page.getByLabel("Primary account owner-only resources").fill("/records/report-7");
  await page.getByLabel("Secondary account owner-only resources").fill("/documents/ledger-42");
  await page.getByLabel("Second identity (optional)").selectOption("");
  await expect(page.getByLabel("Secondary account owner-only resources")).toBeDisabled();
  await page.getByLabel("Second identity (optional)").selectOption(secondary);
  await expect(page.getByLabel("Secondary account owner-only resources")).toHaveValue("");
  await expect(page.getByLabel("Primary account owner-only resources")).toHaveValue("/records/report-7");
  await page.getByRole("button", { name: "Authorize and start" }).click();
  await expect.poll(() => submissions.length).toBe(1);
  expect(submissions[0]).toMatchObject({ execution_options: { readonly_access: { owner_only_resources: [{ path: "/records/report-7", owner: "primary" }] } } });
});

test("changing project clears both credentials and private resource declarations", async ({ page }) => {
  await entry(page);
  await page.getByLabel("Second identity (optional)").selectOption(secondary);
  await page.getByText("Read-only authorization context (optional)", { exact: true }).click();
  await page.getByLabel("Primary account owner-only resources").fill("/records/report-7");
  await page.getByLabel("Secondary account owner-only resources").fill("/documents/ledger-42");
  await page.getByRole("combobox", { name: "Pentesting project", exact: true }).selectOption("");
  await page.getByRole("radio", { name: /^Gray box/ }).click();
  await expect(page.getByLabel("Primary project credential")).toHaveValue("");
  await page.getByText("Read-only authorization context (optional)", { exact: true }).click();
  for (const label of ["Primary account owner-only resources", "Secondary account owner-only resources"]) {
    await expect(page.getByLabel(label)).toHaveValue("");
    await expect(page.getByLabel(label)).toBeDisabled();
  }
});

test("one-account gray-box remains launchable on mobile without ownership declarations", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const submissions = await entry(page);
  await page.getByRole("button", { name: "Authorize and start" }).click();
  await expect.poll(() => submissions.length).toBe(1);
  expect(submissions[0]).toMatchObject({ credential_id: primary, second_credential_id: null, execution_options: { readonly_access: { owner_only_resources: [] } } });
});
