import { expect, test } from "@playwright/test";
import { login } from "./support";

test("reload uses the HttpOnly server session without browser token storage", async ({
  page,
  context,
}) => {
  await login(page);

  const cookies = await context.cookies();
  const sessionCookie = cookies.find((cookie) =>
    ["__Host-SCCAPSession", "SCCAPSessionDev"].includes(cookie.name),
  );
  expect(sessionCookie?.httpOnly).toBe(true);
  expect(sessionCookie?.path).toBe("/");
  expect(
    await page.evaluate(() => localStorage.getItem("accessToken")),
  ).toBeNull();

  let refreshRequests = 0;
  page.on("request", (request) => {
    if (request.url().includes("/api/v1/auth/refresh")) refreshRequests += 1;
  });
  await page.reload();

  await expect(page).toHaveURL(/\/account\/dashboard$/);
  await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible();
  expect(refreshRequests).toBe(0);

  const reloadedCookie = (await context.cookies()).find(
    (cookie) => cookie.name === sessionCookie?.name,
  );
  expect(reloadedCookie?.value).toBe(sessionCookie?.value);
});

test("unsafe cookie request without the in-memory CSRF proof is rejected", async ({
  page,
}) => {
  await login(page);

  const status = await page.evaluate(async () => {
    const response = await fetch("/api/v1/account/preferences", {
      method: "PUT",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ theme: "dark" }),
    });
    return response.status;
  });
  expect(status).toBe(403);
});

test("security settings show the current server-side session", async ({ page }) => {
  await login(page);
  await page.goto("/account/settings/security");

  await expect(page.getByText("Active sessions")).toBeVisible();
  await expect(page.getByText("Current")).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign out other sessions" })).toBeVisible();
});

test("an expired browser session redirects to login", async ({ page }) => {
  await login(page);
  await page.route("**/api/v1/scans/history**", async (route) => {
    await route.fulfill({
      status: 401,
      contentType: "application/json",
      body: JSON.stringify({ detail: "Browser session is invalid or expired." }),
    });
  });

  await page.goto("/account/history");
  await expect(page).toHaveURL(/\/login$/);
});

test("tenant-entry expiry redirects to tenant selection without logging out", async ({
  page,
  context,
}) => {
  await login(page);
  const tenantEntryCookie = (await context.cookies()).find((cookie) =>
    ["__Host-SCCAPTenantEntry", "SCCAPTenantEntryDev"].includes(cookie.name),
  );
  if (!tenantEntryCookie) throw new Error("tenant-entry cookie was not issued");
  expect(tenantEntryCookie.httpOnly).toBe(true);
  await context.clearCookies({ name: tenantEntryCookie.name });
  await context.setExtraHTTPHeaders({});

  await page.goto("/account/history");
  await expect(page).toHaveURL(/\/admin\/tenants$/);
  const me = await page.request.get("/api/v1/auth/session/me");
  expect(me.status()).toBe(200);
});

test("tenant entry remains active when navigating to the dashboard", async ({
  page,
  context,
}) => {
  const email = process.env.SCCAP_BROWSER_EMAIL;
  const password = process.env.SCCAP_BROWSER_PASSWORD;
  if (!email || !password) throw new Error("browser fixture credentials are required");

  await page.goto("/login");
  await page.getByLabel("Username or email").fill(email);
  await page.getByLabel("Password", { exact: false }).fill(password);
  await page.waitForTimeout(800);
  await page.getByRole("button", { name: "Log in" }).click();
  await expect(page).toHaveURL(/\/(account\/dashboard|admin\/tenants)$/);
  if (!page.url().endsWith("/admin/tenants")) {
    await page.goto("/admin/tenants");
  }

  page.on("dialog", async (dialog) => {
    if (dialog.message().startsWith("Re-enter your password")) {
      await dialog.accept(password);
    } else if (dialog.message().startsWith("Reason for break-glass")) {
      await dialog.accept("Browser tenant navigation regression");
    } else {
      await dialog.dismiss();
    }
  });
  await page.getByRole("button", { name: "Enter tenant" }).first().click();
  await expect(page.getByRole("button", { name: "Exit tenant" })).toBeVisible();
  const tenantEntryCookie = (await context.cookies()).find((cookie) =>
    ["__Host-SCCAPTenantEntry", "SCCAPTenantEntryDev"].includes(cookie.name),
  );
  expect(tenantEntryCookie?.httpOnly).toBe(true);

  await page.reload();

  const dashboardStats = page.waitForResponse((response) =>
    response.url().includes("/api/v1/dashboard/stats"),
  );
  await page.getByRole("link", { name: "Dashboard", exact: true }).click();
  expect((await dashboardStats).status()).toBe(200);
  await expect(page).toHaveURL(/\/account\/dashboard$/);
  await expect(page.getByText(/open findings across the platform/i)).toBeVisible();
});
