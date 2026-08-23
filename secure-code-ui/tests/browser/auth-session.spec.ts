import { expect, test } from "@playwright/test";
import { login } from "./support";

test("concurrent 401s share one rotating refresh and preserve the active session", async ({
  page,
  context,
}) => {
  await login(page);

  const initialRefreshCookie = (await context.cookies()).find(
    (cookie) => cookie.name === "SecureCodePlatformRefresh",
  );
  expect(initialRefreshCookie?.httpOnly).toBe(true);

  const expiredToken =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
    "eyJzdWIiOiJicm93c2VyLWZpeHR1cmUiLCJleHAiOjF9." +
    "invalid-signature";
  await page.evaluate((token) => localStorage.setItem("accessToken", token), expiredToken);

  let refreshRequests = 0;
  page.on("request", (request) => {
    if (request.url().includes("/api/v1/auth/refresh")) refreshRequests += 1;
  });
  const refreshResponse = page.waitForResponse(
    (response) =>
      response.url().includes("/api/v1/auth/refresh") && response.status() === 200,
  );
  await page.reload();
  await refreshResponse;

  await expect(page).toHaveURL(/\/account\/dashboard$/);
  await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible();
  await page.waitForTimeout(500);
  expect(refreshRequests).toBe(1);

  const refreshedAccessToken = await page.evaluate(() =>
    localStorage.getItem("accessToken"),
  );
  expect(refreshedAccessToken).toBeTruthy();
  expect(refreshedAccessToken).not.toBe(expiredToken);

  const rotatedRefreshCookie = (await context.cookies()).find(
    (cookie) => cookie.name === "SecureCodePlatformRefresh",
  );
  expect(rotatedRefreshCookie?.value).toBeTruthy();
  expect(rotatedRefreshCookie?.value).not.toBe(initialRefreshCookie?.value);
});
