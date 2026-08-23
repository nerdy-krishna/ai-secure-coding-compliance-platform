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
