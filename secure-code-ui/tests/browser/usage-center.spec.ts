import { expect, test } from "@playwright/test";

import { login } from "./support";

test("authenticated user can inspect canonical usage without sensitive payloads", async ({
  page,
}) => {
  await login(page);
  await page.goto("/usage");

  await expect(page.getByRole("heading", { name: "Usage & budget center" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Usage summary" })).toBeVisible();
  await expect(page.getByText("Ledger drilldown")).toBeVisible();
  await expect(page.getByText(/Prompts, responses, source contents/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Export CSV" })).toBeVisible();
});
