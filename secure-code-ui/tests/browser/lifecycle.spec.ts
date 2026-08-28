import { expect, test, type Download, type Page } from "@playwright/test";
import {
  getBrowserFixture,
  login,
  runBrowserFixture,
  SUBMITTED_SOURCE_SECRET,
} from "./support";

test.describe.configure({ mode: "serial" });

async function downloadFrom(page: Page, title: string): Promise<Download> {
  const pending = page.waitForEvent("download");
  await page.getByTitle(title).click();
  return pending;
}

test("submission lands on and remains at the canonical scan route", async ({ page }) => {
  const fixture = getBrowserFixture();
  await login(page);
  await page.goto("/submission/submit");

  const projectName = `Browser submitted ${Date.now()}`;
  await page.getByPlaceholder("e.g., payments-api").fill(projectName);
  await page.locator("#field-reasoning-llm").selectOption(fixture.llm_config_id);
  await page.locator("#field-utility-llm").selectOption(fixture.llm_config_id);
  await page.getByRole("button", { name: fixture.framework_name }).click();
  await page.locator('input[type="file"]').first().setInputFiles({
    name: "browser-regression.py",
    mimeType: "text/x-python",
    buffer: Buffer.from(
      `# ${SUBMITTED_SOURCE_SECRET}\nprint("browser lifecycle")\n`,
    ),
  });

  const [submission] = await Promise.all([
    page.waitForResponse((response) => response.url().endsWith("/api/v1/scans")),
    page.getByRole("button", { name: "Start scan" }).click(),
  ]);
  expect(submission.status()).toBe(200);
  await page.waitForURL(/\/analysis\/scanning\/[0-9a-f-]+$/);
  const canonicalRoute = new URL(page.url()).pathname;
  await expect(page).toHaveURL(new RegExp(`${canonicalRoute}$`));
  await expect(page.getByText("Live event log")).toBeVisible();
  await page.reload();
  await expect(page).toHaveURL(new RegExp(`${canonicalRoute}$`));
  await expect(page.getByText("Live event log")).toBeVisible();
});

test("prescan review fits the viewport without overlapping controls", async ({ page }) => {
  const fixture = getBrowserFixture();
  await page.setViewportSize({ width: 1440, height: 900 });
  await login(page);
  await page.goto(`/analysis/scanning/${fixture.prescan_scan_id}`);

  await expect(page.getByRole("button", { name: "Continue to LLM" })).toBeVisible();
  await expect(page.locator(".prescan-review-card")).toBeVisible();

  const layout = await page.evaluate(() => {
    const rect = (selector: string) => {
      const element = document.querySelector<HTMLElement>(selector);
      if (!element) throw new Error(`missing layout probe: ${selector}`);
      const bounds = element.getBoundingClientRect();
      return {
        top: bounds.top,
        right: bounds.right,
        bottom: bounds.bottom,
        left: bounds.left,
        clientWidth: element.clientWidth,
        scrollWidth: element.scrollWidth,
      };
    };
    const controls = rect(".scan-running-controls");
    const progress = rect(".scan-progress-card");
    const review = rect(".prescan-review-card");
    const table = rect(".prescan-findings-table");
    const activity = rect(".scan-activity-log");
    return {
      documentClientWidth: document.documentElement.clientWidth,
      documentScrollWidth: document.documentElement.scrollWidth,
      controls,
      progress,
      review,
      table,
      activity,
      controlsOverlapProgress:
        controls.bottom > progress.top && controls.top < progress.bottom,
      controlsOverlapReview:
        controls.bottom > review.top && controls.top < review.bottom,
    };
  });

  expect(layout.documentScrollWidth).toBeLessThanOrEqual(
    layout.documentClientWidth + 1,
  );
  expect(layout.controlsOverlapProgress).toBe(false);
  expect(layout.controlsOverlapReview).toBe(false);
  expect(layout.review.scrollWidth).toBeLessThanOrEqual(layout.review.clientWidth + 1);
  expect(layout.table.scrollWidth).toBeLessThanOrEqual(layout.table.clientWidth + 1);
  expect(layout.activity.scrollWidth).toBeLessThanOrEqual(
    layout.activity.clientWidth + 1,
  );
});

test("profiling and analysis gates render durable evidence and accept one decision", async ({
  page,
}) => {
  const fixture = getBrowserFixture();
  await login(page);
  await page.goto(`/analysis/scanning/${fixture.gate_scan_id}`);

  await expect(page.getByText("Approve file profiling cost", { exact: false })).toBeVisible();
  await expect(page.getByText(/Step 2 of 3/)).toBeVisible();
  const profilingDecision = page.waitForResponse(
    (response) =>
      response.url().includes(`/scans/${fixture.gate_scan_id}/approve`) &&
      response.status() === 202,
  );
  await page.getByRole("button", { name: "Approve & profile" }).click();
  await profilingDecision;
  await expect(page.getByRole("button", { name: "Approve & profile" })).toBeHidden();

  runBrowserFixture("advance", fixture.gate_scan_id);
  await page.reload();
  await expect(
    page.getByText("Approve full security analysis cost", { exact: false }),
  ).toBeVisible();
  await expect(page.getByText(/Step 3 of 3/)).toBeVisible();
  const analysisDecision = page.waitForResponse(
    (response) =>
      response.url().includes(`/scans/${fixture.gate_scan_id}/approve`) &&
      response.status() === 202,
  );
  await page.getByRole("button", { name: "Approve & run" }).click();
  await analysisDecision;
  await expect(page.getByRole("button", { name: "Approve & run" })).toBeHidden();
});

test("SSE reconnect resumes by cursor, cancellation completes, and terminal UI projects it", async ({
  page,
}) => {
  const fixture = getBrowserFixture();
  await login(page);

  const reconnectCursors: string[] = [];
  page.on("request", (request) => {
    if (!request.url().includes(`/scans/${fixture.replay_scan_id}/stream?`)) return;
    const cursor = new URL(request.url()).searchParams.get("last_event_id");
    if (cursor !== null) reconnectCursors.push(cursor);
  });
  await page.addInitScript(
    ({ eventPayload }) => {
      const NativeEventSource = window.EventSource;
      let delivered = false;
      class OneShotEventSource extends EventTarget {
        static readonly CONNECTING = 0;
        static readonly OPEN = 1;
        static readonly CLOSED = 2;
        readonly url: string;
        readonly withCredentials: boolean;
        readyState = OneShotEventSource.CONNECTING;
        onopen: ((event: Event) => void) | null = null;
        onmessage: ((event: MessageEvent) => void) | null = null;
        onerror: ((event: Event) => void) | null = null;
        private closedByClient = false;

        constructor(url: string | URL, init?: EventSourceInit) {
          super();
          if (delivered) {
            return new NativeEventSource(url, init) as unknown as OneShotEventSource;
          }
          this.url = String(url);
          this.withCredentials = Boolean(init?.withCredentials);
          queueMicrotask(() => {
            if (this.closedByClient || delivered) return;
            delivered = true;
            this.readyState = OneShotEventSource.OPEN;
            this.dispatchEvent(
              new MessageEvent("scan_event", {
                data: JSON.stringify(eventPayload),
                lastEventId: String(eventPayload.event_id),
              }),
            );
            this.readyState = OneShotEventSource.CLOSED;
            const error = new Event("error");
            this.onerror?.(error);
            this.dispatchEvent(error);
          });
        }

        close(): void {
          this.closedByClient = true;
          this.readyState = OneShotEventSource.CLOSED;
        }
      }
      Object.defineProperty(window, "EventSource", {
        configurable: true,
        value: OneShotEventSource,
        writable: true,
      });
    },
    {
      eventPayload: {
        schema_version: 1,
        cursor: String(fixture.first_event_id),
        scan_id: fixture.replay_scan_id,
        event_id: fixture.first_event_id,
        attempt_id: fixture.replay_attempt_id,
        activity_kind: "workflow",
        stage_name: "BROWSER_BOOTSTRAP",
        status: "COMPLETED",
        timestamp: new Date().toISOString(),
        details: { elapsed_ms: 12 },
      },
    },
  );

  await page.goto(`/analysis/scanning/${fixture.replay_scan_id}`);
  await expect
    .poll(() => reconnectCursors[0], { timeout: 15_000 })
    .toBe(String(fixture.first_event_id));

  const log = page.locator("pre.sccap-code");
  await expect(log).toContainText("Browser bootstrap");
  await expect(log).toContainText("Browser scanner");
  const beforeCancel = await log.innerText();
  expect(beforeCancel.match(/Browser bootstrap/g)).toHaveLength(1);

  await page.getByRole("button", { name: "Stop scan" }).click();
  const cancellation = page.waitForResponse(
    (response) =>
      response.url().includes(`/scans/${fixture.replay_scan_id}/cancel`) &&
      response.status() === 200,
  );
  await page.getByRole("button", { name: "Stop scan" }).last().click();
  await cancellation;
  const terminalResponse = await page.request.get(
    `/api/v1/scans/${fixture.replay_scan_id}/result`,
  );
  expect(terminalResponse.status()).toBe(200);
  const terminal = (await terminalResponse.json()) as {
    status: string;
    events: Array<{ stage_name: string; status: string }>;
  };
  expect(terminal.status).toBe("CANCELLED");
  const cancellationPhases = terminal.events
    .filter((event) => event.stage_name === "CANCELLATION")
    .map((event) => event.status);
  expect(cancellationPhases).toEqual(["REQUESTED", "OBSERVED", "COMPLETED"]);
  await page.reload();
  await expect(page.getByRole("heading", { name: "Scan stopped at your request" })).toBeVisible();
  await page.goto(`/analysis/results/${fixture.replay_scan_id}`);
  await expect(page.getByText(/stopped/i).first()).toBeVisible();
});

test("completed results render and every evidence download is usable", async ({ page }) => {
  const fixture = getBrowserFixture();
  await login(page);
  await page.goto(`/analysis/results/${fixture.result_scan_id}`);

  await expect(
    page.getByRole("heading", { name: "Browser fixture SQL injection" }),
  ).toBeVisible();
  await expect(page.getByText("Deterministic scanner provenance")).toBeVisible();

  const downloads = [
    ["Download the findings report as HTML", ".html"],
    ["Download the findings report as PDF", ".pdf"],
    ["Download the findings report as CSV", ".csv"],
    ["Download the findings report as SARIF 2.1.0 for GitHub code scanning", ".sarif"],
    ["Download the original JSON emitted by the deterministic scanners", ".json"],
  ] as const;
  for (const [title, extension] of downloads) {
    const download = await downloadFrom(page, title);
    expect(download.suggestedFilename()).toContain(fixture.result_scan_id);
    expect(download.suggestedFilename().endsWith(extension)).toBe(true);
    const path = await download.path();
    expect(path).toBeTruthy();
  }
});
