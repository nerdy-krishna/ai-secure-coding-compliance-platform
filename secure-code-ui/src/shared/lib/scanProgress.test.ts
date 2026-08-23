import { describe, expect, it } from "vitest";

import { deriveScanProgress, type ProgressEvent } from "./scanProgress";

const prescanDeclineEvents: ProgressEvent[] = [
  { stage_name: "QUEUED", status: "COMPLETED" },
  { stage_name: "ANALYZING_CONTEXT", status: "COMPLETED" },
  { stage_name: "PRESCAN_REVIEW", status: "WAITING" },
  { stage_name: "PRESCAN_REVIEW", status: "COMPLETED" },
];

describe("deriveScanProgress terminal projections", () => {
  it("preserves partial progress when a user stops at the prescan gate", () => {
    const progress = deriveScanProgress(
      prescanDeclineEvents,
      "BLOCKED_USER_DECLINE",
      false,
    );

    expect(progress.progressPct).toBe(30);
    expect(progress.stages.map((stage) => stage.state)).toEqual([
      "done",
      "done",
      "done",
      "pending",
      "pending",
      "pending",
      "pending",
      "pending",
      "pending",
      "pending",
    ]);
  });

  it("does not report a failed partial scan as 100 percent complete", () => {
    const progress = deriveScanProgress(
      [
        ...prescanDeclineEvents,
        { stage_name: "PROFILING_REVIEW", status: "COMPLETED" },
        { stage_name: "PROFILING_FILES", status: "FAILED" },
      ],
      "FAILED",
      false,
    );

    expect(progress.progressPct).toBe(50);
    expect(progress.stages[progress.stages.length - 1]?.state).toBe("pending");
  });

  it("projects successful terminal scans as fully complete", () => {
    const progress = deriveScanProgress([], "COMPLETED", false);

    expect(progress.progressPct).toBe(100);
    expect(progress.stages.every((stage) => stage.state === "done")).toBe(true);
  });
});
