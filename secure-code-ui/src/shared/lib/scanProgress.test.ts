// Tests for the scan-progress deriver (#85 / PRD #83).
//
// The deriver is the single source of truth for the rail, the badge,
// and the progress bar — so these fixture tests pin its behaviour for
// a clean run, each approval gate, a resumed gate, terminal scans, and
// duplicated / out-of-order events.

import { describe, expect, it } from "vitest";

import {
  type ProgressEvent,
  deriveScanProgress,
} from "./scanProgress";

const ev = (stage_name: string, status: string): ProgressEvent => ({
  stage_name,
  status,
});

function stateOf(events: ProgressEvent[], key: string, crossFile = false) {
  const p = deriveScanProgress(events, null, crossFile);
  return p.stages.find((s) => s.key === key)?.state;
}

describe("deriveScanProgress", () => {
  it("marks every stage done for a clean terminal run", () => {
    const p = deriveScanProgress(
      [ev("QUEUED", "COMPLETED"), ev("ANALYZING_CONTEXT", "COMPLETED")],
      "COMPLETED",
      false,
    );
    expect(p.stages.every((s) => s.state === "done")).toBe(true);
    expect(p.progressPct).toBe(100);
    expect(p.isTerminal).toBe(true);
    expect(p.isError).toBe(false);
    expect(p.currentStageKey).toBeNull();
  });

  it("pauses the rail at the prescan gate", () => {
    const events = [
      ev("QUEUED", "COMPLETED"),
      ev("ANALYZING_CONTEXT", "STARTED"),
      ev("ANALYZING_CONTEXT", "COMPLETED"),
      ev("PRESCAN_REVIEW", "WAITING"),
    ];
    const p = deriveScanProgress(events, null, false);
    expect(stateOf(events, "PRESCAN_REVIEW")).toBe("paused");
    expect(stateOf(events, "ANALYZING_CONTEXT")).toBe("done");
    expect(p.currentStageKey).toBe("PRESCAN_REVIEW");
    expect(p.badge).toMatch(/Awaiting/);
  });

  it("pauses the rail at the profiling-cost gate", () => {
    const events = [
      ev("ANALYZING_CONTEXT", "COMPLETED"),
      ev("PROFILING_REVIEW", "WAITING"),
    ];
    expect(stateOf(events, "PROFILING_REVIEW")).toBe("paused");
    expect(deriveScanProgress(events, null, false).badge).toMatch(/Awaiting/);
  });

  it("pauses the rail at the analysis-cost gate", () => {
    const events = [
      ev("ANALYZING_CONTEXT", "COMPLETED"),
      ev("ESTIMATING_COST", "COMPLETED"),
      ev("COST_REVIEW", "WAITING"),
    ];
    const p = deriveScanProgress(events, null, false);
    expect(stateOf(events, "COST_REVIEW")).toBe("paused");
    expect(stateOf(events, "ESTIMATING_COST")).toBe("done");
    expect(p.badge).toBe("Awaiting Cost approval");
  });

  it("advances past a resumed gate", () => {
    // The cost gate WAITING, then COMPLETED (resumed), then the next
    // stage STARTED — the gate must read done, not paused.
    const events = [
      ev("ESTIMATING_COST", "COMPLETED"),
      ev("COST_REVIEW", "WAITING"),
      ev("COST_REVIEW", "COMPLETED"),
      ev("RUNNING_AGENTS", "STARTED"),
    ];
    expect(stateOf(events, "COST_REVIEW")).toBe("done");
    expect(stateOf(events, "RUNNING_AGENTS")).toBe("running");
    expect(deriveScanProgress(events, null, false).currentStageKey).toBe(
      "RUNNING_AGENTS",
    );
  });

  it("shows the in-progress stage as running mid-scan", () => {
    const events = [
      ev("ANALYZING_CONTEXT", "COMPLETED"),
      ev("RUNNING_AGENTS", "STARTED"),
    ];
    expect(stateOf(events, "RUNNING_AGENTS")).toBe("running");
    // Earlier stages with no event are still treated as done.
    expect(stateOf(events, "QUEUED")).toBe("done");
    // Later stages are pending.
    expect(stateOf(events, "GENERATING_REPORTS")).toBe("pending");
  });

  it("flags a failed terminal scan", () => {
    const p = deriveScanProgress(
      [ev("RUNNING_AGENTS", "STARTED")],
      "FAILED",
      false,
    );
    expect(p.isTerminal).toBe(true);
    expect(p.isError).toBe(true);
    expect(p.progressPct).toBe(100);
  });

  it("tolerates duplicated and out-of-order events", () => {
    // ESTIMATING_COST COMPLETED arrives twice; COST_REVIEW WAITING is
    // re-sent after a duplicate — last-write-wins still resolves the
    // gate to paused.
    const events = [
      ev("ESTIMATING_COST", "COMPLETED"),
      ev("COST_REVIEW", "WAITING"),
      ev("ESTIMATING_COST", "STARTED"),
      ev("ESTIMATING_COST", "COMPLETED"),
      ev("COST_REVIEW", "WAITING"),
    ];
    expect(stateOf(events, "COST_REVIEW")).toBe("paused");
    expect(stateOf(events, "ESTIMATING_COST")).toBe("done");
  });

  it("includes the cross-file stage only when opted in", () => {
    const events = [ev("CONSOLIDATING", "COMPLETED")];
    const off = deriveScanProgress(events, null, false);
    const on = deriveScanProgress(events, null, true);
    expect(off.stages.some((s) => s.key === "CROSS_FILE_VALIDATION")).toBe(
      false,
    );
    expect(on.stages.some((s) => s.key === "CROSS_FILE_VALIDATION")).toBe(true);
  });
});
