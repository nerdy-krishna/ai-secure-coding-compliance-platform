// Scan progress derivation (#85 / PRD #83).
//
// `scan_events` is the single source of truth for scan progress. This
// pure module turns the ordered event list into the view model the
// scan-status page renders — the per-stage rail states, the current
// stage, the progress %, and the badge label. The status badge and the
// rail therefore derive from ONE function and can never disagree.
//
// Worker event vocabulary (see app/shared/lib/scan_progress.py):
//   STAGE/STARTED   on node entry
//   STAGE/COMPLETED on node exit
//   GATE/WAITING    when the graph suspends at an approval gate
//   GATE/COMPLETED  when the gate is resumed
// `scans.status` is consulted only to classify a *terminal* scan
// (COMPLETED / FAILED / …) — terminal statuses are written directly and
// are reliable; the desync bug only ever affected live statuses.

export type StageState = "done" | "running" | "paused" | "pending";

export interface ProgressEvent {
  stage_name: string;
  status: string;
  timestamp?: string | null;
}

export interface RailStage {
  key: string;
  label: string;
  /** Icon-component key for this stage — rendered via `StageIcon`
   *  (`shared/ui/StageIcon`). Shared so every page that shows the scan
   *  pipeline (status page, scan cards) uses one consistent icon set. */
  icon: string;
  /** True for the three human-in-the-loop approval gates. */
  gate?: boolean;
}

export interface DerivedStage extends RailStage {
  state: StageState;
}

export interface ScanProgress {
  stages: DerivedStage[];
  currentStageKey: string | null;
  progressPct: number;
  badge: string;
  isTerminal: boolean;
  isError: boolean;
}

// The canonical scan pipeline, in display order. Each `key` matches the
// `stage_name` the worker emits for that stage.
const BASE_STAGES: RailStage[] = [
  { key: "QUEUED", label: "Queued", icon: "Clock" },
  { key: "ANALYZING_CONTEXT", label: "Analyzing context", icon: "Layers" },
  {
    key: "PRESCAN_REVIEW",
    label: "Pre-LLM scan review",
    icon: "Shield",
    gate: true,
  },
  {
    key: "PROFILING_REVIEW",
    label: "Profiling cost review",
    icon: "Gauge",
    gate: true,
  },
  { key: "PROFILING_FILES", label: "Profiling files", icon: "Search" },
  { key: "ESTIMATING_COST", label: "Estimating cost", icon: "Dollar" },
  { key: "COST_REVIEW", label: "Cost review", icon: "Check", gate: true },
  { key: "RUNNING_AGENTS", label: "Running security agents", icon: "Cpu" },
  { key: "CONSOLIDATING", label: "Consolidating findings", icon: "Filter" },
  { key: "GENERATING_REPORTS", label: "Generating reports", icon: "BookOpen" },
];

const CROSS_FILE_STAGE: RailStage = {
  key: "CROSS_FILE_VALIDATION",
  label: "Cross-file validation",
  icon: "Link",
};

const TERMINAL_STATUSES = new Set([
  "COMPLETED",
  "REMEDIATION_COMPLETED",
  "FAILED",
  "CANCELLED",
  "EXPIRED",
  "BLOCKED_PRE_LLM",
  "BLOCKED_USER_DECLINE",
]);

const ERROR_STATUSES = new Set(["FAILED", "EXPIRED"]);

/** True when a scan has reached a terminal status. */
export function isTerminalStatus(status: string | null | undefined): boolean {
  return !!status && TERMINAL_STATUSES.has(status);
}

/** The rail definition for a scan — the cross-file stage is included
 *  only when the scan opted in to cross-file validation (#82). */
export function railStages(crossFileValidation: boolean): RailStage[] {
  if (!crossFileValidation) return BASE_STAGES;
  const out = [...BASE_STAGES];
  const idx = out.findIndex((s) => s.key === "CONSOLIDATING");
  out.splice(idx + 1, 0, CROSS_FILE_STAGE);
  return out;
}

function badgeForStage(stage: DerivedStage): string {
  if (stage.state === "paused") {
    return `Awaiting ${stage.label.replace(/ review$/i, "")} approval`;
  }
  return stage.label;
}

/**
 * Derive the full scan-progress view model from the event stream.
 *
 * `events` is the ordered scan-event list. `terminalStatus` is the
 * scan's `scans.status` value — used ONLY to classify a finished scan.
 * `crossFileValidation` toggles the optional cross-file rail stage.
 */
export function deriveScanProgress(
  events: ProgressEvent[],
  terminalStatus: string | null,
  crossFileValidation: boolean,
): ScanProgress {
  const stages = railStages(crossFileValidation);
  const isTerminal = !!terminalStatus && TERMINAL_STATUSES.has(terminalStatus);
  const isError = !!terminalStatus && ERROR_STATUSES.has(terminalStatus);

  // Last-write-wins status per stage_name, in event order. Tolerates
  // duplicated / out-of-order events — only the latest matters.
  const latest = new Map<string, string>();
  for (const ev of events) {
    if (ev && typeof ev.stage_name === "string") {
      latest.set(ev.stage_name, ev.status);
    }
  }

  // Pass 1 — each stage's own state from its latest event.
  const states: StageState[] = stages.map((s) => {
    const ev = latest.get(s.key);
    if (ev === "WAITING") return "paused";
    if (ev === "STARTED") return "running";
    if (ev === "COMPLETED" || ev === "FAILED") return "done";
    return "pending";
  });

  // Pass 2 — monotonic fix-up. The frontier is the furthest stage with
  // any event; everything before it must be done (a missed event must
  // not strand an earlier stage as pending), everything after pending.
  let frontier = -1;
  for (let i = 0; i < stages.length; i++) {
    if (latest.has(stages[i].key)) frontier = i;
  }
  for (let i = 0; i < frontier; i++) {
    if (states[i] === "pending" || states[i] === "running") states[i] = "done";
  }
  for (let i = frontier + 1; i < stages.length; i++) states[i] = "pending";
  // A done frontier with a successor means the scan has moved on — the
  // next stage is active until its own STARTED event lands.
  if (
    !isTerminal &&
    frontier >= 0 &&
    frontier < stages.length - 1 &&
    states[frontier] === "done"
  ) {
    states[frontier + 1] = "running";
  }

  if (isTerminal) {
    // A finished scan: success marks every stage done; a failure leaves
    // the rail where it stopped (frontier stage stays as-is).
    if (!isError) {
      for (let i = 0; i < states.length; i++) states[i] = "done";
    }
  }

  const derived: DerivedStage[] = stages.map((s, i) => ({
    ...s,
    state: states[i],
  }));

  const currentIdx = derived.findIndex(
    (s) => s.state === "running" || s.state === "paused",
  );
  const currentStageKey =
    isTerminal || currentIdx < 0 ? null : derived[currentIdx].key;

  const doneCount = states.filter((s) => s === "done").length;
  let progressPct: number;
  if (isTerminal) {
    progressPct = 100;
  } else {
    progressPct = Math.min(
      95,
      Math.round((doneCount / derived.length) * 100),
    );
  }

  let badge: string;
  if (isTerminal) {
    badge = terminalStatus as string;
  } else if (currentIdx >= 0) {
    badge = badgeForStage(derived[currentIdx]);
  } else {
    badge = "Queued";
  }

  return {
    stages: derived,
    currentStageKey,
    progressPct,
    badge,
    isTerminal,
    isError,
  };
}
