// secure-code-ui/src/shared/lib/scanStatus.ts
//
// Single source of truth for how scan-status strings render in the UI.
// The backend uses raw enum names (`BLOCKED_USER_DECLINE`, `BLOCKED_PRE_LLM`,
// `PENDING_COST_APPROVAL`, …) which read poorly when surfaced verbatim.
// Every chip/banner/H1 that shows status text should go through
// `displayStatus()` so the wording stays consistent.
//
// The `kind` axis separates *outcome* from *running state*:
//   - "running"       → still in progress, blue pulse
//   - "needs-input"   → paused for a human gate (cost / prescan approval)
//   - "completed"     → success terminal, green
//   - "stopped"       → user-initiated terminal (Stop scan, prescan decline);
//                       NOT a failure — must not surface "Scan failed"
//   - "blocked"       → safety-guard terminal (critical secret short-circuit);
//                       not a user error and not a code bug — amber/warn
//   - "expired"       → auto-expired terminal; neutral, not a failure
//   - "failed"        → genuine error terminal; red, only this gets "Scan failed"
//
// The `tone` axis is for color picking (chip / banner backgrounds).

export type StatusKind =
  | "running"
  | "needs-input"
  | "completed"
  | "stopped"
  | "blocked"
  | "expired"
  | "failed";

export type StatusTone = "info" | "success" | "muted" | "warn" | "critical";

interface StatusMeta {
  /** User-facing label. Sentence case, no trailing period. */
  label: string;
  kind: StatusKind;
  tone: StatusTone;
}

const STATUS_TABLE: Record<string, StatusMeta> = {
  // Running
  QUEUED: { label: "Queued", kind: "running", tone: "info" },
  ANALYZING_CONTEXT: { label: "Analyzing context", kind: "running", tone: "info" },
  ESTIMATING_COST: { label: "Estimating cost", kind: "running", tone: "info" },
  QUEUED_FOR_SCAN: { label: "Queued for scan", kind: "running", tone: "info" },
  RUNNING_AGENTS: { label: "Running security agents", kind: "running", tone: "info" },
  CORRELATING: { label: "Correlating findings", kind: "running", tone: "info" },
  GENERATING_REPORTS: { label: "Generating reports", kind: "running", tone: "info" },

  // Human-gate states
  PENDING_COST_APPROVAL: {
    label: "Awaiting cost approval",
    kind: "needs-input",
    tone: "info",
  },
  PENDING_PRESCAN_APPROVAL: {
    label: "Awaiting prescan review",
    kind: "needs-input",
    tone: "info",
  },
  PENDING_PROFILING_APPROVAL: {
    label: "Awaiting profiling approval",
    kind: "needs-input",
    tone: "info",
  },

  // Success
  COMPLETED: { label: "Completed", kind: "completed", tone: "success" },
  REMEDIATION_COMPLETED: {
    label: "Remediation complete",
    kind: "completed",
    tone: "success",
  },

  // User-initiated stops — NOT failures
  CANCELLED: { label: "Stopped", kind: "stopped", tone: "muted" },
  BLOCKED_USER_DECLINE: {
    label: "Stopped before LLM analysis",
    kind: "stopped",
    tone: "muted",
  },

  // Safety-guard stop — NOT a failure
  BLOCKED_PRE_LLM: {
    label: "Blocked (critical secret)",
    kind: "blocked",
    tone: "warn",
  },

  // Auto-expired — neutral terminal, not a failure
  EXPIRED: { label: "Expired", kind: "expired", tone: "muted" },

  // Genuine error
  FAILED: { label: "Failed", kind: "failed", tone: "critical" },
};

function lookup(status: string | null | undefined): StatusMeta {
  if (!status) {
    // Used for the brief moment before the first scan-status fetch
    // resolves. Render as a neutral "Loading…" rather than the previous
    // QUEUED-by-default which made every page flap from "Analyzing
    // your code" to the real terminal state.
    return { label: "Loading…", kind: "running", tone: "muted" };
  }
  return (
    STATUS_TABLE[status] ?? {
      // Unknown status from a future backend release: fall back to the
      // raw enum but humanized, and treat it as "running" so we don't
      // accidentally label an unknown state as a failure.
      label: status.replace(/_/g, " ").toLowerCase(),
      kind: "running",
      tone: "info",
    }
  );
}

/** User-facing label for a scan status (e.g. `BLOCKED_USER_DECLINE` → "Stopped before LLM analysis"). */
export function displayStatus(status: string | null | undefined): string {
  return lookup(status).label;
}

export function statusKind(status: string | null | undefined): StatusKind {
  return lookup(status).kind;
}

export function statusTone(status: string | null | undefined): StatusTone {
  return lookup(status).tone;
}

/** True only for the genuine-error terminal (`FAILED`). Use this to
 *  drive "Scan failed" banners — never lump in user stops or safety
 *  blocks. */
export function isErrorStatus(status: string | null | undefined): boolean {
  return statusKind(status) === "failed";
}

/** True for user-initiated terminals (`CANCELLED`, `BLOCKED_USER_DECLINE`). */
export function isStoppedStatus(status: string | null | undefined): boolean {
  return statusKind(status) === "stopped";
}

/** True for safety-guard terminals (`BLOCKED_PRE_LLM`). */
export function isBlockedStatus(status: string | null | undefined): boolean {
  return statusKind(status) === "blocked";
}

/** True for any non-success terminal (failed / stopped / blocked / expired).
 *  Use this to disable "View results" or hide stage-progress affordances. */
export function isUnsuccessfulTerminal(
  status: string | null | undefined,
): boolean {
  const k = statusKind(status);
  return k === "failed" || k === "stopped" || k === "blocked" || k === "expired";
}
