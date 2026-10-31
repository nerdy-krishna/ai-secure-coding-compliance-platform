// secure-code-ui/src/shared/lib/scanRoute.ts
//
// Picks the right route to land on when navigating to a scan from a
// list page. Terminal statuses go to the read-only ResultsPage; every
// non-terminal status (queued, running, pending-approval) goes to the
// ScanRunningPage which carries the live progress + approval UI.

const TERMINAL_STATUSES = new Set([
  "COMPLETED",
  "REMEDIATION_COMPLETED",
  "FAILED",
  "CANCELLED",
  "EXPIRED",
  "STOPPED_BEFORE_LLM",
  "BLOCKED_USER_DECLINE",
  "BLOCKED_PRE_LLM",
]);

export function isTerminalStatus(status: string): boolean {
  return TERMINAL_STATUSES.has(status);
}

export function scanRouteFor(scanId: string, status: string): string {
  return isTerminalStatus(status)
    ? `/analysis/results/${scanId}`
    : `/analysis/scanning/${scanId}`;
}
