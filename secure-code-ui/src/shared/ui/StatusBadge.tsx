// secure-code-ui/src/shared/ui/StatusBadge.tsx
//
// One badge for every status the platform shows, with a colour and the word.
//
// Colour alone is not a status: it is unreadable for a colour-blind reader and invisible in a
// screenshot pasted into a report. The tone classes are shared with the coverage and asset
// tables, so "needs_follow_up" looks the same everywhere it appears.

const TONE: Record<string, string> = {
  completed: "is-ok",
  success: "is-ok",
  approved: "is-ok",
  up: "is-ok",
  reachable: "is-ok",
  running: "is-info",
  queued: "is-info",
  testing: "is-info",
  paused: "is-warn",
  pending: "is-warn",
  open: "is-warn",
  needs_follow_up: "is-warn",
  blocked: "is-warn",
  filtered: "is-warn",
  expired: "is-muted",
  cancelled: "is-muted",
  denied: "is-muted",
  ruled_out: "is-muted",
  not_applicable: "is-muted",
  failed: "is-bad",
  error: "is-bad",
  down: "is-bad",
  rejected: "is-bad",
  confirmed: "is-bad",
};

export function StatusBadge({ status, title }: { status: string; title?: string }) {
  const tone = TONE[(status || "").toLowerCase()] ?? "is-muted";
  return (
    <span className={`status-badge ${tone}`} title={title ?? status}>
      {status || "unknown"}
    </span>
  );
}

export default StatusBadge;
