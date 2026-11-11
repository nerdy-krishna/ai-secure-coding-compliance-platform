// secure-code-ui/src/pages/assets/useScanActivity.ts
//
// One page, one scan, one window.
//
// The activity console used to be shared by every tab, so a probe started on the Assets tab
// appeared inside a CVE check, and the history of every earlier scan was replayed at the top
// of the page. This hook gives each page its own console: it asks the event stream where it
// is now, and only shows what happens from the moment the scan starts.
//
// It also owns the scan's state — idle, in progress, completed, cancelled, error — because a
// console that cannot say whether the thing is still running is a log, not a monitor.

import { useCallback, useEffect, useRef, useState } from "react";
import type { ConsoleLine, ConsolePhase } from "../../shared/ui/TerminalConsole";
import { eventsCursor, listAssetEvents } from "../../shared/api/assetsService";

export interface ScanActivity {
  lines: ConsoleLine[];
  phase: ConsolePhase;
  /** What the phase means in this page's terms, e.g. "Researching". */
  label: string;
  /** Seconds since the scan started, for the header. */
  elapsed: number;
  start: (label: string) => Promise<void>;
  finish: (phase: ConsolePhase, label?: string) => void;
  clear: () => void;
  /** True once a scan has been started at least once. */
  hasRun: boolean;
}

const POLL_MS = 1500;
const MAX_LINES = 500;

export default function useScanActivity(): ScanActivity {
  const [lines, setLines] = useState<ConsoleLine[]>([]);
  const [phase, setPhase] = useState<ConsolePhase>("idle");
  const [label, setLabel] = useState("Idle");
  const [hasRun, setHasRun] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const cursor = useRef<number | null>(null);
  const startedAt = useRef<number | null>(null);
  const seen = useRef<Set<number>>(new Set());

  const append = useCallback((incoming: ConsoleLine[]) => {
    if (!incoming.length) return;
    setLines((current) => {
      const next = [...current];
      for (const line of incoming) {
        if (typeof line.id === "number") {
          if (seen.current.has(line.id)) continue;
          seen.current.add(line.id);
        }
        next.push(line);
      }
      return next.length > MAX_LINES ? next.slice(next.length - MAX_LINES) : next;
    });
  }, []);

  // Poll from the cursor captured at scan start. Nothing older than the scan can appear.
  useEffect(() => {
    if (cursor.current === null) return;
    let stopped = false;

    const tick = async () => {
      try {
        const batch = await listAssetEvents(cursor.current ?? 0);
        if (stopped || !batch.items.length) return;
        cursor.current = batch.last_id;
        append(
          batch.items.map((event) => ({
            id: event.id,
            at: event.at,
            level: event.level,
            kind: event.kind,
            message: event.message,
            detail: event.payload ?? undefined,
          })),
        );
        // An error in the stream is an error in the scan, unless the operator stopped it.
        if (batch.items.some((event) => event.level === "error")) {
          setPhase((current) => (current === "running" ? "error" : current));
        }
      } catch {
        /* a poll failure is not a scan failure */
      }
    };

    void tick();
    const timer = window.setInterval(() => void tick(), POLL_MS);
    return () => {
      stopped = true;
      window.clearInterval(timer);
    };
  }, [append, hasRun]);

  // The elapsed clock only runs while the scan does.
  useEffect(() => {
    if (phase !== "running" || startedAt.current === null) return;
    const timer = window.setInterval(() => {
      setElapsed(Math.round((Date.now() - (startedAt.current ?? Date.now())) / 1000));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [phase]);

  const start = useCallback(
    async (nextLabel: string) => {
      // Capture the stream position *before* the request that begins the work, so the
      // first events of this scan are inside the window and earlier ones are not.
      const mark = await eventsCursor().catch(() => 0);
      cursor.current = mark;
      seen.current = new Set();
      startedAt.current = Date.now();
      setElapsed(0);
      setLines([]);
      setPhase("running");
      setLabel(nextLabel);
      setHasRun(true);
    },
    [],
  );

  const finish = useCallback((next: ConsolePhase, nextLabel?: string) => {
    setPhase(next);
    if (nextLabel) setLabel(nextLabel);
    if (next !== "running") setElapsed(Math.round((Date.now() - (startedAt.current ?? Date.now())) / 1000));
  }, []);

  const clear = useCallback(() => {
    // Clearing a per-scan window clears the window, not the tenant's event log.
    setLines([]);
  }, []);

  return { lines, phase, label, elapsed, start, finish, clear, hasRun };
}
