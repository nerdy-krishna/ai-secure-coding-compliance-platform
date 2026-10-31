// Live elapsed-time hook for scan timers.
//
// Returns a formatted duration between `startIso` and `endIso`. While
// `endIso` is null the value ticks every second (an active scan); once
// the scan finishes it freezes at the final duration.

import { useEffect, useState } from "react";

/** Format a millisecond span as a compact `1h 2m` / `5m 12s` / `34s`. */
export function formatDuration(ms: number): string {
  const total = Math.max(0, Math.round(ms / 1000));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export function useElapsed(
  startIso?: string | null,
  endIso?: string | null,
): string {
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (endIso || !startIso) return;
    const t = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(t);
  }, [startIso, endIso]);

  if (!startIso) return "";
  const start = new Date(startIso).getTime();
  if (Number.isNaN(start)) return "";
  const end = endIso ? new Date(endIso).getTime() : now;
  return formatDuration(end - start);
}

/**
 * Live counter of the time a scan actually worked.
 *
 * `created_at → completed_at` is wall clock: it counts every minute the scan sat
 * waiting for a human at an approval gate. The backend therefore reports
 * `active_processing_seconds` (wall clock minus gate waits). This hook keeps that
 * number ticking forward only while the scan is genuinely working, and freezes it
 * the moment the scan parks at a gate, is stopped, or finishes.
 */
export function useActiveElapsed(
  baseSeconds: number | null | undefined,
  isWorking: boolean,
): string {
  const [seconds, setSeconds] = useState<number | null>(
    typeof baseSeconds === "number" ? Math.floor(baseSeconds) : null,
  );

  // Server truth wins whenever it reports more time than we have counted locally
  // (a resumed scan, a poll after a page was backgrounded).
  useEffect(() => {
    if (typeof baseSeconds !== "number") return;
    setSeconds((prev) =>
      prev === null || baseSeconds > prev ? Math.floor(baseSeconds) : prev,
    );
  }, [baseSeconds]);

  useEffect(() => {
    if (!isWorking) return;
    const timer = window.setInterval(() => {
      setSeconds((prev) => (prev === null ? prev : prev + 1));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [isWorking]);

  if (seconds === null) return "";
  return formatDuration(seconds * 1000);
}
