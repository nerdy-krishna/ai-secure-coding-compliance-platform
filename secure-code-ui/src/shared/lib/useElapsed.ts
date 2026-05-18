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
