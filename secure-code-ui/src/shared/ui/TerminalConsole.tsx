// secure-code-ui/src/shared/ui/TerminalConsole.tsx
//
// A live activity console, styled as a terminal.
//
// Both surfaces that do long-running work — a pentest run and an inventory CVE check —
// produce a stream of events that matter more as a narrative than as a list: what was
// tried, what came back, what it decided. This renders that stream as a console: fixed
// width columns for time and level, monospace, colour by outcome, expandable detail,
// and controls that behave the way a terminal does (auto-scroll until you scroll up).

import React, { useEffect, useMemo, useRef, useState } from "react";
import { Icon } from "./Icon";

export type ConsoleLevel = "info" | "success" | "warning" | "error" | "detail";

export type ConsoleStatus = "running" | "done" | "failed";

export interface ConsoleLine {
  id: string | number;
  /** ISO timestamp; rendered as local time-of-day. */
  at: string | null;
  /** Set for work that is still in flight, so the row can tick. */
  status?: ConsoleStatus;
  /** When the work started; drives the live elapsed counter. */
  startedAt?: string | null;
  /** Seconds the work took, once it has finished. */
  durationSeconds?: number | null;
  level: ConsoleLevel;
  /** Short label for the column after the timestamp, e.g. "tool", "match". */
  kind?: string;
  message: string;
  /** The same message without the length cap, shown in expanded view. */
  fullMessage?: string;
  /** Anything worth expanding: the raw payload, a request, a verdict. */
  detail?: unknown;
}

interface Props {
  title: string;
  lines: ConsoleLine[];
  /** Shown when there is nothing yet. */
  emptyHint?: string;
  /** True while work is running: shows the live dot. */
  live?: boolean;
  onClear?: () => void;
  /** Filename stem for the download action. */
  downloadName?: string;
  maxHeight?: number;
}

const LEVEL_GLYPH: Record<ConsoleLevel, string> = {
  info: "·",
  success: "✓",
  warning: "!",
  error: "✗",
  detail: "›",
};

function timeOfDay(iso: string | null): string {
  if (!iso) return "--:--:--";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "--:--:--";
  return date.toLocaleTimeString([], { hour12: false });
}

/** A ticking clock for a row that is still running. */
const Elapsed: React.FC<{ startedAt: string | null | undefined; finished?: boolean }> = ({
  startedAt,
  finished,
}) => {
  const [, setTick] = useState(0);
  useEffect(() => {
    if (finished || !startedAt) return;
    const timer = window.setInterval(() => setTick((value) => value + 1), 1000);
    return () => window.clearInterval(timer);
  }, [finished, startedAt]);

  if (!startedAt) return null;
  const started = new Date(startedAt).getTime();
  if (Number.isNaN(started)) return null;
  const seconds = Math.max(0, Math.round((Date.now() - started) / 1000));
  const text = seconds >= 60 ? `${Math.floor(seconds / 60)}m ${seconds % 60}s` : `${seconds}s`;
  // ZAP and nuclei legitimately run for minutes; past that, say so rather than
  // leaving the operator to guess whether it is working or wedged.
  const tone = finished ? "is-done" : seconds >= 300 ? " is-slow" : "";
  return (
    <span className={`console-elapsed${tone}`} title={seconds >= 300 ? "Still running" : undefined}>
      {text}
    </span>
  );
};

const TerminalConsole: React.FC<Props> = ({
  title,
  lines,
  emptyHint = "No activity yet.",
  live = false,
  onClear,
  downloadName = "activity",
  maxHeight = 460,
}) => {
  const bodyRef = useRef<HTMLDivElement | null>(null);
  const [pinned, setPinned] = useState(true); // auto-scroll while at the bottom
  const [paused, setPaused] = useState(false);
  const [copiedId, setCopiedId] = useState<string | number | null>(null);
  const [expanded, setExpanded] = useState<Set<string | number>>(new Set());
  // Expanded view shows every line in full — message and payload — with no clicking.
  // Per-line `detail` still works for a single entry when this is off.
  const [expandedView, setExpandedView] = useState(false);
  const [levels, setLevels] = useState<Set<ConsoleLevel>>(new Set());

  const visible = useMemo(
    () => (levels.size === 0 ? lines : lines.filter((line) => levels.has(line.level))),
    [lines, levels],
  );

  // Freeze the view while paused: the stream keeps arriving, the scroll does not move.
  useEffect(() => {
    if (!pinned || paused) return;
    const body = bodyRef.current;
    if (body) body.scrollTop = body.scrollHeight;
  }, [visible.length, pinned, paused]);

  const onScroll = () => {
    const body = bodyRef.current;
    if (!body) return;
    const atBottom = body.scrollHeight - body.scrollTop - body.clientHeight < 24;
    setPinned(atBottom);
  };

  const toggleLevel = (level: ConsoleLevel) => {
    setLevels((current) => {
      const next = new Set(current);
      if (next.has(level)) next.delete(level);
      else next.add(level);
      return next;
    });
  };

  const toggleExpanded = (id: string | number) => {
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const copyLine = async (line: ConsoleLine) => {
    const text = [timeOfDay(line.at), line.level.toUpperCase(), line.kind, line.message]
      .filter(Boolean)
      .join(" ");
    try {
      await navigator.clipboard.writeText(
        line.detail ? `${text}\n${JSON.stringify(line.detail, null, 2)}` : text,
      );
      setCopiedId(line.id);
      window.setTimeout(() => setCopiedId(null), 1200);
    } catch {
      /* clipboard unavailable; the download action remains */
    }
  };

  const download = () => {
    const text = visible
      .map((line) =>
        [
          line.at ?? "",
          line.level.toUpperCase(),
          line.kind ?? "",
          line.message,
          line.detail ? JSON.stringify(line.detail) : "",
        ]
          .filter(Boolean)
          .join("\t"),
      )
      .join("\n");
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${downloadName}.log`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const counts = useMemo(() => {
    const tally = { error: 0, warning: 0, success: 0 } as Record<string, number>;
    for (const line of lines) {
      if (line.level in tally) tally[line.level] += 1;
    }
    return tally;
  }, [lines]);

  return (
    <div className="console">
      <div className="console-bar">
        <span className="console-dots" aria-hidden="true">
          <i /> <i /> <i />
        </span>
        <span className="console-title">{title}</span>
        {live && !paused && <span className="console-live" title="Receiving events" />}
        <span className="console-count">
          {visible.length} line{visible.length === 1 ? "" : "s"}
          {counts.error ? ` · ${counts.error} error${counts.error === 1 ? "" : "s"}` : ""}
          {counts.warning ? ` · ${counts.warning} warning${counts.warning === 1 ? "" : "s"}` : ""}
        </span>
        <div className="console-tools">
          {(["error", "warning", "success", "info", "detail"] as ConsoleLevel[]).map((level) => (
            <button
              key={level}
              className={`console-filter${levels.has(level) ? " is-on" : ""}`}
              onClick={() => toggleLevel(level)}
              title={`Filter: ${level}`}
            >
              {LEVEL_GLYPH[level]}
            </button>
          ))}
          <button
            className={`console-tool${expandedView ? " is-on" : ""}`}
            onClick={() => setExpandedView((value) => !value)}
            title={expandedView ? "Collapse to one line per entry" : "Expand every entry in full"}
            aria-pressed={expandedView}
          >
            <Icon.PanelLeft size={12} />
          </button>
          <button
            className={`console-tool${paused ? " is-on" : ""}`}
            onClick={() => setPaused((value) => !value)}
            title={paused ? "Resume following" : "Pause following"}
          >
            {paused ? <Icon.Play size={12} /> : <Icon.Pause size={12} />}
          </button>
          <button className="console-tool" onClick={download} title="Download log">
            <Icon.Download size={12} />
          </button>
          {onClear && (
            <button className="console-tool" onClick={onClear} title="Clear view">
              <Icon.X size={12} />
            </button>
          )}
        </div>
      </div>

      <div
        className="console-body"
        ref={bodyRef}
        onScroll={onScroll}
        style={{ maxHeight: expandedView ? Math.max(maxHeight, 560) : maxHeight }}
      >
        {visible.length === 0 ? (
          <div className="console-empty">{emptyHint}</div>
        ) : (
          visible.map((line) => {
            const isOpen = expandedView || expanded.has(line.id);
            const text = expandedView ? line.fullMessage ?? line.message : line.message;
            return (
              <div
                key={line.id}
                className={`console-line is-${line.level}${line.status ? ` is-${line.status}` : ""}`}
              >
                <span className="console-time">{timeOfDay(line.at)}</span>
                <span className="console-glyph" aria-hidden="true">
                  {LEVEL_GLYPH[line.level]}
                </span>
                {line.kind && <span className="console-kind">{line.kind}</span>}
                {line.status === "running" && <span className="console-running" aria-label="running" />}
                <span className={`console-message${expandedView ? " is-expanded" : ""}`}>
                  {text}
                  {line.detail !== undefined && line.detail !== null && !expandedView && (
                    <button
                      className="console-expand"
                      onClick={() => toggleExpanded(line.id)}
                      title={isOpen ? "Hide detail" : "Show detail"}
                    >
                      {isOpen ? "hide" : "detail"}
                    </button>
                  )}
                  {isOpen && line.detail !== undefined && line.detail !== null && (
                    <pre className="console-detail">
                      {typeof line.detail === "string"
                        ? line.detail
                        : JSON.stringify(line.detail, null, 2)}
                    </pre>
                  )}
                </span>
                {line.status ? (
                  line.status === "running" ? (
                    <Elapsed startedAt={line.startedAt} />
                  ) : (
                    <span className={`console-elapsed is-done${line.status === "failed" ? " is-failed" : ""}`}>
                      {line.durationSeconds != null ? `${line.durationSeconds}s` : "done"}
                    </span>
                  )
                ) : null}
                <button
                  className="console-copy"
                  onClick={() => void copyLine(line)}
                  title="Copy this line"
                >
                  {copiedId === line.id ? "copied" : "copy"}
                </button>
              </div>
            );
          })
        )}
      </div>

      {!pinned && (
        <button
          className="console-jump"
          onClick={() => {
            setPinned(true);
            setPaused(false);
            const body = bodyRef.current;
            if (body) body.scrollTop = body.scrollHeight;
          }}
        >
          <Icon.ChevronD size={12} /> {live ? "Jump to latest" : "Jump to end"}
        </button>
      )}
    </div>
  );
};

export default TerminalConsole;
