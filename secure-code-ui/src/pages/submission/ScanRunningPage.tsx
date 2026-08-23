// secure-code-ui/src/pages/submission/ScanRunningPage.tsx
//
// Port of the SCCAP design bundle's ScanRunning screen, wired to the
// real backend via the SSE endpoint added in F.5.3c:
//   GET /api/v1/scans/{scan_id}/stream
// Emits three event types: scan_state (status transitions), scan_event
// (new ScanEvent rows), done (terminal status reached). We render each
// scan_event as a pipeline stage and advance the progress bar against a
// fixed stage list that mirrors the worker graph.

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useLocation, useNavigate, useParams } from "react-router-dom";
import { CriticalSecretOverrideModal } from "../../features/prescan-approval/CriticalSecretOverrideModal";
import { PrescanReviewCard } from "../../features/prescan-approval/PrescanReviewCard";
import { scanService } from "../../shared/api/scanService";
import { useAuth } from "../../shared/hooks/useAuth";
import {
  displayStatus,
  isBlockedStatus,
  isErrorStatus,
  isStoppedStatus,
  isUnsuccessfulTerminal,
} from "../../shared/lib/scanStatus";
import type { PrescanReviewResponse } from "../../shared/types/api";
import { Icon } from "../../shared/ui/Icon";
import { StageIcon } from "../../shared/ui/StageIcon";
import { deriveScanProgress } from "../../shared/lib/scanProgress";
import type { ApprovalGate, CostDetails } from "../../shared/lib/scanContract";
import { useElapsed } from "../../shared/lib/useElapsed";
import { SectionHead } from "../../shared/ui/DashboardPrimitives";
import { Modal } from "../../shared/ui/Modal";
import { PageHeader } from "../../shared/ui/PageHeader";
import { useToast } from "../../shared/ui/Toast";

interface ScanEventMsg {
  schema_version: number;
  cursor: string;
  scan_id: string;
  event_id: number;
  attempt_id?: string | null;
  activity_kind:
    | "workflow"
    | "scanner"
    | "llm_call"
    | "retry"
    | "warning"
    | "degradation"
    | "decision"
    | "cancellation"
    | "terminal";
  stage_name: string;
  status: string; // "COMPLETED" / "STARTED" / "FAILED" for the event itself
  timestamp: string | null;
  // §3.10b — per-event payload. Carries `{file_path, findings_count,
  // fixes_count}` for `FILE_ANALYZED` events; null for legacy stage
  // events (QUEUED / ANALYZING_CONTEXT / etc.).
  details?: {
    [key: string]: unknown;
    file_path?: string;
    findings_count?: number;
    fixes_count?: number;
    llm_calls?: number;
    reused_tasks?: number;
    skipped_tasks?: number;
    failed_tasks?: number;
    token_count?: number;
    elapsed_ms?: number;
    classification?: string;
    progress_category?: string;
    phase?: string;
    latency_ms?: number;
    retry_attempt?: number;
    max_retries?: number;
    backoff_ms?: number;
    provider?: string;
    model?: string;
    agent_name?: string;
    within_slo?: boolean;
  } | null;
}

// One row in the per-file analysis log surfaced by §3.10b. Keyed by
// file_path so the same file showing up twice (e.g. multi-chunk
// analysis) collapses to a single row with the latest counts.
interface FileProgressItem {
  file_path: string;
  findings_count: number;
  fixes_count: number;
  llm_calls: number;
  reused_tasks: number;
  skipped_tasks: number;
  failed_tasks: number;
  token_count: number;
  elapsed_ms: number;
  classification?: string;
  progress_category?: string;
  timestamp: string | null;
}

interface ScanStateMsg {
  scan_id: string;
  status: string;
  // Carried only on the cost-approval flip — see SSE handler in
  // routers/projects.py. Lets the frontend surface the estimate the
  // moment status flips to PENDING_COST_APPROVAL without a manual
  // page refresh.
  cost_details?: CostDetails | null;
  active_approval_gate?: ApprovalGate | null;
}

// Normalise a scan-event from any source — the result-endpoint seed,
// the SSE `scan_event` stream, or the polling fallback — into a
// `ScanEventMsg`. Returns null for a malformed payload.
const toScanEventMsg = (
  scanId: string,
  raw: unknown,
): ScanEventMsg | null => {
  const e = raw as {
    schema_version?: unknown;
    cursor?: unknown;
    event_id?: unknown;
    attempt_id?: unknown;
    activity_kind?: unknown;
    stage_name?: unknown;
    status?: unknown;
    timestamp?: unknown;
    details?: ScanEventMsg["details"];
  };
  if (
    (e.schema_version !== undefined && e.schema_version !== 1) ||
    typeof e.stage_name !== "string" ||
    e.stage_name.length >= 64 ||
    typeof e.status !== "string" ||
    e.status.length >= 64
  ) {
    return null;
  }
  const allowedKinds = new Set<ScanEventMsg["activity_kind"]>([
    "workflow",
    "scanner",
    "llm_call",
    "retry",
    "warning",
    "degradation",
    "decision",
    "cancellation",
    "terminal",
  ]);
  const activityKind = allowedKinds.has(
    e.activity_kind as ScanEventMsg["activity_kind"],
  )
    ? (e.activity_kind as ScanEventMsg["activity_kind"])
    : "workflow";
  return {
    schema_version: 1,
    cursor:
      typeof e.cursor === "string"
        ? e.cursor
        : String(typeof e.event_id === "number" ? e.event_id : 0),
    scan_id: scanId,
    event_id: typeof e.event_id === "number" ? e.event_id : 0,
    attempt_id: typeof e.attempt_id === "string" ? e.attempt_id : null,
    activity_kind: activityKind,
    stage_name: e.stage_name,
    status: e.status,
    timestamp: typeof e.timestamp === "string" ? e.timestamp : null,
    details: e.details ?? null,
  };
};

const eventDisplayName = (stageName: string): string => {
  switch (stageName) {
    case "MANUAL_RESUME_REQUESTED":
      return "Manual resume requested";
    case "RESUME_ARTIFACT_EVALUATION":
      return "Resume artifacts evaluated";
    case "MANUAL_RESTART_REQUESTED":
      return "Manual restart requested";
    case "COVERAGE_WARNING":
      return "Coverage warning";
    case "PRIMARY_LLM_DEGRADED":
      return "Primary LLM degraded";
    case "SECONDARY_LLM_DEGRADED":
      return "Secondary LLM degraded";
    case "GLOBAL_CONSOLIDATION":
      return "Global consolidation";
    default:
      return stageName
        .toLowerCase()
        .replace(/_/g, " ")
        .replace(/^./, (first: string) => first.toUpperCase());
  }
};

const ACTIVITY_DETAIL_KEYS = [
  "message",
  "scanner",
  "scanner_status",
  "file_path",
  "classification",
  "progress_category",
  "findings_count",
  "fixes_count",
  "llm_calls",
  "reused_tasks",
  "skipped_tasks",
  "failed_tasks",
  "rerun_tasks",
  "completed_tasks",
  "elapsed_ms",
  "warnings",
  "files_total",
  "warnings_total",
  "categories",
  "raw_count",
  "consolidated_count",
  "merged_roots",
  "merged_inputs",
  "dropped",
  "validated_count",
  "rejected_count",
  "eligible_count",
  "total_findings",
  "confirmed",
  "mitigated",
  "unconfirmed",
  "input_count",
  "output_count",
  "merged_clusters",
  "findings_total",
  "risk_score",
  "total_estimated_cost",
  "expected_estimated_cost",
  "upper_bound_estimated_cost",
  "estimate_confidence",
  "total_input_tokens",
  "predicted_output_tokens",
  "lane",
  "calls",
  "failures",
  "successful_lanes",
  "skip_reason",
  "token_count",
  "mode",
  "phase",
  "latency_ms",
  "slo_ms",
  "within_slo",
  "terminated_processes",
  "provider",
  "model",
  "agent_name",
  "stage",
  "retry_attempt",
  "max_retries",
  "backoff_ms",
  "provider_requests",
  "prompt_tokens",
  "completion_tokens",
  "error_class",
] as const;

const formatActivityValue = (key: string, value: unknown): string | null => {
  if (value === null || value === undefined || value === "") return null;
  if (
    ["elapsed_ms", "latency_ms", "backoff_ms", "slo_ms"].includes(key) &&
    typeof value === "number"
  ) {
    return `${(value / 1000).toFixed(value >= 10000 ? 0 : 1)}s`;
  }
  if (
    [
      "total_estimated_cost",
      "expected_estimated_cost",
      "upper_bound_estimated_cost",
    ].includes(key) &&
    typeof value === "number"
  ) {
    return `$${value.toFixed(4)}`;
  }
  if (Array.isArray(value)) return value.slice(0, 5).map(String).join(", ");
  if (typeof value === "object") {
    return Object.entries(value as Record<string, unknown>)
      .slice(0, 6)
      .map(([nestedKey, nestedValue]) => `${nestedKey}: ${String(nestedValue)}`)
      .join(", ");
  }
  return String(value);
};

const formatActivityDetails = (
  details: ScanEventMsg["details"],
): string => {
  if (!details) return "";
  const fragments: string[] = [];
  for (const key of ACTIVITY_DETAIL_KEYS) {
    if (!(key in details)) continue;
    const value = formatActivityValue(key, details[key]);
    if (!value) continue;
    if (key === "message" || key === "file_path") fragments.push(value);
    else fragments.push(`${key.replace(/_/g, " ")}: ${value}`);
  }
  return fragments.length > 0 ? ` — ${fragments.join(" · ")}` : "";
};

// Merge new scan-events into the existing list, deduped by the stable
// DB id (`event_id`). All three feeds — seed, SSE, poll — re-emit the
// same rows, so a stable-id dedupe is what keeps the live event log
// from showing every event two or three times. Events with id 0 (a
// backend too old to expose the id) fall back to a stage+timestamp key.
const mergeScanEvents = (
  prev: ScanEventMsg[],
  incoming: ScanEventMsg[],
): ScanEventMsg[] => {
  if (incoming.length === 0) return prev;
  const keyOf = (e: ScanEventMsg) =>
    e.event_id > 0
      ? `id:${e.event_id}`
      : `fp:${e.stage_name}|${e.timestamp ?? ""}`;
  const seen = new Set(prev.map(keyOf));
  let changed = false;
  const merged = [...prev];
  for (const e of incoming) {
    const k = keyOf(e);
    if (seen.has(k)) continue;
    seen.add(k);
    merged.push(e);
    changed = true;
  }
  if (!changed) return prev;
  // Stable display order by the monotonic DB id when present.
  merged.sort((a, b) =>
    a.event_id > 0 && b.event_id > 0 ? a.event_id - b.event_id : 0,
  );
  return merged.slice(-500);
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

const hasCompletedCancellation = (events: ScanEventMsg[]) =>
  events.some(
    (event) =>
      event.stage_name === "CANCELLATION" && event.status === "COMPLETED",
  );

// `fmtStatus` was a raw `BLOCKED_USER_DECLINE → "blocked user decline"`
// transform that surfaced the backend enum name in chips and the
// status card. Replaced by `displayStatus()` from
// `shared/lib/scanStatus` so wording is consistent across all pages
// and statuses like "Stopped before LLM analysis" / "Blocked
// (critical secret)" render properly.

const ScanRunningPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const queryClient = useQueryClient();
  const toast = useToast();
  // Status starts `null` — NOT "QUEUED" — so the page doesn't flap
  // from "Analyzing your code" / "queued" to the real terminal state
  // for the few hundred ms before the one-shot getScanResult resolves.
  // Renders a small loading skeleton until the first known status.
  const [status, setStatus] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string>("");
  // Whether the scan opted in to cross-file validation (#82). Seeded
  // from the one-shot getScanResult below; drives the extra stage row.
  const [crossFileValidation, setCrossFileValidation] = useState(false);
  const [hasResumableArtifacts, setHasResumableArtifacts] = useState(false);
  const [events, setEvents] = useState<ScanEventMsg[]>([]);
  const [activityKindFilter, setActivityKindFilter] = useState("all");
  const [activityStageFilter, setActivityStageFilter] = useState("all");
  // §3.10b — per-file analysis progress, keyed by file_path so a file
  // showing up multiple times collapses to one row. Renders below the
  // pipeline stages while RUNNING_AGENTS is active.
  const [fileProgress, setFileProgress] = useState<
    Record<string, FileProgressItem>
  >({});
  const [streamError, setStreamError] = useState<string | null>(null);
  const [costDetails, setCostDetails] = useState<CostDetails | null>(null);
  const [activeApprovalGate, setActiveApprovalGate] =
    useState<ApprovalGate | null>(null);
  const [approving, setApproving] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [stopConfirmOpen, setStopConfirmOpen] = useState(false);
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [runControlMode, setRunControlMode] = useState<"resume" | "restart" | null>(null);
  const [runControlSubmitting, setRunControlSubmitting] = useState(false);
  // Project pointers seeded from the one-shot getScanResult call below.
  // Used to route back to the scan's project page after delete instead
  // of bouncing the user to the dashboard (a queued/failed scan has no
  // summary_report, so we can't pull these from the report payload).
  const [projectInfo, setProjectInfo] = useState<{
    id: string;
    name: string;
  } | null>(null);
  const { user } = useAuth();
  const isSuperuser = !!user?.is_superuser;
  const [prescanReview, setPrescanReview] = useState<PrescanReviewResponse | null>(
    null,
  );
  const [prescanLoading, setPrescanLoading] = useState(false);
  const [overrideOpen, setOverrideOpen] = useState(false);
  const [declining, setDeclining] = useState(false);
  // Optimistic dismiss for the pending-* approval panels. Tracks the
  // status the user submitted against (not just a boolean) — when the
  // worker flips the scan from PENDING_PRESCAN_APPROVAL straight to
  // PENDING_COST_APPROVAL, a plain boolean would still match
  // "current status is pending" and the cost card would never render.
  // The dismiss only applies while `submittedForStatus === status`;
  // once status changes value, the flag naturally falls away and the
  // next gate (if any) renders normally.
  const [submittedForGateId, setSubmittedForGateId] = useState<string | null>(
    null,
  );
  const decisionKeysRef = useRef(new Map<string, string>());
  const closedGateIdsRef = useRef(new Set<string>());
  const lastFetchedStatusRef = useRef<string | null>(null);
  const esRef = useRef<EventSource | null>(null);

  // Seed `status` from a one-shot HTTP fetch on mount. The SSE stream
  // emits live updates only and currently can't authenticate (cookie
  // path not wired in `current_active_user_sse`); without this seed the
  // page stays at the initial "QUEUED" string forever for any scan
  // that's already terminal (CANCELLED / FAILED / COMPLETED) when the
  // user lands here.
  useEffect(() => {
    if (!scanId) return;
    let cancelled = false;
    scanService
      .getScanResult(scanId)
      .then((r) => {
        if (cancelled) return;
        if (typeof r.status === "string" && r.status.length < 64) {
          setStatus(r.status);
        }
        if (typeof r.cross_file_validation === "boolean") {
          setCrossFileValidation(r.cross_file_validation);
        }
        setHasResumableArtifacts(Boolean(r.has_resumable_artifacts));
        if (r.project_id) {
          setProjectInfo({
            id: r.project_id,
            name: r.project_name || "Project",
          });
        }
        if (r.cost_details) {
          setCostDetails(r.cost_details);
        }
        setActiveApprovalGate(r.active_approval_gate ?? null);
        // Seed the live-event-log + stage-progress from the DB.
        // Terminal scans' SSE streams emit these once and close, so
        // a user landing AFTER the scan finished otherwise sees
        // "Waiting for events…" forever. The SSE stream and the
        // polling fallback both top up; `mergeScanEvents` dedupes
        // every feed by the stable `event_id`.
        const seeded = (r.events ?? [])
          .map((e) => toScanEventMsg(scanId, e))
          .filter((e): e is ScanEventMsg => e !== null);
        if (seeded.length > 0) {
          setEvents((prev) => mergeScanEvents(prev, seeded));
        }
      })
      .catch(() => {
        // Best-effort — leave the SSE stream to fill in if it can. The
        // user will still see "Lost connection to the scan stream"
        // below if both paths fail.
      });
    return () => {
      cancelled = true;
    };
  }, [scanId]);

  // Polling fallback. The SSE stream is the primary live feed, but it
  // can silently stall — a dropped connection that doesn't surface an
  // error, a token-refresh race, a proxy that buffers events. Without
  // this, the only recovery was a manual page refresh. While the scan
  // is non-terminal we re-read `GET /scans/{id}/result` every few
  // seconds and merge `status` + `events` + `cost_details`; every feed
  // is deduped by `event_id`, so this never double-counts. Polling
  // stops as soon as the scan reaches a terminal status.
  useEffect(() => {
    if (!scanId) return;
    if (
      status &&
      TERMINAL_STATUSES.has(status) &&
      !(status === "CANCELLED" && !hasCompletedCancellation(events))
    )
      return;
    let cancelled = false;
    const POLL_INTERVAL_MS = 5000;

    const tick = async () => {
      try {
        const r = await scanService.getScanResult(scanId);
        if (cancelled) return;
        if (typeof r.status === "string" && r.status.length < 64) {
          setStatus(r.status);
          if (r.error_message) {
            setErrorMessage(r.error_message);
          }
        }
        setHasResumableArtifacts(Boolean(r.has_resumable_artifacts));
        if (r.cost_details) {
          setCostDetails((prev) => ({ ...(prev ?? {}), ...r.cost_details }));
        }
        setActiveApprovalGate(r.active_approval_gate ?? null);
        const polled = (r.events ?? [])
          .map((e) => toScanEventMsg(scanId, e))
          .filter((e): e is ScanEventMsg => e !== null);
        if (polled.length > 0) {
          setEvents((prev) => mergeScanEvents(prev, polled));
        }
      } catch {
        // Best-effort — the next tick (or SSE) recovers.
      }
    };

    const timer = setInterval(() => void tick(), POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [scanId, status, events]);

  // Open the SSE stream on mount; close on unmount or when status goes
  // terminal. EventSource cannot send Authorization headers, so we
  // mint a short-TTL, scan-id-bound JWT first (POST /stream-token,
  // 60s TTL, audience "sse:scan-stream") and pass it as
  // ?access_token=… The token's narrow audience + scan-binding +
  // short lifetime mitigates the access-log exposure that disqualifies
  // raw access tokens from URLs (V16.2.5).
  //
  // Reconnect strategy: the JWT TTL is shorter than most scans, so a
  // transient drop (idle proxy, network blip) past 60s sees the
  // browser's auto-retry hit a 401 with the now-expired token and
  // EventSource gives up forever. We override that by handling the
  // CLOSED state ourselves — close, mint a fresh token, and re-open
  // with exponential backoff. `last_event_id` is round-tripped to the
  // backend so reconnects don't re-emit history we already rendered.
  useEffect(() => {
    if (!scanId) return;
    const apiBase = (import.meta.env.VITE_API_BASE_URL as string) || "/api/v1";
    let cancelled = false;
    let retryAttempt = 0;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;
    // Highest SSE-issued event id we've rendered. Sent as
    // ?last_event_id=… on reconnect so the backend skips events we
    // already ingested. `mergeScanEvents` dedupes by `event_id`
    // regardless, so a replayed event is harmless either way.
    let lastSeenEventId = 0;

    const attachListeners = (es: EventSource) => {
      es.addEventListener("scan_state", (ev) => {
        try {
          const payload = JSON.parse((ev as MessageEvent).data) as ScanStateMsg;
          if (
            typeof payload.status !== "string" ||
            payload.status.length >= 64
          ) {
            return;
          }
          // First successful frame after (re)connect — reset backoff
          // and clear any "Lost connection…" banner.
          retryAttempt = 0;
          setStreamError(null);
          setStatus(payload.status);
          // Backend ships `cost_details` only on the cost-approval
          // flip; merge so the estimate renders live without forcing
          // a page refresh.
          if (payload.cost_details) {
            setCostDetails((prev) => ({
              ...(prev ?? {}),
              ...payload.cost_details,
            }));
          }
          const streamedGate = payload.active_approval_gate ?? null;
          setActiveApprovalGate(
            streamedGate && !closedGateIdsRef.current.has(streamedGate.gate_id)
              ? streamedGate
              : null,
          );
        } catch {
          // noop
        }
      });

      es.addEventListener("scan_event", (ev) => {
        try {
          const raw = JSON.parse((ev as MessageEvent).data) as unknown;
          const msg = toScanEventMsg(scanId, raw);
          if (!msg) return;
          retryAttempt = 0;
          setStreamError(null);
          if (msg.event_id > lastSeenEventId) {
            lastSeenEventId = msg.event_id;
          }
          // mergeScanEvents dedupes by event_id, so a replay on
          // reconnect or an overlap with the seed/poll feed is a no-op.
          setEvents((prev) => mergeScanEvents(prev, [msg]));
          if (msg.stage_name === "FILE_ANALYZED" && msg.details?.file_path) {
            const filePath = String(msg.details.file_path).slice(0, 512);
            if (!filePath) return;
            const findingsCount = Math.max(
              0,
              Number(msg.details?.findings_count) | 0,
            );
            const fixesCount = Math.max(
              0,
              Number(msg.details?.fixes_count) | 0,
            );
            setFileProgress((prev) => {
              const next = {
                ...prev,
                [filePath]: {
                  file_path: filePath,
                  findings_count: findingsCount,
                  fixes_count: fixesCount,
                  llm_calls: Math.max(0, Number(msg.details?.llm_calls) | 0),
                  reused_tasks: Math.max(0, Number(msg.details?.reused_tasks) | 0),
                  skipped_tasks: Math.max(0, Number(msg.details?.skipped_tasks) | 0),
                  failed_tasks: Math.max(0, Number(msg.details?.failed_tasks) | 0),
                  token_count: Math.max(0, Number(msg.details?.token_count) | 0),
                  elapsed_ms: Math.max(0, Number(msg.details?.elapsed_ms) | 0),
                  classification: msg.details?.classification,
                  progress_category: msg.details?.progress_category,
                  timestamp: msg.timestamp,
                },
              };
              const keys = Object.keys(next);
              if (keys.length > 1000) {
                const oldest = keys.reduce((a, b) =>
                  (next[a].timestamp ?? "") <= (next[b].timestamp ?? "") ? a : b,
                );
                delete next[oldest];
              }
              return next;
            });
          }
        } catch {
          // noop
        }
      });

      es.addEventListener("done", (ev) => {
        try {
          const payload = JSON.parse((ev as MessageEvent).data) as ScanStateMsg;
          if (
            typeof payload.status !== "string" ||
            payload.status.length >= 64
          ) {
            es.close();
            return;
          }
          setStatus(payload.status);
        } catch {
          // noop
        }
        // Stream is intentionally closed by the server; suppress
        // reconnect.
        cancelled = true;
        es.close();
      });

      es.onerror = () => {
        // Native auto-retry has already failed (or the response was
        // a hard error like 401 from an expired token). Take over:
        // close cleanly, mint a fresh token, and re-open with backoff.
        if (es.readyState === EventSource.CLOSED) {
          try {
            es.close();
          } catch {
            // noop
          }
          if (esRef.current === es) esRef.current = null;
          if (cancelled) return;
          // Cap retry attempts so a permanently-broken stream
          // doesn't busy-loop forever.
          if (retryAttempt >= 8) {
            setStreamError("Lost connection to the scan stream.");
            return;
          }
          const delay = Math.min(15000, 500 * 2 ** retryAttempt);
          retryAttempt += 1;
          if (retryTimer) clearTimeout(retryTimer);
          retryTimer = setTimeout(() => void connect(), delay);
        }
      };
    };

    const connect = async () => {
      if (cancelled) return;
      let token: string;
      try {
        const issued = await scanService.getStreamToken(scanId);
        token = issued.access_token;
      } catch (err) {
        if (cancelled) return;
        if (retryAttempt >= 8) {
          const e = err as { message?: string };
          setStreamError(
            e.message || "Could not authorize the live scan stream.",
          );
          return;
        }
        const delay = Math.min(15000, 500 * 2 ** retryAttempt);
        retryAttempt += 1;
        if (retryTimer) clearTimeout(retryTimer);
        retryTimer = setTimeout(() => void connect(), delay);
        return;
      }
      if (cancelled) return;
      const params = new URLSearchParams({ access_token: token });
      if (lastSeenEventId > 0) {
        params.set("last_event_id", String(lastSeenEventId));
      }
      const url =
        `${apiBase}/scans/${encodeURIComponent(scanId)}/stream?` +
        params.toString();
      const es = new EventSource(url, { withCredentials: true });
      esRef.current = es;
      attachListeners(es);
    };

    void connect();

    return () => {
      cancelled = true;
      if (retryTimer) clearTimeout(retryTimer);
      esRef.current?.close();
      esRef.current = null;
    };
  }, [scanId]);

  // When the scan TRANSITIONS to a terminal status (success or
  // BLOCKED_PRE_LLM short-circuit) WHILE the user is watching, auto-
  // navigate to the results page after 1.5s so they see the outcome.
  //
  // Crucially: the redirect must NOT fire when the user lands on this
  // page with the scan already terminal (e.g. via the "Timeline"
  // button on the results page) — otherwise it bounces them back to
  // results immediately. Track whether we ever observed a non-
  // terminal status during this page view; only redirect after a
  // genuine transition.
  const sawNonTerminalRef = useRef(false);
  useEffect(() => {
    if (!scanId) return;
    if (status && !TERMINAL_STATUSES.has(status)) {
      sawNonTerminalRef.current = true;
    }
    if (
      sawNonTerminalRef.current &&
      (status === "COMPLETED" ||
        status === "REMEDIATION_COMPLETED" ||
        status === "BLOCKED_PRE_LLM")
    ) {
      const t = setTimeout(
        () =>
          navigate(`/analysis/results/${scanId}`, {
            state: projectInfo
              ? {
                  fromLabel: projectInfo.name,
                  fromPath: `/analysis/projects/${projectInfo.id}`,
                }
              : undefined,
          }),
        1500,
      );
      return () => clearTimeout(t);
    }
  }, [status, scanId, navigate, projectInfo]);

  // Scan-completion notifications are fired by the global ScanWatcher
  // (#89), mounted at the app root — so they land regardless of which
  // page is open. The old page-bound effect was removed.

  // Which gate (if any) the user has just dismissed. Only counts as
  // "submitted" while the live status still matches what was current
  // at click time — so a worker that hops through gates back-to-back
  // (e.g. PENDING_PRESCAN_APPROVAL → PENDING_COST_APPROVAL) doesn't
  // hide the second gate's card under a stale flag.
  const prescanSubmitted =
    submittedForGateId === activeApprovalGate?.gate_id;
  const costSubmitted =
    submittedForGateId === activeApprovalGate?.gate_id;
  const profilingSubmitted =
    submittedForGateId === activeApprovalGate?.gate_id;
  const isPendingApproval =
    status === "PENDING_COST_APPROVAL" &&
    activeApprovalGate?.kind === "cost_approval" &&
    activeApprovalGate.state === "pending" &&
    !costSubmitted;
  const isPendingPrescan =
    status === "PENDING_PRESCAN_APPROVAL" &&
    activeApprovalGate?.kind === "prescan_approval" &&
    activeApprovalGate.state === "pending" &&
    !prescanSubmitted;
  const isPendingProfiling =
    status === "PENDING_PROFILING_APPROVAL" &&
    activeApprovalGate?.kind === "profiling_approval" &&
    activeApprovalGate.state === "pending" &&
    !profilingSubmitted;
  const expectedCost =
    costDetails?.expected_estimated_cost ?? costDetails?.total_estimated_cost;
  const upperBoundCost = costDetails?.upper_bound_estimated_cost;
  const estimateConfidence = costDetails?.estimate_confidence;

  // Scan progress (#85): the rail, the progress bar, and the live
  // badge all derive from ONE pure function over the `scan_events`
  // stream — they can never disagree. `status` is consulted only to
  // classify a terminal scan. The cross-file stage appears only for
  // opted-in scans (#82).
  const scanProgress = useMemo(
    () => deriveScanProgress(events, status, crossFileValidation),
    [events, status, crossFileValidation],
  );
  const progress = scanProgress.progressPct;
  const cancellationComplete = useMemo(
    () => hasCompletedCancellation(events),
    [events],
  );
  const isTerminal =
    status !== null &&
    TERMINAL_STATUSES.has(status) &&
    (status !== "CANCELLED" || cancellationComplete);
  const filteredEvents = useMemo(
    () =>
      events.filter(
        (event) =>
          (activityKindFilter === "all" ||
            event.activity_kind === activityKindFilter) &&
          (activityStageFilter === "all" ||
            event.stage_name === activityStageFilter),
      ),
    [events, activityKindFilter, activityStageFilter],
  );
  const activityStages = useMemo(
    () => Array.from(new Set(events.map((event) => event.stage_name))).sort(),
    [events],
  );
  // Scan-event timestamps bound the elapsed timer — earliest event is
  // the start; once terminal, the latest event freezes it.
  const scanStartedAt = useMemo(() => {
    let earliest: string | null = null;
    for (const e of events) {
      if (e.timestamp && (!earliest || e.timestamp < earliest)) {
        earliest = e.timestamp;
      }
    }
    return earliest;
  }, [events]);
  const scanEndedAt = useMemo(() => {
    if (!isTerminal) return null;
    let latest: string | null = null;
    for (const e of events) {
      if (e.timestamp && (!latest || e.timestamp > latest)) {
        latest = e.timestamp;
      }
    }
    return latest;
  }, [events, isTerminal]);
  const elapsed = useElapsed(scanStartedAt, scanEndedAt);
  // Split the previous catch-all `isFailed` lump into the four kinds
  // of unsuccessful terminals so the UI can stop labeling user stops
  // and safety blocks as "Scan failed":
  //   isError    → only FAILED (real error, red)
  //   isStopped  → CANCELLED / BLOCKED_USER_DECLINE (user pressed Stop)
  //   isBlocked  → BLOCKED_PRE_LLM (auto safety guard tripped)
  //   isExpired  → EXPIRED (auto-aged out, neutral)
  // Use `isUnsuccessful` for the "no-results" UI affordances (disabled
  // View results, dimmed progress, etc.) — that grouping is fine; the
  // failure-only banner is what matters.
  const isError = isErrorStatus(status);
  const isStopped = isStoppedStatus(status);
  const isBlocked = isBlockedStatus(status);
  const isExpired = status === "EXPIRED";
  const isUnsuccessful = isUnsuccessfulTerminal(status);
  const canRunControl =
    status === "FAILED" || (status === "CANCELLED" && hasResumableArtifacts);

  // Reset the optimistic-dismiss tracker the moment the live status
  // moves off the gate the user submitted against. Crucially fires on
  // PENDING_PRESCAN_APPROVAL → PENDING_COST_APPROVAL too — a plain
  // "is status still pending" check would miss that hop and trap the
  // cost card behind a stale prescan submission.
  useEffect(() => {
    if (
      submittedForGateId !== null &&
      submittedForGateId !== activeApprovalGate?.gate_id
    ) {
      setSubmittedForGateId(null);
    }
  }, [activeApprovalGate?.gate_id, submittedForGateId]);

  const gateDecisionPayload = useCallback(
    (kind: ApprovalGate["kind"]) => {
      if (!activeApprovalGate || activeApprovalGate.kind !== kind) {
        throw new Error("This approval gate is no longer active. Refresh and try again.");
      }
      let idempotencyKey = decisionKeysRef.current.get(activeApprovalGate.gate_id);
      if (!idempotencyKey) {
        idempotencyKey = crypto.randomUUID();
        decisionKeysRef.current.set(activeApprovalGate.gate_id, idempotencyKey);
      }
      return {
        idempotencyKey,
        contract: {
          gate_id: activeApprovalGate.gate_id,
          gate_version: activeApprovalGate.version,
          evidence_hash: activeApprovalGate.evidence_hash,
        },
      };
    },
    [activeApprovalGate],
  );

  // Defensive fallback: if the page lands on PENDING_COST_APPROVAL
  // but we never received the SSE `cost_details` payload (e.g. SSE
  // reconnect raced the status flip, or the user landed straight on
  // a scan already past estimating), pull the estimate via the
  // one-shot HTTP path so the approval card isn't stuck on
  // "Approve to run the full analysis." with no numbers.
  useEffect(() => {
    if (!scanId) return;
    if (
      status !== "PENDING_COST_APPROVAL" &&
      status !== "PENDING_PROFILING_APPROVAL"
    )
      return;
    if (costDetails && typeof costDetails.total_estimated_cost === "number")
      return;
    let cancelled = false;
    scanService
      .getScanResult(scanId)
      .then((r) => {
        if (cancelled) return;
        if (r.cost_details) setCostDetails(r.cost_details);
      })
      .catch(() => {
        // Best-effort — SSE will keep retrying anyway.
      });
    return () => {
      cancelled = true;
    };
  }, [scanId, status, costDetails]);

  // Fetch the prescan review whenever the scan enters the prescan-
  // approval gate or one of its terminal states. Re-fetches on every
  // distinct entry so a refresh / reconnect lands the latest data.
  useEffect(() => {
    if (!scanId) return;
    const reviewable =
      status === "PENDING_PRESCAN_APPROVAL" ||
      status === "BLOCKED_PRE_LLM" ||
      status === "BLOCKED_USER_DECLINE";
    if (!reviewable) {
      lastFetchedStatusRef.current = null;
      return;
    }
    if (lastFetchedStatusRef.current === status) return;
    lastFetchedStatusRef.current = status;
    let cancelled = false;
    setPrescanLoading(true);
    scanService
      .getPrescanReview(scanId)
      .then((data) => {
        if (!cancelled) setPrescanReview(data);
      })
      .catch((err: { message?: string }) => {
        if (!cancelled) toast.error(err.message || "Failed to load prescan findings");
      })
      .finally(() => {
        if (!cancelled) setPrescanLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [scanId, status, toast]);

  const handleApprove = useCallback(async () => {
    if (!scanId) return;
    const { contract, idempotencyKey } = gateDecisionPayload("cost_approval");
    setSubmittedForGateId(contract.gate_id);
    setApproving(true);
    try {
      await scanService.approveScan(
        scanId,
        { kind: "cost_approval", approved: true, ...contract },
        idempotencyKey,
      );
      closedGateIdsRef.current.add(contract.gate_id);
      setActiveApprovalGate(null);
      toast.success("Scan approved. Analysis resuming.");
    } catch (err) {
      const e = err as { message?: string };
      toast.error(e.message || "Failed to approve scan");
      // Re-show the panel so the user can retry.
      setSubmittedForGateId(null);
    } finally {
      setApproving(false);
    }
  }, [gateDecisionPayload, scanId, toast]);

  const submitPrescanApproval = useCallback(
    async (override: boolean) => {
      if (!scanId) return;
      const { contract, idempotencyKey } = gateDecisionPayload("prescan_approval");
      setSubmittedForGateId(contract.gate_id);
      setApproving(true);
      try {
        await scanService.approveScan(scanId, {
          kind: "prescan_approval",
          approved: true,
          override_critical_secret: override,
          ...contract,
        }, idempotencyKey);
        closedGateIdsRef.current.add(contract.gate_id);
        setActiveApprovalGate(null);
        toast.success(
          override
            ? "Override recorded. Continuing to LLM analysis."
            : "Continuing to LLM analysis.",
        );
        setOverrideOpen(false);
      } catch (err) {
        const e = err as { message?: string };
        toast.error(e.message || "Failed to continue scan");
        setSubmittedForGateId(null);
      } finally {
        setApproving(false);
      }
    },
    [gateDecisionPayload, scanId, toast],
  );

  const handlePrescanContinue = useCallback(() => {
    if (prescanReview?.has_critical_secret) {
      setOverrideOpen(true);
      return;
    }
    void submitPrescanApproval(false);
  }, [prescanReview, submitPrescanApproval]);

  const handlePrescanStop = useCallback(async () => {
    if (!scanId) return;
    const { contract, idempotencyKey } = gateDecisionPayload("prescan_approval");
    setSubmittedForGateId(contract.gate_id);
    setDeclining(true);
    try {
      await scanService.approveScan(scanId, {
        kind: "prescan_approval",
        approved: false,
        override_critical_secret: false,
        ...contract,
      }, idempotencyKey);
      closedGateIdsRef.current.add(contract.gate_id);
      setActiveApprovalGate(null);
      toast.info("Scan stopped before LLM analysis.");
    } catch (err) {
      const e = err as { message?: string };
      toast.error(e.message || "Failed to stop scan");
      setSubmittedForGateId(null);
    } finally {
      setDeclining(false);
    }
  }, [gateDecisionPayload, scanId, toast]);

  const handleProfilingApprove = useCallback(async () => {
    if (!scanId) return;
    const { contract, idempotencyKey } = gateDecisionPayload("profiling_approval");
    setSubmittedForGateId(contract.gate_id);
    setApproving(true);
    try {
      await scanService.approveScan(scanId, {
        kind: "profiling_approval",
        approved: true,
        ...contract,
      }, idempotencyKey);
      closedGateIdsRef.current.add(contract.gate_id);
      setActiveApprovalGate(null);
      toast.success("Profiling approved. Profiling files…");
    } catch (err) {
      const e = err as { message?: string };
      toast.error(e.message || "Failed to approve profiling");
      setSubmittedForGateId(null);
    } finally {
      setApproving(false);
    }
  }, [gateDecisionPayload, scanId, toast]);

  const handleProfilingDecline = useCallback(async () => {
    if (!scanId) return;
    const { contract, idempotencyKey } = gateDecisionPayload("profiling_approval");
    setSubmittedForGateId(contract.gate_id);
    setDeclining(true);
    try {
      await scanService.approveScan(scanId, {
        kind: "profiling_approval",
        approved: false,
        ...contract,
      }, idempotencyKey);
      closedGateIdsRef.current.add(contract.gate_id);
      setActiveApprovalGate(null);
      toast.info("Scan stopped before profiling.");
    } catch (err) {
      const e = err as { message?: string };
      toast.error(e.message || "Failed to stop scan");
      setSubmittedForGateId(null);
    } finally {
      setDeclining(false);
    }
  }, [gateDecisionPayload, scanId, toast]);

  const handleCancel = useCallback(async () => {
    if (!scanId) return;
    setCancelling(true);
    try {
      await scanService.cancelScan(scanId);
      // The durable status flips immediately while activity progresses through
      // requested → observed → completed acknowledgement phases.
      setStatus("CANCELLED");
      toast.info("Cancellation requested. Stopping active work…");
      queryClient.invalidateQueries({
        queryKey: ["project-scans", projectInfo?.id],
      });
      queryClient.invalidateQueries({ queryKey: ["projects"] });
    } catch (err) {
      const e = err as { message?: string };
      toast.error(e.message || "Failed to cancel scan");
    } finally {
      setCancelling(false);
      setStopConfirmOpen(false);
    }
  }, [scanId, projectInfo?.id, queryClient, toast]);

  const handleRunControl = useCallback(async () => {
    if (!scanId || !runControlMode) return;
    setRunControlSubmitting(true);
    try {
      await scanService.runControlScan(scanId, runControlMode);
      toast.info(
        runControlMode === "resume"
          ? "Scan resume queued. Completed durable work will be reused where possible."
          : "Scan restart queued. Partial task artifacts and derived findings were discarded.",
      );
      setStatus("QUEUED");
      setRunControlMode(null);
      queryClient.invalidateQueries({ queryKey: ["project-scans", projectInfo?.id] });
      queryClient.invalidateQueries({ queryKey: ["projects"] });
    } catch (err) {
      const e = err as { message?: string };
      toast.error(e.message || `Failed to ${runControlMode} scan`);
    } finally {
      setRunControlSubmitting(false);
    }
  }, [scanId, runControlMode, toast, queryClient, projectInfo?.id]);

  const handleDelete = useCallback(async () => {
    if (!scanId) return;
    setDeleting(true);
    try {
      await scanService.deleteScan(scanId);
      toast.info("Scan deleted.");
      queryClient.invalidateQueries({
        queryKey: ["project-scans", projectInfo?.id],
      });
      queryClient.invalidateQueries({ queryKey: ["projects"] });
      if (projectInfo) {
        navigate(`/analysis/projects/${projectInfo.id}`, {
          state: { projectName: projectInfo.name },
        });
      } else {
        navigate("/analysis/results");
      }
    } catch (err) {
      const e = err as { message?: string };
      toast.error(e.message || "Failed to delete scan");
    } finally {
      setDeleting(false);
      setDeleteConfirmOpen(false);
    }
  }, [scanId, projectInfo, navigate, queryClient, toast]);

  return (
    <div className="fade-in" style={{ display: "grid", gap: 16 }}>
      {/* Header — full width above the 2-col body so the Status card on
          the right aligns with the Overall progress card on the left. */}
      <PageHeader
        crumbs={(() => {
          const fromLabel = (location.state as Record<string, unknown>)
            ?.fromLabel as string | undefined;
          const fromPath = (location.state as Record<string, unknown>)
            ?.fromPath as string | undefined;
          if (fromLabel) {
            return [
              {
                label: fromLabel,
                to: fromPath,
                onClick: !fromPath ? () => navigate(-1) : undefined,
              },
              { label: `Scan ${scanId?.slice(0, 8) ?? "…"}` },
            ];
          }
          return [
            { label: "Projects", to: "/analysis/results" },
            ...(projectInfo
              ? [
                  {
                    label: projectInfo.name,
                    to: `/analysis/projects/${projectInfo.id}`,
                  },
                ]
              : []),
            { label: `Scan ${scanId?.slice(0, 8) ?? "…"}` },
          ];
        })()}
        chip={
          // Critical (red) chip ONLY for genuine errors. User stops,
          // safety blocks, and EXPIRED render as a neutral chip — they
          // are not failures.
          <div
            className={`chip ${
              isError
                ? "chip-critical"
                : isBlocked
                  ? "chip-warn"
                  : status === "COMPLETED" ||
                      status === "REMEDIATION_COMPLETED"
                    ? "chip-success"
                    : "chip-info"
            }`}
          >
            {/* Pulse dot only while genuinely running. Suppress while
                status is still loading (null) — a pulsing chip there
                would imply progress that hasn't been observed yet. */}
            {status !== null && !isTerminal && (
              <span
                className="pulse-dot dot"
                style={{ background: "currentColor" }}
              />
            )}
            {isError ? <Icon.Alert size={11} /> : null}
            Scan{" "}
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>
              {scanId?.slice(0, 8)}
            </span>{" "}
            · {isTerminal ? displayStatus(status) : scanProgress.badge}
          </div>
        }
        title={
          !status
            ? "Loading scan…"
            : isPendingPrescan
              ? "Pre-LLM scan complete — review before continuing"
              : isPendingApproval
                ? "Ready to run — approve the estimated cost"
                : status === "COMPLETED" || status === "REMEDIATION_COMPLETED"
                  ? "Scan complete"
                  : status === "BLOCKED_PRE_LLM"
                    ? "Scan stopped — critical secret detected"
                    : status === "BLOCKED_USER_DECLINE"
                      ? "Scan stopped at your request"
                      : status === "CANCELLED"
                        ? cancellationComplete
                          ? "Scan stopped at your request"
                          : "Stopping scan…"
                        : isExpired
                          ? "Scan expired"
                          : isError
                            ? "Scan did not complete"
                            : "Analyzing your code"
        }
        subtitle="You can leave this page — the scan continues in the background and results appear on the Projects list when done."
      />

      {/* Body — 2-col grid, content + sidebar. */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 360px",
          gap: 20,
          alignItems: "start",
        }}
      >
        <div style={{ display: "grid", gap: 16 }}>
          {/* progress + stages */}
        <div className="surface" style={{ padding: 24 }}>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "baseline",
              marginBottom: 12,
            }}
          >
            <div style={{ fontSize: 13, color: "var(--fg-muted)" }}>
              Overall progress
            </div>
            <div
              style={{ display: "flex", alignItems: "baseline", gap: 12 }}
            >
              {elapsed && (
                <span
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 4,
                    fontSize: 12.5,
                    color: isTerminal ? "var(--fg-muted)" : "var(--primary)",
                    fontWeight: 500,
                    fontVariantNumeric: "tabular-nums",
                  }}
                  title={isTerminal ? "Scan duration" : "Elapsed time"}
                >
                  <Icon.Clock size={12} /> {elapsed}
                </span>
              )}
              <div
                style={{
                  fontSize: 13,
                  fontVariantNumeric: "tabular-nums",
                  fontWeight: 500,
                  color: "var(--fg)",
                }}
              >
                {progress}%
              </div>
            </div>
          </div>
          <div className="sccap-progress">
            <span
              style={{
                width: `${progress}%`,
                // Red bar only for genuine errors; user stops / blocks
                // / expired keep the primary color (the bar itself
                // tops out at 100%, just neutrally completed).
                background: isError ? "var(--critical)" : "var(--primary)",
              }}
            />
          </div>

          {/* Horizontal stage timeline — same design as the compact
              pipeline on the dashboard / projects scan cards. */}
          <div style={{ display: "flex", marginTop: 22, overflowX: "auto" }}>
            {scanProgress.stages.map((s, i) => {
              const state = s.state;
              const last = i === scanProgress.stages.length - 1;
              const prevDone = i > 0 && scanProgress.stages[i - 1].state === "done";
              const circleBg =
                state === "done"
                  ? "var(--success)"
                  : state === "running"
                    ? "var(--primary)"
                    : state === "paused"
                      ? "var(--medium)"
                      : "var(--bg-elev)";
              const labelColor =
                state === "running"
                  ? "var(--primary)"
                  : state === "paused"
                    ? "var(--medium)"
                    : state === "done"
                      ? "var(--fg-muted)"
                      : "var(--fg-subtle)";
              return (
                <div
                  key={s.key}
                  title={`${s.label} — ${state}${state === "paused" ? " · awaiting your approval" : ""}`}
                  style={{
                    flex: 1,
                    minWidth: 0,
                    display: "flex",
                    flexDirection: "column",
                    alignItems: "center",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      width: "100%",
                    }}
                  >
                    <span
                      style={{
                        flex: 1,
                        height: 2,
                        background:
                          i === 0
                            ? "transparent"
                            : prevDone
                              ? "var(--success)"
                              : "var(--border)",
                      }}
                    />
                    <span
                      className={
                        state === "running" ? "pulse-ring" : undefined
                      }
                      style={{
                        width: 30,
                        height: 30,
                        borderRadius: "50%",
                        flexShrink: 0,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        background: circleBg,
                        color:
                          state === "pending"
                            ? "var(--fg-subtle)"
                            : "#fff",
                        border:
                          state === "pending"
                            ? "1.5px solid var(--border)"
                            : "1.5px solid transparent",
                      }}
                    >
                      {state === "done" ? (
                        <Icon.Check size={12} />
                      ) : state === "running" ? (
                        <div
                          className="sccap-spin"
                          style={{
                            width: 10,
                            height: 10,
                            border: "2px solid currentColor",
                            borderTopColor: "transparent",
                            borderRadius: "50%",
                          }}
                        />
                      ) : state === "paused" ? (
                        <Icon.Pause size={12} />
                      ) : (
                        <StageIcon name={s.icon} size={14} />
                      )}
                    </span>
                    <span
                      style={{
                        flex: 1,
                        height: 2,
                        background: last
                          ? "transparent"
                          : state === "done"
                            ? "var(--success)"
                            : "var(--border)",
                      }}
                    />
                  </div>
                  <span
                    style={{
                      marginTop: 6,
                      fontSize: 10.5,
                      lineHeight: 1.3,
                      textAlign: "center",
                      color: labelColor,
                      fontWeight:
                        state === "running" || state === "paused" ? 600 : 400,
                    }}
                  >
                    {s.label}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        {/* prescan-approval gate (ADR-009 / G6) — render the review
            card while the scan is paused at PENDING_PRESCAN_APPROVAL,
            and also after a terminal decline so the operator can audit
            the findings that drove the block. */}
        {(isPendingPrescan ||
          status === "BLOCKED_PRE_LLM" ||
          status === "BLOCKED_USER_DECLINE") && (
          <>
            {prescanLoading && !prescanReview && (
              <div
                className="sccap-card"
                style={{ color: "var(--fg-muted)", fontSize: 13 }}
              >
                Loading prescan findings…
              </div>
            )}
            {prescanReview && (
              <>
                {isPendingPrescan && activeApprovalGate && (
                  <div style={{ color: "var(--fg-subtle)", fontSize: 11 }}>
                    Step 1 of 3 · {activeApprovalGate.display_name} · Evidence{" "}
                    {activeApprovalGate.evidence_hash}
                  </div>
                )}
                <PrescanReviewCard
                  findings={prescanReview.findings}
                  hasCriticalSecret={prescanReview.has_critical_secret}
                  approving={approving}
                  declining={declining}
                  onContinue={handlePrescanContinue}
                  onStop={handlePrescanStop}
                  readOnly={!isPendingPrescan}
                />
              </>
            )}
          </>
        )}

        <CriticalSecretOverrideModal
          open={overrideOpen}
          submitting={approving}
          onCancel={() => setOverrideOpen(false)}
          onConfirm={() => void submitPrescanApproval(true)}
        />

        {/* profiling-cost gate (#71) — approve before per-file profiling */}
        {isPendingProfiling && (
          <div
            className="sccap-card"
            style={{
              background: "var(--primary-weak)",
              borderColor: "transparent",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 12,
            }}
          >
            <div>
              <div
                style={{
                  fontWeight: 600,
                  color: "var(--primary-strong)",
                  marginBottom: 4,
                }}
              >
                {activeApprovalGate?.display_name ?? "Approve file profiling cost"}
                {typeof expectedCost === "number" && (
                  <span
                    style={{
                      marginLeft: 10,
                      color: "var(--fg)",
                      fontSize: 16,
                      fontVariantNumeric: "tabular-nums",
                    }}
                  >
                    · expected ${expectedCost.toFixed(4)}
                    {typeof upperBoundCost === "number"
                      ? ` · upper $${upperBoundCost.toFixed(4)}`
                      : ""}
                  </span>
                )}
              </div>
              <div style={{ color: "var(--fg)", fontSize: 13 }}>
                Step 2 of 3 · {activeApprovalGate?.purpose ??
                  "Approve profiling before the full analysis estimate is prepared."}
              </div>
              {activeApprovalGate && (
                <div style={{ marginTop: 4, color: "var(--fg-subtle)", fontSize: 11 }}>
                  Evidence {activeApprovalGate.evidence_hash}
                </div>
              )}
              {estimateConfidence && (
                <div style={{ marginTop: 4, color: "var(--fg-subtle)", fontSize: 12 }}>
                  {estimateConfidence.toUpperCase()} confidence
                  {typeof costDetails?.estimate_sample_count === "number"
                    ? ` · ${costDetails.estimate_sample_count} historical observations`
                    : ""}
                </div>
              )}
              {!!costDetails?.estimate_assumptions?.length && (
                <details style={{ marginTop: 6, fontSize: 12, color: "var(--fg-subtle)" }}>
                  <summary>Estimate assumptions</summary>
                  <ul style={{ margin: "6px 0 0", paddingLeft: 18 }}>
                    {costDetails.estimate_assumptions.map((assumption) => (
                      <li key={assumption}>{assumption}</li>
                    ))}
                  </ul>
                </details>
              )}
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <button
                className="sccap-btn"
                onClick={handleProfilingDecline}
                disabled={declining || approving}
              >
                {declining ? "Stopping…" : "Stop"}
              </button>
              <button
                className="sccap-btn sccap-btn-primary"
                onClick={handleProfilingApprove}
                disabled={approving || declining}
              >
                <Icon.Check size={12} />{" "}
                {approving ? "Approving…" : "Approve & profile"}
              </button>
            </div>
          </div>
        )}

        {/* pending-approval banner + actions */}
        {isPendingApproval && (
          <div
            className="sccap-card"
            style={{
              background: "var(--primary-weak)",
              borderColor: "transparent",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 12,
            }}
          >
            <div>
              <div
                style={{
                  fontWeight: 600,
                  color: "var(--primary-strong)",
                  marginBottom: 4,
                }}
              >
                {activeApprovalGate?.display_name ??
                  "Approve full security analysis cost"}
                {typeof expectedCost === "number" && (
                  <span
                    style={{
                      marginLeft: 10,
                      color: "var(--fg)",
                      fontSize: 16,
                      fontVariantNumeric: "tabular-nums",
                    }}
                  >
                    · expected ${expectedCost.toFixed(4)}
                    {typeof upperBoundCost === "number"
                      ? ` · upper $${upperBoundCost.toFixed(4)}`
                      : ""}
                  </span>
                )}
              </div>
              <div style={{ color: "var(--fg)", fontSize: 13 }}>
                Step 3 of 3 · {activeApprovalGate?.purpose ??
                  "Approve the full security analysis estimate."}{" "}
                {typeof costDetails?.total_input_tokens === "number" &&
                typeof costDetails?.predicted_output_tokens === "number"
                  ? `~${costDetails.total_input_tokens.toLocaleString()} input tokens + ~${costDetails.predicted_output_tokens.toLocaleString()} predicted output tokens. Approve to run the full analysis.`
                  : "Approve to run the full analysis."}
              </div>
              {activeApprovalGate && (
                <div style={{ marginTop: 4, color: "var(--fg-subtle)", fontSize: 11 }}>
                  Evidence {activeApprovalGate.evidence_hash}
                </div>
              )}
              {estimateConfidence && (
                <div style={{ marginTop: 4, color: "var(--fg-subtle)", fontSize: 12 }}>
                  {estimateConfidence.toUpperCase()} confidence
                  {typeof costDetails?.planned_request_count === "number"
                    ? ` · ${costDetails.planned_request_count} planned model requests`
                    : ""}
                  {typeof costDetails?.estimate_sample_count === "number"
                    ? ` · ${costDetails.estimate_sample_count} historical observations`
                    : ""}
                </div>
              )}
              {!!costDetails?.estimate_assumptions?.length && (
                <details style={{ marginTop: 6, fontSize: 12, color: "var(--fg-subtle)" }}>
                  <summary>Estimate assumptions</summary>
                  <ul style={{ margin: "6px 0 0", paddingLeft: 18 }}>
                    {costDetails.estimate_assumptions.map((assumption) => (
                      <li key={assumption}>{assumption}</li>
                    ))}
                  </ul>
                </details>
              )}
              {/* Dual-LLM per-model breakdown (#93) — shown only when a
                  second reasoning LLM was configured. */}
              {costDetails?.slots?.reasoning_secondary && (
                <div
                  style={{
                    marginTop: 4,
                    fontSize: 12,
                    color: "var(--fg-subtle)",
                    fontVariantNumeric: "tabular-nums",
                  }}
                >
                  Primary LLM $
                  {(
                    costDetails.slots.reasoning?.total_estimated_cost ?? 0
                  ).toFixed(4)}
                  {" · "}
                  Second LLM $
                  {(
                    costDetails.slots.reasoning_secondary
                      ?.total_estimated_cost ?? 0
                  ).toFixed(4)}
                </div>
              )}
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <button
                className="sccap-btn"
                onClick={handleCancel}
                disabled={cancelling}
              >
                {cancelling ? "Cancelling…" : "Cancel"}
              </button>
              <button
                className="sccap-btn sccap-btn-primary"
                onClick={handleApprove}
                disabled={approving}
              >
                <Icon.Check size={12} />{" "}
                {approving ? "Approving…" : "Approve & run"}
              </button>
            </div>
          </div>
        )}

        {/* Outcome banner. Three flavors so we never label a user
            stop or a safety-guard block as "Scan failed":
              - Error  (FAILED): red, "check logs / retry" copy
              - Stopped (CANCELLED, BLOCKED_USER_DECLINE): neutral,
                "you stopped this — submit again when ready" copy
              - Blocked (BLOCKED_PRE_LLM): amber/warn, "safety guard
                tripped, review the prescan card" copy
              - Expired: neutral, "auto-aged out" copy
            EXPIRED isn't currently emitted by the worker but the
            banner is here for completeness. */}
        {isError && (
          <div
            className="sccap-card"
            style={{
              background: "var(--critical-weak)",
              borderColor: "transparent",
            }}
          >
            <div
              style={{ fontWeight: 600, color: "var(--critical)", marginBottom: 4 }}
            >
              Scan failed
            </div>
            <div style={{ color: "var(--fg)", fontSize: 13, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
              {errorMessage || "Check the worker logs for details, or try resubmitting the same source. The scan record is preserved under the Projects list."}
            </div>
          </div>
        )}
        {isStopped && (
          <div
            className="sccap-card"
            style={{
              background: "var(--bg-soft)",
              borderColor: "transparent",
            }}
          >
            <div style={{ fontWeight: 600, color: "var(--fg)", marginBottom: 4 }}>
              {status === "BLOCKED_USER_DECLINE"
                ? "Scan stopped before LLM analysis"
                : "Scan stopped"}
            </div>
            <div style={{ color: "var(--fg-muted)", fontSize: 13 }}>
              You stopped this scan — no LLM credit was spent. Submit the
              project again whenever you're ready to continue.
            </div>
          </div>
        )}
        {isBlocked && (
          <div
            className="sccap-card"
            style={{
              background: "var(--high-weak)",
              borderColor: "transparent",
            }}
          >
            <div
              style={{
                fontWeight: 600,
                color: "var(--high)",
                marginBottom: 4,
              }}
            >
              Scan blocked — critical secret detected
            </div>
            <div style={{ color: "var(--fg)", fontSize: 13 }}>
              The prescan found a high-confidence secret in your source. The
              LLM phase was skipped to avoid sending the credential to a
              provider. Rotate the secret, remove it from the codebase, and
              resubmit.
            </div>
          </div>
        )}
        {isExpired && (
          <div
            className="sccap-card"
            style={{
              background: "var(--bg-soft)",
              borderColor: "transparent",
            }}
          >
            <div style={{ fontWeight: 600, color: "var(--fg)", marginBottom: 4 }}>
              Scan expired
            </div>
            <div style={{ color: "var(--fg-muted)", fontSize: 13 }}>
              This scan sat at an approval gate too long and was auto-aged
              out. Resubmit the project to start fresh.
            </div>
          </div>
        )}

        {/* §3.10b — per-file progress, only while there's something to show. */}
        {Object.keys(fileProgress).length > 0 && (
          <div className="surface" style={{ padding: 18 }}>
            <SectionHead
              title={
                <>
                  <Icon.File size={14} /> Files analyzed{isTerminal ? "" : " (live)"}
                </>
              }
            />
            <div
              style={{
                fontSize: 12,
                color: "var(--fg-muted)",
                marginBottom: 8,
              }}
            >
              {Object.keys(fileProgress).length} file
              {Object.keys(fileProgress).length === 1 ? "" : "s"} processed
              {(() => {
                const totalFindings = Object.values(fileProgress).reduce(
                  (s, f) => s + f.findings_count,
                  0,
                );
                const totalFixes = Object.values(fileProgress).reduce(
                  (s, f) => s + f.fixes_count,
                  0,
                );
                return ` — ${totalFindings} finding${totalFindings === 1 ? "" : "s"}, ${totalFixes} fix${totalFixes === 1 ? "" : "es"}`;
              })()}
            </div>
            <div
              style={{
                maxHeight: 200,
                overflow: "auto",
                display: "grid",
                gap: 4,
                fontSize: 12,
                fontFamily: "var(--font-mono)",
              }}
            >
              {Object.values(fileProgress)
                .sort((a, b) =>
                  (b.timestamp ?? "").localeCompare(a.timestamp ?? ""),
                )
                .map((f) => (
                  <div
                    key={f.file_path}
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      gap: 12,
                      padding: "4px 0",
                      borderBottom: "1px solid var(--border)",
                    }}
                  >
                    <span
                      style={{
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                        color: "var(--fg)",
                      }}
                      title={f.file_path}
                    >
                      {f.file_path}
                    </span>
                    <span
                      style={{
                        color:
                          f.findings_count > 0
                            ? "var(--high)"
                            : "var(--fg-muted)",
                        flexShrink: 0,
                      }}
                    >
                      {f.progress_category === "skipped-low-value" ? "skipped" : `${f.findings_count} finding${f.findings_count === 1 ? "" : "s"}`}
                      {f.fixes_count > 0 && ` · ${f.fixes_count} fix${f.fixes_count === 1 ? "" : "es"}`}
                      {` · ${f.llm_calls} LLM`}
                      {f.reused_tasks > 0 && ` · ${f.reused_tasks} reused`}
                      {f.failed_tasks > 0 && ` · ${f.failed_tasks} failed`}
                      {f.classification && ` · ${f.classification}`}
                      {f.elapsed_ms > 0 && ` · ${Math.round(f.elapsed_ms / 1000)}s`}
                    </span>
                  </div>
                ))}
            </div>
          </div>
        )}

        {/* live event log */}
        <div className="surface" style={{ padding: 18 }}>
          <SectionHead
            title={
              <>
                <Icon.Terminal size={14} /> {isTerminal ? "Activity log" : "Live event log"}
              </>
            }
          />
          <div
            aria-label="Activity filters"
            style={{ display: "flex", gap: 8, marginBottom: 10, flexWrap: "wrap" }}
          >
            <label style={{ fontSize: 11, color: "var(--fg-muted)" }}>
              Type{" "}
              <select
                aria-label="Filter activity by type"
                value={activityKindFilter}
                onChange={(event) => setActivityKindFilter(event.target.value)}
                className="sccap-input"
                style={{ width: "auto", padding: "4px 8px", fontSize: 11 }}
              >
                <option value="all">All types</option>
                <option value="workflow">Workflow</option>
                <option value="scanner">Scanners</option>
                <option value="llm_call">LLM calls</option>
                <option value="retry">Retries</option>
                <option value="warning">Warnings</option>
                <option value="degradation">Degraded</option>
                <option value="decision">Decisions</option>
                <option value="cancellation">Cancellation</option>
                <option value="terminal">Terminal</option>
              </select>
            </label>
            <label style={{ fontSize: 11, color: "var(--fg-muted)" }}>
              Stage{" "}
              <select
                aria-label="Filter activity by stage"
                value={activityStageFilter}
                onChange={(event) => setActivityStageFilter(event.target.value)}
                className="sccap-input"
                style={{ width: "auto", padding: "4px 8px", fontSize: 11 }}
              >
                <option value="all">All stages</option>
                {activityStages.map((stageName) => (
                  <option key={stageName} value={stageName}>
                    {eventDisplayName(stageName)}
                  </option>
                ))}
              </select>
            </label>
          </div>
          {streamError && (
            <div
              style={{
                fontSize: 12,
                color: "var(--critical)",
                marginBottom: 8,
              }}
            >
              {streamError}
            </div>
          )}
          <pre
            className="sccap-code"
            style={{
              maxHeight: 240,
              overflow: "auto",
              fontSize: 11.5,
              margin: 0,
            }}
          >
            {events.length === 0
              ? "Waiting for events…\n"
              : filteredEvents.length === 0
                ? "No activity matches these filters.\n"
                : filteredEvents
                  .map(
                    (e) =>
                      `[${e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : "—"}] ${e.activity_kind.replace(/_/g, " ")} · ${eventDisplayName(e.stage_name)} · ${e.status}${formatActivityDetails(e.details)}`,
                  )
                  .join("\n")}
          </pre>
        </div>
      </div>

      <aside style={{ display: "grid", gap: 12, alignContent: "start" }}>
        <div className="sccap-card">
          <div style={{ fontSize: 12, color: "var(--fg-muted)" }}>Status</div>
          <div
            style={{
              fontSize: 18,
              fontWeight: 600,
              letterSpacing: "-0.02em",
              marginTop: 4,
              // Red ONLY for genuine errors. Stops/blocks/expired stay
              // neutral; completed stays green.
              color: isError
                ? "var(--critical)"
                : status === "COMPLETED" || status === "REMEDIATION_COMPLETED"
                  ? "var(--success)"
                  : "var(--fg)",
            }}
          >
            {isTerminal ? displayStatus(status) : scanProgress.badge}
          </div>
          <div
            style={{ marginTop: 10, fontSize: 12, color: "var(--fg-muted)" }}
          >
            {
              scanProgress.stages.filter((s) => s.state === "done").length
            }{" "}
            of {scanProgress.stages.length} stages complete
          </div>
        </div>

        <button
          className="sccap-btn sccap-btn-primary"
          onClick={() => navigate(`/analysis/results/${scanId}`)}
          // Disable "View results" when there's nothing to view: still
          // running, OR any unsuccessful terminal (failed / stopped /
          // blocked / expired all leave summary_report empty).
          disabled={!isTerminal || isUnsuccessful}
          style={{
            opacity: !isTerminal || isUnsuccessful ? 0.6 : 1,
          }}
        >
          {!isTerminal
            ? "Scanning…"
            : isUnsuccessful
              ? "No results"
              : (
                  <>
                    View results <Icon.ArrowR size={12} />
                  </>
                )}
        </button>
        {!isTerminal && (
          <button
            className="sccap-btn"
            onClick={() => setStopConfirmOpen(true)}
            disabled={cancelling}
            style={{ color: "var(--critical)" }}
          >
            <Icon.X size={12} /> {cancelling ? "Stopping…" : "Stop scan"}
          </button>
        )}
        {canRunControl && (
          <>
            <button
              className="sccap-btn sccap-btn-primary"
              onClick={() => setRunControlMode("resume")}
              disabled={runControlSubmitting}
            >
              Resume scan
            </button>
            <button
              className="sccap-btn"
              onClick={() => setRunControlMode("restart")}
              disabled={runControlSubmitting}
            >
              Restart from original submission
            </button>
          </>
        )}
        {isSuperuser && (
          <button
            className="sccap-btn"
            onClick={() => setDeleteConfirmOpen(true)}
            disabled={deleting}
            style={{ color: "var(--critical)" }}
          >
            <Icon.Alert size={12} /> {deleting ? "Deleting…" : "Delete scan"}
          </button>
        )}
        <button
          className="sccap-btn"
          onClick={() => navigate("/account/dashboard")}
        >
          Back to dashboard
        </button>
      </aside>
      </div>

      <Modal
        open={stopConfirmOpen}
        onClose={() => (cancelling ? undefined : setStopConfirmOpen(false))}
        title="Stop this scan?"
        footer={
          <>
            <button
              className="sccap-btn"
              onClick={() => setStopConfirmOpen(false)}
              disabled={cancelling}
            >
              Keep running
            </button>
            <button
              className="sccap-btn sccap-btn-primary"
              onClick={handleCancel}
              disabled={cancelling}
              style={{ background: "var(--critical)" }}
            >
              {cancelling ? "Stopping…" : "Stop scan"}
            </button>
          </>
        }
      >
        <div style={{ color: "var(--fg)", fontSize: 13.5, lineHeight: 1.55 }}>
          The scan will transition to <b>CANCELLED</b>. Any partial progress is
          discarded — no findings or fixes are produced. You can submit the
          project again later.
        </div>
      </Modal>

      <Modal
        open={runControlMode !== null}
        onClose={() =>
          runControlSubmitting ? undefined : setRunControlMode(null)
        }
        title={
          runControlMode === "resume"
            ? "Resume this scan?"
            : "Restart this scan?"
        }
        footer={
          <>
            <button
              className="sccap-btn"
              onClick={() => setRunControlMode(null)}
              disabled={runControlSubmitting}
            >
              Cancel
            </button>
            <button
              className="sccap-btn sccap-btn-primary"
              onClick={handleRunControl}
              disabled={runControlSubmitting}
            >
              {runControlSubmitting
                ? "Queueing…"
                : runControlMode === "resume"
                  ? "Resume scan"
                  : "Restart scan"}
            </button>
          </>
        }
      >
        <div style={{ color: "var(--fg)", fontSize: 13.5, lineHeight: 1.55 }}>
          {runControlMode === "resume" ? (
            <>
              Resume reuses completed durable work where possible and continues
              from the original submitted snapshot and scan configuration.
            </>
          ) : (
            <>
              Restart discards partial task artifacts and derived final findings,
              then reruns the original submitted snapshot and scan configuration
              under the same scan id. Audit events and LLM interaction logs are
              preserved.
            </>
          )}
        </div>
      </Modal>

      <Modal
        open={deleteConfirmOpen}
        onClose={() => (deleting ? undefined : setDeleteConfirmOpen(false))}
        title="Delete this scan permanently?"
        footer={
          <>
            <button
              className="sccap-btn"
              onClick={() => setDeleteConfirmOpen(false)}
              disabled={deleting}
            >
              Cancel
            </button>
            <button
              className="sccap-btn sccap-btn-primary"
              onClick={handleDelete}
              disabled={deleting}
              style={{ background: "var(--critical)" }}
            >
              {deleting ? "Deleting…" : "Delete scan"}
            </button>
          </>
        }
      >
        <div style={{ color: "var(--fg)", fontSize: 13.5, lineHeight: 1.55 }}>
          This removes the scan, its findings, and event log from the
          database. The action cannot be undone.{" "}
          {!isTerminal && (
            <b style={{ color: "var(--critical)" }}>
              The worker may still be processing this scan in the background —
              consider stopping it first.
            </b>
          )}
        </div>
      </Modal>
    </div>
  );
};

export default ScanRunningPage;
