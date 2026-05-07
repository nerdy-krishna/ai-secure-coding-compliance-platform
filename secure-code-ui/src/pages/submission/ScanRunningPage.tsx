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
import { useNotificationPermission } from "../../shared/hooks/useNotificationPermission";
import { pushNotification } from "../../shared/hooks/useNotifications";
import {
  displayStatus,
  isBlockedStatus,
  isErrorStatus,
  isStoppedStatus,
  isUnsuccessfulTerminal,
} from "../../shared/lib/scanStatus";
import type { PrescanReviewResponse } from "../../shared/types/api";
import { Icon } from "../../shared/ui/Icon";
import { SectionHead } from "../../shared/ui/DashboardPrimitives";
import { Modal } from "../../shared/ui/Modal";
import { PageHeader } from "../../shared/ui/PageHeader";
import { useToast } from "../../shared/ui/Toast";

interface ScanEventMsg {
  scan_id: string;
  event_id: number;
  stage_name: string;
  status: string; // "COMPLETED" / "STARTED" / "FAILED" for the event itself
  timestamp: string | null;
  // §3.10b — per-event payload. Carries `{file_path, findings_count,
  // fixes_count}` for `FILE_ANALYZED` events; null for legacy stage
  // events (QUEUED / ANALYZING_CONTEXT / etc.).
  details?: {
    file_path?: string;
    findings_count?: number;
    fixes_count?: number;
  } | null;
}

// One row in the per-file analysis log surfaced by §3.10b. Keyed by
// file_path so the same file showing up twice (e.g. multi-chunk
// analysis) collapses to a single row with the latest counts.
interface FileProgressItem {
  file_path: string;
  findings_count: number;
  fixes_count: number;
  timestamp: string | null;
}

interface ScanStateMsg {
  scan_id: string;
  status: string;
  // Carried only on the cost-approval flip — see SSE handler in
  // routers/projects.py. Lets the frontend surface the estimate the
  // moment status flips to PENDING_COST_APPROVAL without a manual
  // page refresh.
  cost_details?: {
    total_estimated_cost?: number;
    total_input_tokens?: number;
    predicted_output_tokens?: number;
  } | null;
}

// Known pipeline stages, in order. The backend emits stage_name values
// matching these keys; unknown stage names are appended live.
interface Stage {
  key: string;
  label: string;
  icon: React.ReactNode;
}

// Pipeline stages, in display order. `PRESCAN_REVIEW` and `COST_REVIEW`
// are *virtual* stages — the worker doesn't emit a matching stage_name,
// they're derived from the live status (`PENDING_PRESCAN_APPROVAL` /
// `PENDING_COST_APPROVAL`) plus the events that mark the gate as
// crossed. They exist because the prior list left "Pre-LLM scan
// review" out entirely (so during the prescan gate we'd misleadingly
// show "Analyzing context" as the active step) and treated the stage
// right after `ESTIMATING_COST` as active during the cost-approval
// gate (so "Running security agents" spun even though the scan was
// paused waiting for the user). Dropping the literal `QUEUED_FOR_SCAN`
// row — it fires twice (after each gate) and isn't user-meaningful.
const KNOWN_STAGES: Stage[] = [
  { key: "QUEUED", label: "Queued", icon: <Icon.Clock size={14} /> },
  { key: "ANALYZING_CONTEXT", label: "Analyzing context", icon: <Icon.Folder size={14} /> },
  { key: "PRESCAN_REVIEW", label: "Pre-LLM scan review", icon: <Icon.Shield size={14} /> },
  { key: "ESTIMATING_COST", label: "Estimating cost", icon: <Icon.Dollar size={14} /> },
  { key: "COST_REVIEW", label: "Cost review", icon: <Icon.Dollar size={14} /> },
  { key: "RUNNING_AGENTS", label: "Running security agents", icon: <Icon.Cpu size={14} /> },
  { key: "CORRELATING", label: "Correlating findings", icon: <Icon.Layers size={14} /> },
  { key: "GENERATING_REPORTS", label: "Generating reports", icon: <Icon.File size={14} /> },
];

// Stage events whose presence in `seenStages` proves the corresponding
// gate has been crossed (used to mark the virtual gate stages "done"
// regardless of which decline/override path the user took).
const POST_PRESCAN_EVENTS = [
  "ESTIMATING_COST",
  "PRESCAN_OVERRIDE_CRITICAL_SECRET",
  "PRESCAN_USER_DECLINED",
  "PRESCAN_AUTO_DECLINED",
  "QUEUED_FOR_SCAN",
];
const POST_COST_EVENTS = [
  "RUNNING_AGENTS",
  "FILE_ANALYZED",
  "CORRELATING",
  "PATCH_VERIFICATION",
  "GENERATING_REPORTS",
];

type StageState = "done" | "active" | "paused" | "pending";

function computeStageStates(
  stages: Stage[],
  seenStages: Set<string>,
  isTerminal: boolean,
  isPendingPrescan: boolean,
  isPendingApproval: boolean,
  prescanSubmitted: boolean,
  costSubmitted: boolean,
): StageState[] {
  const isPastPrescan = POST_PRESCAN_EVENTS.some((k) => seenStages.has(k));
  const isPastCost = POST_COST_EVENTS.some((k) => seenStages.has(k));

  // First pass: assign done/paused/pending without considering "active"
  // — that's a one-shot promotion in pass 2. The `*Submitted` flags
  // collapse the click → SSE round-trip: the moment the user dismisses
  // a gate, mark it done (optimistic) so the next real stage takes
  // over with its spinner instead of the gate flickering through
  // pending → active before the post-gate event arrives.
  const states: StageState[] = stages.map((s) => {
    if (s.key === "PRESCAN_REVIEW") {
      if (isPendingPrescan) return "paused";
      if (prescanSubmitted || isPastPrescan) return "done";
      return "pending";
    }
    if (s.key === "COST_REVIEW") {
      if (isPendingApproval) return "paused";
      if (costSubmitted || isPastCost) return "done";
      return "pending";
    }
    return seenStages.has(s.key) ? "done" : "pending";
  });

  // Second pass: promote the first eligible "pending" to "active".
  // Eligibility: every prior stage must already be "done" — so a
  // "paused" gate (any earlier stage) blocks promotion, which is
  // exactly the behaviour we want (no spinner anywhere while the
  // user is on an approval card). Skip entirely on terminal scans.
  if (!isTerminal) {
    for (let i = 0; i < stages.length; i++) {
      if (states[i] !== "pending") continue;
      const priorsDone = states.slice(0, i).every((st) => st === "done");
      if (priorsDone) {
        states[i] = "active";
        break;
      }
    }
  }
  return states;
}

const TERMINAL_STATUSES = new Set([
  "COMPLETED",
  "REMEDIATION_COMPLETED",
  "FAILED",
  "CANCELLED",
  "EXPIRED",
  "BLOCKED_PRE_LLM",
  "BLOCKED_USER_DECLINE",
]);

function progressFromStages(
  seenStages: Set<string>,
  currentStatus: string | null,
  isPendingPrescan: boolean,
  isPendingApproval: boolean,
  prescanSubmitted: boolean,
  costSubmitted: boolean,
): number {
  if (!currentStatus) return 0;
  if (currentStatus === "COMPLETED" || currentStatus === "REMEDIATION_COMPLETED") return 100;
  if (
    currentStatus === "FAILED" ||
    currentStatus === "CANCELLED" ||
    currentStatus === "EXPIRED" ||
    currentStatus === "BLOCKED_PRE_LLM" ||
    currentStatus === "BLOCKED_USER_DECLINE"
  )
    return 100;
  // Count "done" using the same state machine the stage list uses, so
  // virtual gate stages (PRESCAN_REVIEW / COST_REVIEW) contribute too.
  const states = computeStageStates(
    KNOWN_STAGES,
    seenStages,
    false,
    isPendingPrescan,
    isPendingApproval,
    prescanSubmitted,
    costSubmitted,
  );
  const done = states.filter((s) => s === "done").length;
  // Ensure we don't show 100% while still running.
  return Math.min(95, Math.round((done / KNOWN_STAGES.length) * 100));
}

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
  const notificationPerm = useNotificationPermission();
  // Status starts `null` — NOT "QUEUED" — so the page doesn't flap
  // from "Analyzing your code" / "queued" to the real terminal state
  // for the few hundred ms before the one-shot getScanResult resolves.
  // Renders a small loading skeleton until the first known status.
  const [status, setStatus] = useState<string | null>(null);
  const [seenStages, setSeenStages] = useState<Set<string>>(new Set());
  const [events, setEvents] = useState<ScanEventMsg[]>([]);
  // §3.10b — per-file analysis progress, keyed by file_path so a file
  // showing up multiple times collapses to one row. Renders below the
  // pipeline stages while RUNNING_AGENTS is active.
  const [fileProgress, setFileProgress] = useState<
    Record<string, FileProgressItem>
  >({});
  const [streamError, setStreamError] = useState<string | null>(null);
  const [costDetails, setCostDetails] = useState<{
    total_estimated_cost?: number;
    total_input_tokens?: number;
    predicted_output_tokens?: number;
  } | null>(null);
  const [approving, setApproving] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [stopConfirmOpen, setStopConfirmOpen] = useState(false);
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);
  const [deleting, setDeleting] = useState(false);
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
  const [submittedForStatus, setSubmittedForStatus] = useState<string | null>(
    null,
  );
  const lastFetchedStatusRef = useRef<string | null>(null);
  const esRef = useRef<EventSource | null>(null);
  // N3: dedupe — only one notification per scan_id per page lifetime,
  // even if SSE reconnects after the `done` event.
  const notifiedRef = useRef<Record<string, boolean>>({});

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
        if (r.project_id) {
          setProjectInfo({
            id: r.project_id,
            name: r.project_name || "Project",
          });
        }
        if (r.cost_details) {
          setCostDetails(r.cost_details);
        }
        // Seed the live-event-log + stage-progress from the DB.
        // Terminal scans' SSE streams emit these once and close, so
        // a user landing AFTER the scan finished otherwise sees
        // "Waiting for events…" forever. SSE still tops up with any
        // new events for an in-progress scan.
        const seededEvents = r.events ?? [];
        if (seededEvents.length > 0) {
          // ScanEventItem has no `id` field — dedupe by
          // (stage_name + timestamp). Synthesize an event_id from
          // the timestamp so the SSE stream's later id-based dedupe
          // doesn't conflict (SSE-emitted events overwrite by id).
          setEvents((prev) => {
            const fingerprint = (e: { stage_name?: string; timestamp?: string | null }) =>
              `${e.stage_name ?? ""}|${e.timestamp ?? ""}`;
            const seen = new Set(prev.map((e) => fingerprint(e)));
            const merged = [...prev];
            for (const e of seededEvents) {
              if (!seen.has(fingerprint(e))) {
                // Generated schema doesn't include `details` (it
                // was added to the backend after the last codegen),
                // so read it via a structural cast to keep TS happy
                // until we regenerate api-generated.ts.
                const withDetails = e as unknown as {
                  details?: ScanEventMsg["details"];
                };
                merged.push({
                  scan_id: scanId,
                  event_id: -Date.parse(e.timestamp ?? "") || 0,
                  stage_name: e.stage_name,
                  status: e.status,
                  timestamp: e.timestamp ?? null,
                  details: withDetails.details ?? null,
                });
              }
            }
            return merged.slice(-500);
          });
          setSeenStages((prev) => {
            const next = new Set(prev);
            for (const e of seededEvents) next.add(e.stage_name);
            return next;
          });
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
    // ?last_event_id=… on reconnect so the backend skips the events
    // we already ingested. Seeded events use synthesized negative
    // ids so they don't pollute this counter.
    let lastSeenEventId = 0;
    // Dedupe across the seed-on-mount path and SSE replays. Native
    // EventSource also sends Last-Event-ID on its internal retries
    // and the backend honors it, but our manual reconnect creates a
    // brand-new EventSource so we need a frontend safety net too.
    const eventFingerprint = (e: {
      stage_name?: string;
      timestamp?: string | null;
    }) => `${e.stage_name ?? ""}|${e.timestamp ?? ""}`;

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
        } catch {
          // noop
        }
      });

      es.addEventListener("scan_event", (ev) => {
        try {
          const payload = JSON.parse((ev as MessageEvent).data) as ScanEventMsg;
          if (
            typeof payload.status !== "string" ||
            payload.status.length >= 64
          ) {
            return;
          }
          if (
            typeof payload.stage_name !== "string" ||
            payload.stage_name.length >= 64
          ) {
            return;
          }
          retryAttempt = 0;
          setStreamError(null);
          if (
            typeof payload.event_id === "number" &&
            payload.event_id > lastSeenEventId
          ) {
            lastSeenEventId = payload.event_id;
          }
          const fp = eventFingerprint(payload);
          setEvents((prev) => {
            // Drop replays — backend re-emits from id=0 on connect
            // unless Last-Event-ID was honored, and the seed-on-mount
            // path may have already inserted this row.
            if (prev.some((e) => eventFingerprint(e) === fp)) return prev;
            return [...prev, payload].slice(-500);
          });
          setSeenStages((prev) => {
            const next = new Set(prev);
            next.add(payload.stage_name);
            return next;
          });
          if (
            payload.stage_name === "FILE_ANALYZED" &&
            payload.details?.file_path
          ) {
            const filePath = String(payload.details.file_path).slice(0, 512);
            if (!filePath) return;
            const findingsCount = Math.max(
              0,
              Number(payload.details?.findings_count) | 0,
            );
            const fixesCount = Math.max(
              0,
              Number(payload.details?.fixes_count) | 0,
            );
            setFileProgress((prev) => {
              const next = {
                ...prev,
                [filePath]: {
                  file_path: filePath,
                  findings_count: findingsCount,
                  fixes_count: fixesCount,
                  timestamp: payload.timestamp,
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
  }, [status, scanId, navigate]);

  // §6 desktop + in-app notification on terminal status. Lives in its own
  // effect so it picks up the latest `notificationPerm` state (the
  // SSE listener captures stale values at registration time).
  // Threat-model mitigations:
  //   N1 — generic body, no findings count / severity / file paths
  //   N3 — `tag: scan_id` + `notifiedRef` dedupes per-scan
  useEffect(() => {
    if (!scanId) return;
    if (!status || !TERMINAL_STATUSES.has(status)) return;
    if (notifiedRef.current[scanId]) return;
    notifiedRef.current[scanId] = true;

    const isSuccess = status === "COMPLETED" || status === "REMEDIATION_COMPLETED";
    const isBlocked = status === "BLOCKED_PRE_LLM" || status === "BLOCKED_USER_DECLINE";
    const notifType = isSuccess ? "success" : isBlocked ? "warning" : "error";
    const notifTitle = projectInfo
      ? `${projectInfo.name} — scan ${isSuccess ? "completed" : isBlocked ? "blocked" : "failed"}`
      : `Scan ${scanId.slice(0, 12)} — ${isSuccess ? "completed" : isBlocked ? "blocked" : "failed"}`;

    // Always push an in-app notification.
    pushNotification({
      type: notifType,
      title: notifTitle,
      href: `/analysis/results/${scanId}`,
    });

    if (
      notificationPerm.supported &&
      notificationPerm.permission === "granted"
    ) {
      try {
        new Notification("SCCAP — Scan finished", {
          body: "Scan finished",
          tag: scanId,
        });
      } catch {
        // Notification constructor can throw on iOS Safari etc.
        // Fail silently — the in-app redirect still happens.
      }
    }
  }, [
    status,
    scanId,
    projectInfo,
    notificationPerm.supported,
    notificationPerm.permission,
    notificationPerm.dismissed,
    toast,
  ]);

  // Which gate (if any) the user has just dismissed. Only counts as
  // "submitted" while the live status still matches what was current
  // at click time — so a worker that hops through gates back-to-back
  // (e.g. PENDING_PRESCAN_APPROVAL → PENDING_COST_APPROVAL) doesn't
  // hide the second gate's card under a stale flag.
  const prescanSubmitted =
    submittedForStatus === "PENDING_PRESCAN_APPROVAL" &&
    status === "PENDING_PRESCAN_APPROVAL";
  const costSubmitted =
    submittedForStatus === "PENDING_COST_APPROVAL" &&
    status === "PENDING_COST_APPROVAL";
  const isPendingApproval =
    status === "PENDING_COST_APPROVAL" && !costSubmitted;
  const isPendingPrescan =
    status === "PENDING_PRESCAN_APPROVAL" && !prescanSubmitted;

  const progress = useMemo(
    () =>
      progressFromStages(
        seenStages,
        status,
        isPendingPrescan,
        isPendingApproval,
        prescanSubmitted,
        costSubmitted,
      ),
    [
      seenStages,
      status,
      isPendingPrescan,
      isPendingApproval,
      prescanSubmitted,
      costSubmitted,
    ],
  );
  const isTerminal = status !== null && TERMINAL_STATUSES.has(status);
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

  // Reset the optimistic-dismiss tracker the moment the live status
  // moves off the gate the user submitted against. Crucially fires on
  // PENDING_PRESCAN_APPROVAL → PENDING_COST_APPROVAL too — a plain
  // "is status still pending" check would miss that hop and trap the
  // cost card behind a stale prescan submission.
  useEffect(() => {
    if (submittedForStatus !== null && submittedForStatus !== status) {
      setSubmittedForStatus(null);
    }
  }, [status, submittedForStatus]);

  // Defensive fallback: if the page lands on PENDING_COST_APPROVAL
  // but we never received the SSE `cost_details` payload (e.g. SSE
  // reconnect raced the status flip, or the user landed straight on
  // a scan already past estimating), pull the estimate via the
  // one-shot HTTP path so the approval card isn't stuck on
  // "Approve to run the full analysis." with no numbers.
  useEffect(() => {
    if (!scanId) return;
    if (status !== "PENDING_COST_APPROVAL") return;
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
    setSubmittedForStatus("PENDING_COST_APPROVAL");
    setApproving(true);
    try {
      await scanService.approveScan(scanId);
      toast.success("Scan approved. Analysis resuming.");
    } catch (err) {
      const e = err as { message?: string };
      toast.error(e.message || "Failed to approve scan");
      // Re-show the panel so the user can retry.
      setSubmittedForStatus(null);
    } finally {
      setApproving(false);
    }
  }, [scanId, toast]);

  const submitPrescanApproval = useCallback(
    async (override: boolean) => {
      if (!scanId) return;
      setSubmittedForStatus("PENDING_PRESCAN_APPROVAL");
      setApproving(true);
      try {
        await scanService.approveScan(scanId, {
          kind: "prescan_approval",
          approved: true,
          override_critical_secret: override,
        });
        toast.success(
          override
            ? "Override recorded. Continuing to LLM analysis."
            : "Continuing to LLM analysis.",
        );
        setOverrideOpen(false);
      } catch (err) {
        const e = err as { message?: string };
        toast.error(e.message || "Failed to continue scan");
        setSubmittedForStatus(null);
      } finally {
        setApproving(false);
      }
    },
    [scanId, toast],
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
    setSubmittedForStatus("PENDING_PRESCAN_APPROVAL");
    setDeclining(true);
    try {
      await scanService.approveScan(scanId, {
        kind: "prescan_approval",
        approved: false,
        override_critical_secret: false,
      });
      toast.info("Scan stopped before LLM analysis.");
    } catch (err) {
      const e = err as { message?: string };
      toast.error(e.message || "Failed to stop scan");
      setSubmittedForStatus(null);
    } finally {
      setDeclining(false);
    }
  }, [scanId, toast]);

  const handleCancel = useCallback(async () => {
    if (!scanId) return;
    setCancelling(true);
    try {
      await scanService.cancelScan(scanId);
      toast.info("Scan cancelled.");
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
      toast.error(e.message || "Failed to cancel scan");
    } finally {
      setCancelling(false);
      setStopConfirmOpen(false);
    }
  }, [scanId, projectInfo, navigate, queryClient, toast]);

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
              { label: `Scan ${scanId?.slice(0, 12) ?? "…"}` },
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
            { label: `Scan ${scanId?.slice(0, 12) ?? "…"}` },
          ];
        })()}
        chip={
          // Critical (red) chip ONLY for genuine errors. User stops,
          // safety blocks, and EXPIRED render as a neutral chip — they
          // are not failures.
          <div
            className={`chip ${
              isError ? "chip-critical" : isBlocked ? "chip-warn" : "chip-info"
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
              {scanId?.slice(0, 12)}
            </span>{" "}
            · {displayStatus(status)}
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
                  ? "Scan complete — redirecting to results…"
                  : status === "BLOCKED_PRE_LLM"
                    ? "Scan stopped — critical secret detected"
                    : status === "BLOCKED_USER_DECLINE"
                      ? "Scan stopped at your request"
                      : status === "CANCELLED"
                        ? "Scan stopped at your request"
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

          <div style={{ display: "grid", gap: 10, marginTop: 22 }}>
            {(() => {
              const stageStates = computeStageStates(
                KNOWN_STAGES,
                seenStages,
                isTerminal,
                isPendingPrescan,
                isPendingApproval,
                prescanSubmitted,
                costSubmitted,
              );
              return KNOWN_STAGES.map((s, i) => {
                const state = stageStates[i];
                const isHighlighted = state === "active" || state === "paused";
                return (
                  <div
                    key={s.key}
                    style={{
                      display: "grid",
                      gridTemplateColumns: "auto 1fr",
                      gap: 12,
                      alignItems: "center",
                      padding: "10px 12px",
                      borderRadius: 8,
                      background: isHighlighted
                        ? "var(--primary-weak)"
                        : "transparent",
                      transition: "background .3s var(--ease)",
                    }}
                  >
                    <div
                      style={{
                        width: 26,
                        height: 26,
                        borderRadius: "50%",
                        display: "grid",
                        placeItems: "center",
                        background:
                          state === "done"
                            ? "var(--success)"
                            : state === "active"
                              ? "var(--primary)"
                              : state === "paused"
                                ? "var(--primary)"
                                : "var(--bg-soft)",
                        color: state === "pending" ? "var(--fg-subtle)" : "white",
                        border:
                          "1px solid " +
                          (state === "pending" ? "var(--border)" : "transparent"),
                      }}
                    >
                      {state === "done" ? (
                        <Icon.Check size={12} />
                      ) : state === "active" ? (
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
                        s.icon
                      )}
                    </div>
                    <div
                      style={{
                        fontSize: 13.5,
                        fontWeight: isHighlighted ? 600 : 400,
                        color:
                          state === "pending"
                            ? "var(--fg-subtle)"
                            : "var(--fg)",
                      }}
                    >
                      {s.label}
                      {state === "paused" && (
                        <span
                          style={{
                            marginLeft: 8,
                            fontSize: 12,
                            fontWeight: 400,
                            color: "var(--fg-muted)",
                          }}
                        >
                          · awaiting your approval
                        </span>
                      )}
                    </div>
                  </div>
                );
              });
            })()}
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
              <PrescanReviewCard
                findings={prescanReview.findings}
                hasCriticalSecret={prescanReview.has_critical_secret}
                approving={approving}
                declining={declining}
                onContinue={handlePrescanContinue}
                onStop={handlePrescanStop}
                readOnly={!isPendingPrescan}
              />
            )}
          </>
        )}

        <CriticalSecretOverrideModal
          open={overrideOpen}
          submitting={approving}
          onCancel={() => setOverrideOpen(false)}
          onConfirm={() => void submitPrescanApproval(true)}
        />

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
                Cost estimate ready
                {typeof costDetails?.total_estimated_cost === "number" && (
                  <span
                    style={{
                      marginLeft: 10,
                      color: "var(--fg)",
                      fontSize: 16,
                      fontVariantNumeric: "tabular-nums",
                    }}
                  >
                    · ${costDetails.total_estimated_cost.toFixed(4)}
                  </span>
                )}
              </div>
              <div style={{ color: "var(--fg)", fontSize: 13 }}>
                {typeof costDetails?.total_input_tokens === "number" &&
                typeof costDetails?.predicted_output_tokens === "number"
                  ? `~${costDetails.total_input_tokens.toLocaleString()} input tokens + ~${costDetails.predicted_output_tokens.toLocaleString()} predicted output tokens. Approve to run the full analysis.`
                  : "Approve to run the full analysis."}
              </div>
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
            <div style={{ color: "var(--fg)", fontSize: 13 }}>
              Check the worker logs for details, or try resubmitting the same
              source. The scan record is preserved under the Projects list.
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
                  <Icon.File size={14} /> Files analyzed (live)
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
                      {f.findings_count} finding
                      {f.findings_count === 1 ? "" : "s"}
                      {f.fixes_count > 0 && ` · ${f.fixes_count} fix${f.fixes_count === 1 ? "" : "es"}`}
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
                <Icon.Terminal size={14} /> Live event log
              </>
            }
          />
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
              : events
                  .map(
                    (e) =>
                      `[${e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : "—"}] ${e.stage_name} · ${e.status}`,
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
            {displayStatus(status)}
          </div>
          <div
            style={{ marginTop: 10, fontSize: 12, color: "var(--fg-muted)" }}
          >
            {seenStages.size} stage{seenStages.size === 1 ? "" : "s"} complete
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
