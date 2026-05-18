// Global scan-watcher (#89 / PRD #83).
//
// Mounted once at the authenticated app root. It polls the user's
// recent scans and, when a scan it was tracking as active transitions
// to a terminal status, fires an in-app notification + (if permitted)
// a desktop notification — on whatever page the user is on. This
// replaces the page-bound notification effect that only fired while
// the scan-status page was open.

import React, { useEffect, useRef } from "react";

import { useQuery } from "@tanstack/react-query";

import { scanService } from "../../shared/api/scanService";
import { useAuth } from "../../shared/hooks/useAuth";
import { useNotificationPermission } from "../../shared/hooks/useNotificationPermission";
import { pushNotification } from "../../shared/hooks/useNotifications";
import { ensureWebPushSubscription } from "../../shared/lib/pushSubscription";
import { isTerminalStatus } from "../../shared/lib/scanProgress";
import type { ScanHistoryItem } from "../../shared/types/api";

const SUCCESS_STATUSES = new Set(["COMPLETED", "REMEDIATION_COMPLETED"]);
const BLOCKED_STATUSES = new Set(["BLOCKED_PRE_LLM", "BLOCKED_USER_DECLINE"]);

function notifyScanTerminal(
  scan: ScanHistoryItem,
  desktopAllowed: boolean,
): void {
  const isSuccess = SUCCESS_STATUSES.has(scan.status);
  const isBlocked = BLOCKED_STATUSES.has(scan.status);
  const outcome = isSuccess
    ? "completed"
    : isBlocked
      ? "blocked"
      : "failed";
  const type = isSuccess ? "success" : isBlocked ? "warning" : "error";

  pushNotification({
    type,
    title: `${scan.project_name} — scan ${outcome}`,
    href: `/analysis/results/${scan.id}`,
  });

  if (desktopAllowed) {
    try {
      // Generic body (threat-model N1: no findings count / severity).
      new Notification("SCCAP — Scan finished", {
        body: `${scan.project_name} — scan ${outcome}`,
        tag: scan.id,
      });
    } catch {
      // Notification constructor can throw on some browsers — the
      // in-app notification still landed.
    }
  }
}

export const ScanWatcher: React.FC = () => {
  const { accessToken } = useAuth();
  const notificationPerm = useNotificationPermission();

  // Per-scan last-seen status. Seeded on the first poll WITHOUT
  // notifying, so pre-existing terminal scans never fire a popup —
  // only a transition observed in this session does.
  const lastStatus = useRef<Record<string, string>>({});
  const baselined = useRef(false);

  const { data } = useQuery({
    queryKey: ["scan-watcher"],
    queryFn: () => scanService.getScanHistory(1, 20, undefined, "desc"),
    enabled: !!accessToken,
    // Poll faster while a scan is active so completion is caught
    // promptly; back off when everything is idle.
    refetchInterval: (query) => {
      const items = query.state.data?.items ?? [];
      return items.some((s) => !isTerminalStatus(s.status)) ? 8_000 : 25_000;
    },
  });

  const desktopAllowed =
    notificationPerm.supported && notificationPerm.permission === "granted";

  // Register the browser for Web Push (#90) once notification
  // permission is granted, so scan-completion notifications fire even
  // when the SCCAP tab is closed. Idempotent + best-effort.
  useEffect(() => {
    if (accessToken && desktopAllowed) {
      void ensureWebPushSubscription();
    }
  }, [accessToken, desktopAllowed]);

  useEffect(() => {
    const items = data?.items ?? [];
    if (items.length === 0) return;

    if (!baselined.current) {
      for (const s of items) lastStatus.current[s.id] = s.status;
      baselined.current = true;
      return;
    }

    for (const s of items) {
      const prev = lastStatus.current[s.id];
      const wasActive = prev !== undefined && !isTerminalStatus(prev);
      if (wasActive && isTerminalStatus(s.status)) {
        notifyScanTerminal(s, desktopAllowed);
      }
      lastStatus.current[s.id] = s.status;
    }
  }, [data, desktopAllowed]);

  return null;
};
