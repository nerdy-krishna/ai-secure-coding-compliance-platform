// secure-code-ui/src/features/system/UpdateAvailableBanner.tsx
//
// Dashboard notice when a newer release has been published.
//
// Read-only by design: the platform never replaces its own code from a web
// request. The banner tells the operator that a release exists and gives the
// exact host command to apply it (setup.sh --update, which backs up the
// database, rebuilds, migrates and health-gates).
//
// Superuser-only: /api/v1/system/update-check is superuser-gated, and only an
// operator can run the upgrade anyway.

import React, { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import apiClient from "../../shared/api/apiClient";
import { useAuth } from "../../shared/hooks/useAuth";
import { Icon } from "../../shared/ui/Icon";

interface UpdateStatus {
  phase: "idle" | "running" | "succeeded" | "failed";
  message: string | null;
  updated_at: string | null;
  from_commit: string | null;
  to_commit: string | null;
  exit_code: number | null;
  log_tail: string | null;
  request_pending: boolean;
  runner_available: boolean;
}

interface UpdateCheck {
  current_version: string;
  current_commit: string;
  latest_tag: string | null;
  latest_url: string | null;
  published_at: string | null;
  notes_excerpt: string | null;
  update_available: boolean;
  checked: boolean;
  error: string | null;
  update_command: string;
}

const UpdateAvailableBanner: React.FC = () => {
  const { user } = useAuth();
  const isAdmin = Boolean(user?.is_superuser);

  const { data } = useQuery<UpdateCheck>({
    queryKey: ["system", "update-check"],
    queryFn: async () =>
      (await apiClient.get<UpdateCheck>("/system/update-check")).data,
    enabled: isAdmin,
    // The backend caches the GitHub lookup for an hour; keep the UI in step.
    staleTime: 60 * 60 * 1000,
    retry: false,
  });

  const queryClient = useQueryClient();
  const [triggering, setTriggering] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const { data: status } = useQuery<UpdateStatus>({
    queryKey: ["system", "update-status"],
    queryFn: async () =>
      (await apiClient.get<UpdateStatus>("/system/update-status")).data,
    enabled: isAdmin,
    // Poll quickly while an update runs; the app restarts mid-way, so a failed
    // poll is expected and must not blank the panel.
    refetchInterval: (query) =>
      query.state.data?.phase === "running" ? 4000 : false,
    retry: false,
  });

  const startUpdate = async () => {
    setTriggering(true);
    setError(null);
    try {
      await apiClient.post("/system/update");
      await queryClient.invalidateQueries({ queryKey: ["system", "update-status"] });
    } catch (err) {
      const detail = (err as { response?: { data?: { detail?: string } } })?.response
        ?.data?.detail;
      setError(detail || "Could not start the update.");
    } finally {
      setTriggering(false);
    }
  };

  if (!isAdmin || !data?.update_available) return null;

  const running =
    status?.phase === "running" || status?.request_pending || triggering;

  return (
    <div
      className="sccap-card"
      role="status"
      data-testid="update-available-banner"
      style={{
        display: "grid",
        gap: 8,
        padding: 16,
        marginBottom: 20,
        borderColor: "var(--primary)",
        background: "var(--primary-weak)",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          fontSize: 14,
          fontWeight: 600,
          color: "var(--primary)",
        }}
      >
        <Icon.Refresh size={15} />
        Update available: {data.latest_tag}
      </div>
      <div style={{ fontSize: 13, color: "var(--fg-muted)", lineHeight: 1.55 }}>
        Running {data.current_version}
        {data.current_commit ? ` (${data.current_commit.slice(0, 8)})` : ""}.
        {data.published_at
          ? ` Published ${new Date(data.published_at).toLocaleDateString()}.`
          : ""}{" "}
        Apply it on the host from the install directory — the upgrade backs up
        the database, rebuilds, migrates and health-checks before reporting
        success:
        <code
          style={{
            display: "block",
            marginTop: 6,
            padding: "6px 8px",
            borderRadius: "var(--r-xs)",
            background: "var(--bg-inset)",
            fontFamily: "var(--font-mono)",
            fontSize: 12,
            color: "var(--fg)",
          }}
        >
          {data.update_command}
        </code>
      </div>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <button
          className="sccap-btn sccap-btn-primary sccap-btn-sm"
          onClick={startUpdate}
          disabled={running || status?.runner_available === false}
          title={
            status?.runner_available === false
              ? "This deployment has no host update runner; use ./setup.sh --update"
              : "Backs up the database, rebuilds, migrates and health-checks"
          }
        >
          <Icon.Refresh size={13} />{" "}
          {running ? "Updating…" : "Update now"}
        </button>
        {data.latest_url && (
          <a
            className="sccap-btn sccap-btn-sm"
            href={data.latest_url}
            target="_blank"
            rel="noreferrer noopener"
          >
            <Icon.ArrowR size={13} /> Release notes
          </a>
        )}
        {status && status.phase !== "idle" && (
          <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
            {status.phase}
            {status.message ? ` — ${status.message}` : ""}
          </span>
        )}
      </div>
      {error && (
        <div style={{ fontSize: 12, color: "var(--critical)" }} role="alert">
          {error}
        </div>
      )}
      {running && (
        <div style={{ fontSize: 12, color: "var(--fg-muted)", lineHeight: 1.5 }}>
          The stack restarts during the update — this page may disconnect and come
          back. Reload when the phase reports <b>succeeded</b>.
        </div>
      )}
      {status?.phase === "failed" && status.log_tail && (
        <pre
          style={{
            maxHeight: 220,
            overflow: "auto",
            margin: 0,
            padding: 8,
            background: "var(--bg-inset)",
            borderRadius: "var(--r-xs)",
            fontFamily: "var(--font-mono)",
            fontSize: 11,
            whiteSpace: "pre-wrap",
          }}
        >
          {status.log_tail}
        </pre>
      )}
      {status?.phase === "succeeded" && (
        <button
          className="sccap-btn sccap-btn-sm"
          onClick={() => window.location.reload()}
        >
          Reload to finish
        </button>
      )}
    </div>
  );
};

export default UpdateAvailableBanner;
