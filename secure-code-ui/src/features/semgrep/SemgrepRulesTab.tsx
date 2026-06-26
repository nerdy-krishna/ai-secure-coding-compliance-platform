// src/features/semgrep/SemgrepRulesTab.tsx
//
// Admin tab for managing Semgrep rule sources. Shows settings, a source
// table with inline toggles, and a sync-run drawer.

import React, { useState } from "react";
import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { AxiosError } from "axios";
import { ruleSourcesService } from "../../shared/api/ruleSourcesService";
import type {
  RuleSourceRead,
  RuleSourceUpdate,
  SyncRunRead,
  IngestionSettingsUpdate,
} from "../../shared/types/api";
import { Icon } from "../../shared/ui/Icon";
import { Modal } from "../../shared/ui/Modal";
import { useToast } from "../../shared/ui/Toast";
import SemgrepOnboardingWizard from "./SemgrepOnboardingWizard";

// ── Helpers ──────────────────────────────────────────────────────────────────

function fmtDate(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function fmtSha(sha: string | null): string {
  return sha ? sha.slice(0, 7) : "—";
}

// ── Status badge ─────────────────────────────────────────────────────────────

const StatusBadge: React.FC<{ status: RuleSourceRead["last_sync_status"] }> = ({ status }) => {
  const configs = {
    running: {
      bg: "rgba(245,158,66,0.12)",
      color: "var(--warning)",
      label: "Syncing",
      icon: <Icon.Refresh size={11} style={{ animation: "spin 1s linear infinite" }} />,
    },
    success: {
      bg: "rgba(34,197,94,0.10)",
      color: "var(--success)",
      label: "OK",
      icon: <Icon.Check size={11} />,
    },
    failed: {
      bg: "rgba(239,68,68,0.10)",
      color: "var(--error)",
      label: "Failed",
      icon: <Icon.X size={11} />,
    },
    never: {
      bg: "var(--bg-soft)",
      color: "var(--fg-subtle)",
      label: "Never synced",
      icon: <Icon.Clock size={11} />,
    },
  } as const;

  const c = configs[status];
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 4,
        padding: "2px 8px",
        borderRadius: 999,
        fontSize: 11,
        fontWeight: 500,
        background: c.bg,
        color: c.color,
      }}
    >
      {c.icon} {c.label}
    </span>
  );
};

// ── Edit modal ────────────────────────────────────────────────────────────────

interface EditModalProps {
  source: RuleSourceRead | null;
  onClose: () => void;
  onSave: (id: string, data: RuleSourceUpdate) => void;
  saving: boolean;
}

const EDIT_EMPTY: RuleSourceUpdate & { display_name: string; description: string; repo_url: string; branch: string } = {
  display_name: "",
  description: "",
  repo_url: "",
  branch: "main",
  subpath: null,
  sync_cron: null,
  license_spdx: "",
  author: "",
  enabled: true,
  auto_sync: false,
};

const EditModal: React.FC<EditModalProps> = ({ source, onClose, onSave, saving }) => {
  const [form, setForm] = React.useState<typeof EDIT_EMPTY>(EDIT_EMPTY);

  React.useEffect(() => {
    if (source) {
      setForm({
        display_name: source.display_name,
        description: source.description,
        repo_url: source.repo_url,
        branch: source.branch,
        subpath: source.subpath ?? null,
        sync_cron: source.sync_cron ?? null,
        license_spdx: source.license_spdx,
        author: source.author,
        enabled: source.enabled,
        auto_sync: source.auto_sync,
      });
    }
  }, [source]);

  const set = (k: keyof typeof EDIT_EMPTY, v: unknown) =>
    setForm((f) => ({ ...f, [k]: v }));

  if (!source) return null;

  return (
    <Modal
      open={!!source}
      onClose={onClose}
      title={`Edit source — ${source.slug}`}
      width={640}
      footer={
        <>
          <button className="sccap-btn sccap-btn-sm" onClick={onClose} disabled={saving}>
            Cancel
          </button>
          <button
            className="sccap-btn sccap-btn-primary sccap-btn-sm"
            disabled={saving}
            onClick={() => onSave(source.id, form)}
          >
            {saving ? "Saving…" : "Save changes"}
          </button>
        </>
      }
    >
      <div style={{ display: "grid", gap: 14 }}>
        <label style={{ display: "grid", gap: 6 }}>
          <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>Display name</span>
          <input
            className="sccap-input"
            value={form.display_name}
            onChange={(e) => set("display_name", e.target.value)}
            maxLength={128}
          />
        </label>
        <label style={{ display: "grid", gap: 6 }}>
          <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>Description</span>
          <textarea
            className="sccap-input"
            rows={2}
            value={form.description}
            onChange={(e) => set("description", e.target.value)}
            maxLength={512}
          />
        </label>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <label style={{ display: "grid", gap: 6 }}>
            <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>Repository URL</span>
            <input
              className="sccap-input"
              value={form.repo_url}
              onChange={(e) => set("repo_url", e.target.value)}
              placeholder="https://github.com/…"
            />
          </label>
          <label style={{ display: "grid", gap: 6 }}>
            <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>Branch</span>
            <input
              className="sccap-input"
              value={form.branch}
              onChange={(e) => set("branch", e.target.value)}
            />
          </label>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <label style={{ display: "grid", gap: 6 }}>
            <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>Subpath (optional)</span>
            <input
              className="sccap-input"
              value={form.subpath ?? ""}
              onChange={(e) => set("subpath", e.target.value || null)}
              placeholder="rules/"
            />
          </label>
          <label style={{ display: "grid", gap: 6 }}>
            <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>Sync cron (optional)</span>
            <input
              className="sccap-input"
              value={form.sync_cron ?? ""}
              onChange={(e) => set("sync_cron", e.target.value || null)}
              placeholder="0 3 * * *"
            />
          </label>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <label style={{ display: "grid", gap: 6 }}>
            <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>License (SPDX)</span>
            <input
              className="sccap-input"
              value={form.license_spdx}
              onChange={(e) => set("license_spdx", e.target.value)}
              placeholder="MIT"
            />
          </label>
          <label style={{ display: "grid", gap: 6 }}>
            <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>Author</span>
            <input
              className="sccap-input"
              value={form.author}
              onChange={(e) => set("author", e.target.value)}
            />
          </label>
        </div>
        <div style={{ display: "flex", gap: 24 }}>
          <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer" }}>
            <input
              type="checkbox"
              checked={!!form.enabled}
              onChange={(e) => set("enabled", e.target.checked)}
              style={{ accentColor: "var(--primary)" }}
            />
            <span style={{ fontSize: 13, color: "var(--fg)" }}>Enabled</span>
          </label>
          <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer" }}>
            <input
              type="checkbox"
              checked={!!form.auto_sync}
              onChange={(e) => set("auto_sync", e.target.checked)}
              style={{ accentColor: "var(--primary)" }}
            />
            <span style={{ fontSize: 13, color: "var(--fg)" }}>Auto-sync</span>
          </label>
        </div>
      </div>
    </Modal>
  );
};

// ── Sync runs drawer ──────────────────────────────────────────────────────────

const RunStatusBadge: React.FC<{ status: SyncRunRead["status"] }> = ({ status }) => {
  const map: Record<SyncRunRead["status"], { bg: string; color: string; label: string }> = {
    running: { bg: "rgba(245,158,66,0.12)", color: "var(--warning)", label: "Running" },
    success: { bg: "rgba(34,197,94,0.10)", color: "var(--success)", label: "Success" },
    failed: { bg: "rgba(239,68,68,0.10)", color: "var(--error)", label: "Failed" },
  };
  const c = map[status];
  return (
    <span
      style={{
        display: "inline-block",
        padding: "2px 8px",
        borderRadius: 999,
        fontSize: 11,
        fontWeight: 500,
        background: c.bg,
        color: c.color,
      }}
    >
      {c.label}
    </span>
  );
};

interface SyncRunsDrawerProps {
  source: RuleSourceRead | null;
  onClose: () => void;
}

const SyncRunsDrawer: React.FC<SyncRunsDrawerProps> = ({ source, onClose }) => {
  const { data, isLoading } = useQuery({
    queryKey: ["sync-runs", source?.id],
    queryFn: () => ruleSourcesService.listSyncRuns(source!.id),
    enabled: !!source,
  });

  if (!source) return null;

  return (
    <Modal
      open={!!source}
      onClose={onClose}
      title={`Sync history — ${source.display_name}`}
      width={780}
    >
      {isLoading ? (
        <div style={{ textAlign: "center", color: "var(--fg-muted)", padding: 32 }}>
          Loading runs…
        </div>
      ) : !data?.items.length ? (
        <div style={{ textAlign: "center", color: "var(--fg-muted)", padding: 32 }}>
          No sync runs yet.
        </div>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
            <thead>
              <tr style={{ borderBottom: "1px solid var(--border)" }}>
                {["Started", "Status", "+Added", "~Updated", "-Removed", "Invalid", "Error / SHA"].map(
                  (h) => (
                    <th
                      key={h}
                      style={{
                        textAlign: "left",
                        padding: "6px 10px",
                        color: "var(--fg-muted)",
                        fontWeight: 500,
                        whiteSpace: "nowrap",
                      }}
                    >
                      {h}
                    </th>
                  )
                )}
              </tr>
            </thead>
            <tbody>
              {data.items.map((r) => (
                <tr
                  key={r.id}
                  style={{ borderBottom: "1px solid var(--border)", verticalAlign: "top" }}
                >
                  <td style={{ padding: "8px 10px", whiteSpace: "nowrap", color: "var(--fg-muted)" }}>
                    {fmtDate(r.started_at)}
                  </td>
                  <td style={{ padding: "8px 10px" }}>
                    <RunStatusBadge status={r.status} />
                  </td>
                  <td style={{ padding: "8px 10px", color: "var(--success)" }}>+{r.rules_added}</td>
                  <td style={{ padding: "8px 10px", color: "var(--fg-muted)" }}>~{r.rules_updated}</td>
                  <td style={{ padding: "8px 10px", color: "var(--error)" }}>-{r.rules_removed}</td>
                  <td style={{ padding: "8px 10px", color: "var(--warning)" }}>{r.rules_invalid}</td>
                  <td style={{ padding: "8px 10px", color: "var(--fg-subtle)", fontSize: 11 }}>
                    {r.error ? (
                      <span style={{ color: "var(--error)" }} title={r.error}>
                        {r.error.slice(0, 60)}{r.error.length > 60 ? "…" : ""}
                      </span>
                    ) : (
                      <span title={r.commit_sha_after ?? ""}>{fmtSha(r.commit_sha_after)}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {data.total > data.items.length && (
            <div style={{ padding: "10px 10px 0", fontSize: 11.5, color: "var(--fg-subtle)" }}>
              Showing {data.items.length} of {data.total} runs.
            </div>
          )}
        </div>
      )}
    </Modal>
  );
};

// ── Settings panel ────────────────────────────────────────────────────────────

const SettingsPanel: React.FC = () => {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [expanded, setExpanded] = useState(false);

  const { data: settings, isLoading } = useQuery({
    queryKey: ["rule-sources-settings"],
    queryFn: ruleSourcesService.getSettings,
  });

  const [draft, setDraft] = React.useState<IngestionSettingsUpdate>({});
  React.useEffect(() => {
    if (settings) {
      setDraft({
        global_enabled: settings.global_enabled,
        max_rules_per_scan: settings.max_rules_per_scan,
        sweep_interval_seconds: settings.sweep_interval_seconds,
        workdir: settings.workdir,
        allowed_licenses: settings.allowed_licenses,
      });
    }
  }, [settings]);

  const saveMutation = useMutation({
    mutationFn: (u: IngestionSettingsUpdate) => ruleSourcesService.updateSettings(u),
    onSuccess: () => {
      toast.success("Settings saved.");
      queryClient.invalidateQueries({ queryKey: ["rule-sources-settings"] });
    },
    onError: (err: unknown) => {
      const msg =
        err instanceof AxiosError
          ? (err.response?.data as { detail?: string })?.detail ?? err.message
          : "Failed to save settings";
      toast.error(typeof msg === "string" ? msg : "Failed to save settings");
    },
  });

  const setD = (k: keyof IngestionSettingsUpdate, v: unknown) =>
    setDraft((d) => ({ ...d, [k]: v }));

  return (
    <div className="sccap-card" style={{ marginBottom: 12 }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          cursor: "pointer",
        }}
        onClick={() => setExpanded((x) => !x)}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <Icon.Settings size={14} color="var(--fg-muted)" />
          <span style={{ fontWeight: 600, color: "var(--fg)", fontSize: 13.5 }}>
            Ingestion settings
          </span>
          {settings && (
            <span
              style={{
                padding: "2px 8px",
                borderRadius: 999,
                fontSize: 11,
                background: settings.global_enabled ? "rgba(34,197,94,0.10)" : "var(--bg-soft)",
                color: settings.global_enabled ? "var(--success)" : "var(--fg-subtle)",
              }}
            >
              {settings.global_enabled ? "Enabled" : "Disabled"}
            </span>
          )}
        </div>
        {expanded ? <Icon.ChevronU size={14} /> : <Icon.ChevronD size={14} />}
      </div>

      {expanded && (
        <div style={{ marginTop: 16, display: "grid", gap: 14 }}>
          {isLoading ? (
            <div style={{ color: "var(--fg-muted)", fontSize: 13 }}>Loading…</div>
          ) : (
            <>
              <div style={{ display: "flex", gap: 24, flexWrap: "wrap" }}>
                <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer" }}>
                  <input
                    type="checkbox"
                    checked={!!draft.global_enabled}
                    onChange={(e) => setD("global_enabled", e.target.checked)}
                    style={{ accentColor: "var(--primary)" }}
                  />
                  <span style={{ fontSize: 13, color: "var(--fg)" }}>Global enabled</span>
                </label>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
                <label style={{ display: "grid", gap: 6 }}>
                  <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>Max rules per scan</span>
                  <input
                    className="sccap-input"
                    type="number"
                    min={0}
                    value={draft.max_rules_per_scan ?? ""}
                    onChange={(e) => setD("max_rules_per_scan", parseInt(e.target.value) || 0)}
                  />
                </label>
                <label style={{ display: "grid", gap: 6 }}>
                  <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>Sweep interval (s)</span>
                  <input
                    className="sccap-input"
                    type="number"
                    min={60}
                    value={draft.sweep_interval_seconds ?? ""}
                    onChange={(e) => setD("sweep_interval_seconds", parseInt(e.target.value) || 3600)}
                  />
                </label>
                <label style={{ display: "grid", gap: 6 }}>
                  <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>Working directory</span>
                  <input
                    className="sccap-input"
                    value={draft.workdir ?? ""}
                    onChange={(e) => setD("workdir", e.target.value)}
                  />
                </label>
              </div>
              <label style={{ display: "grid", gap: 6 }}>
                <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
                  Allowed licenses (comma-separated SPDX identifiers)
                </span>
                <input
                  className="sccap-input"
                  value={(draft.allowed_licenses ?? []).join(", ")}
                  onChange={(e) =>
                    setD(
                      "allowed_licenses",
                      e.target.value
                        .split(",")
                        .map((s) => s.trim())
                        .filter(Boolean)
                    )
                  }
                  placeholder="MIT, Apache-2.0, LGPL-2.1"
                />
              </label>
              <div style={{ display: "flex", justifyContent: "flex-end" }}>
                <button
                  className="sccap-btn sccap-btn-primary sccap-btn-sm"
                  onClick={() => saveMutation.mutate(draft)}
                  disabled={saveMutation.isPending}
                >
                  {saveMutation.isPending ? "Saving…" : "Save settings"}
                </button>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
};

// ── Main component ────────────────────────────────────────────────────────────

const SemgrepRulesTab: React.FC = () => {
  const toast = useToast();
  const queryClient = useQueryClient();

  const [editingSource, setEditingSource] = useState<RuleSourceRead | null>(null);
  const [runsSource, setRunsSource] = useState<RuleSourceRead | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  const anyRunning = (sources: RuleSourceRead[]) =>
    sources.some((s) => s.last_sync_status === "running");

  const { data: sources = [], isLoading } = useQuery<RuleSourceRead[]>({
    queryKey: ["rule-sources"],
    queryFn: ruleSourcesService.listSources,
    refetchInterval: (query) => {
      const data = query.state.data;
      return Array.isArray(data) && anyRunning(data) ? 3000 : false;
    },
  });

  // ── Selection helpers ──────────────────────────────────────────────────

  const allIds = sources.map((s) => s.id);
  const allSelected = allIds.length > 0 && allIds.every((id) => selectedIds.has(id));
  const someSelected = selectedIds.size > 0;

  const toggleSelectAll = () => {
    if (allSelected) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(allIds));
    }
  };

  const toggleSelectOne = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const clearSelection = () => setSelectedIds(new Set());

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: RuleSourceUpdate }) =>
      ruleSourcesService.updateSource(id, data),
    onSuccess: () => {
      toast.success("Source updated.");
      queryClient.invalidateQueries({ queryKey: ["rule-sources"] });
      setEditingSource(null);
    },
    onError: (err: unknown) => {
      const msg =
        err instanceof AxiosError
          ? (err.response?.data as { detail?: string })?.detail ?? err.message
          : "Failed to update source";
      toast.error(typeof msg === "string" ? msg : "Failed to update source");
    },
  });

  const deleteMutation = useMutation({
    mutationFn: ruleSourcesService.deleteSource,
    onSuccess: () => {
      toast.success("Source deleted.");
      queryClient.invalidateQueries({ queryKey: ["rule-sources"] });
      setConfirmDeleteId(null);
    },
    onError: (err: unknown) => {
      const msg =
        err instanceof AxiosError
          ? (err.response?.data as { detail?: string })?.detail ?? err.message
          : "Failed to delete source";
      toast.error(typeof msg === "string" ? msg : "Failed to delete source");
    },
  });

  const syncMutation = useMutation({
    mutationFn: ruleSourcesService.triggerSync,
    onSuccess: (_, id) => {
      toast.success("Sync triggered.");
      queryClient.invalidateQueries({ queryKey: ["rule-sources"] });
      queryClient.invalidateQueries({ queryKey: ["sync-runs", id] });
    },
    onError: (err: unknown) => {
      const msg =
        err instanceof AxiosError
          ? (err.response?.data as { detail?: string })?.detail ?? err.message
          : "Failed to trigger sync";
      toast.error(typeof msg === "string" ? msg : "Failed to trigger sync");
    },
  });

  // ── Bulk actions ──────────────────────────────────────────────────────

  const bulkUpdate = useMutation({
    mutationFn: async ({
      ids,
      data,
    }: {
      ids: string[];
      data: RuleSourceUpdate;
    }) => {
      // Fire all updates in parallel and collect results.
      const results = await Promise.allSettled(
        ids.map((id) => ruleSourcesService.updateSource(id, data)),
      );
      const failed = results.filter((r) => r.status === "rejected").length;
      if (failed > 0) {
        throw new Error(`${failed} of ${ids.length} updates failed`);
      }
    },
    onSuccess: (_data, { ids }) => {
      toast.success(`${ids.length} source${ids.length > 1 ? "s" : ""} updated.`);
      queryClient.invalidateQueries({ queryKey: ["rule-sources"] });
      clearSelection();
    },
    onError: (err: unknown) => {
      const msg =
        err instanceof Error ? err.message : "Bulk update failed";
      toast.error(msg);
    },
  });

  const bulkSync = useMutation({
    mutationFn: async (ids: string[]) => {
      const results = await Promise.allSettled(
        ids.map((id) => ruleSourcesService.triggerSync(id)),
      );
      const failed = results.filter((r) => r.status === "rejected").length;
      if (failed > 0) {
        throw new Error(`${failed} of ${ids.length} syncs failed`);
      }
    },
    onSuccess: (_data, ids) => {
      toast.success(`Sync triggered for ${ids.length} source${ids.length > 1 ? "s" : ""}.`);
      queryClient.invalidateQueries({ queryKey: ["rule-sources"] });
      ids.forEach((id) =>
        queryClient.invalidateQueries({ queryKey: ["sync-runs", id] }),
      );
      clearSelection();
    },
    onError: (err: unknown) => {
      const msg =
        err instanceof Error ? err.message : "Bulk sync failed";
      toast.error(msg);
    },
  });

  const toggleEnabled = (source: RuleSourceRead) => {
    updateMutation.mutate({ id: source.id, data: { enabled: !source.enabled } });
  };

  const toggleAutoSync = (source: RuleSourceRead) => {
    updateMutation.mutate({ id: source.id, data: { auto_sync: !source.auto_sync } });
  };

  return (
    <div style={{ display: "grid", gap: 12 }}>
      <SettingsPanel />

      {/* ── Bulk action bar ─────────────────────────────────────── */}
      {someSelected && (
        <div
          className="sccap-card"
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            padding: "10px 16px",
            background:
              "linear-gradient(135deg, var(--primary-weak), var(--bg-elev))",
            border: "1px solid var(--primary-weak)",
          }}
        >
          <Icon.Check size={14} color="var(--primary)" />
          <span style={{ fontWeight: 600, fontSize: 13, color: "var(--primary)" }}>
            {selectedIds.size} selected
          </span>
          <div style={{ flex: 1 }} />
          <button
            className="sccap-btn sccap-btn-sm"
            onClick={() =>
              bulkUpdate.mutate({
                ids: [...selectedIds],
                data: { enabled: true },
              })
            }
            disabled={bulkUpdate.isPending}
          >
            Enable
          </button>
          <button
            className="sccap-btn sccap-btn-sm"
            onClick={() =>
              bulkUpdate.mutate({
                ids: [...selectedIds],
                data: { enabled: false },
              })
            }
            disabled={bulkUpdate.isPending}
          >
            Disable
          </button>
          <button
            className="sccap-btn sccap-btn-sm"
            onClick={() =>
              bulkUpdate.mutate({
                ids: [...selectedIds],
                data: { auto_sync: true },
              })
            }
            disabled={bulkUpdate.isPending}
          >
            Auto-sync On
          </button>
          <button
            className="sccap-btn sccap-btn-sm"
            onClick={() =>
              bulkUpdate.mutate({
                ids: [...selectedIds],
                data: { auto_sync: false },
              })
            }
            disabled={bulkUpdate.isPending}
          >
            Auto-sync Off
          </button>
          <button
            className="sccap-btn sccap-btn-primary sccap-btn-sm"
            onClick={() => bulkSync.mutate([...selectedIds])}
            disabled={bulkSync.isPending || bulkUpdate.isPending}
          >
            <Icon.Refresh size={12} /> Sync selected
          </button>
          <button
            className="sccap-btn sccap-btn-ghost sccap-btn-sm"
            onClick={clearSelection}
          >
            Clear
          </button>
        </div>
      )}

      {isLoading ? (
        <div
          className="sccap-card"
          style={{ padding: 40, textAlign: "center", color: "var(--fg-muted)" }}
        >
          Loading rule sources…
        </div>
      ) : sources.length === 0 ? (
        <SemgrepOnboardingWizard />
      ) : (
        <div className="sccap-card" style={{ padding: 0, overflow: "hidden" }}>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
              <thead>
                <tr style={{ background: "var(--bg-soft)", borderBottom: "1px solid var(--border)" }}>
                  <th style={{ padding: "10px 8px 10px 14px", width: 36 }}>
                    <input
                      type="checkbox"
                      checked={allSelected}
                      ref={(el) => {
                        if (el) el.indeterminate = someSelected && !allSelected;
                      }}
                      onChange={toggleSelectAll}
                      style={{ accentColor: "var(--primary)", cursor: "pointer" }}
                    />
                  </th>
                  {["Source", "License", "Last sync", "Rules", "Status", "Enabled", "Auto-sync", ""].map(
                    (h) => (
                      <th
                        key={h}
                        style={{
                          textAlign: "left",
                          padding: "10px 14px",
                          color: "var(--fg-muted)",
                          fontWeight: 500,
                          whiteSpace: "nowrap",
                          fontSize: 11.5,
                        }}
                      >
                        {h}
                      </th>
                    )
                  )}
                </tr>
              </thead>
              <tbody>
                {sources.map((s) => (
                  <tr
                    key={s.id}
                    style={{
                      borderBottom: "1px solid var(--border)",
                      verticalAlign: "middle",
                    }}
                  >
                    {/* Source */}
                    <td style={{ padding: "10px 8px 10px 14px" }}>
                      <input
                        type="checkbox"
                        checked={selectedIds.has(s.id)}
                        onChange={() => toggleSelectOne(s.id)}
                        style={{ accentColor: "var(--primary)" }}
                      />
                    </td>
                    <td style={{ padding: "10px 8px 10px 4px" }}>
                      <div style={{ fontWeight: 600, color: "var(--fg)" }}>{s.display_name}</div>
                      <div style={{ fontSize: 11, color: "var(--fg-subtle)", marginTop: 1 }}>
                        {s.slug}
                      </div>
                    </td>

                    {/* License */}
                    <td style={{ padding: "10px 14px" }}>
                      <span className="chip" style={{ fontSize: 11 }}>
                        {s.license_spdx}
                      </span>
                    </td>

                    {/* Last sync */}
                    <td style={{ padding: "10px 14px", whiteSpace: "nowrap", color: "var(--fg-muted)" }}>
                      {fmtDate(s.last_synced_at)}
                    </td>

                    {/* Rule count */}
                    <td style={{ padding: "10px 14px", color: "var(--fg)", fontWeight: 500 }}>
                      {s.rule_count.toLocaleString()}
                    </td>

                    {/* Status */}
                    <td style={{ padding: "10px 14px" }}>
                      <StatusBadge status={s.last_sync_status} />
                      {s.last_sync_status === "failed" && s.last_sync_error && (
                        <div
                          title={s.last_sync_error}
                          style={{ fontSize: 10.5, color: "var(--error)", marginTop: 2, maxWidth: 180 }}
                        >
                          {s.last_sync_error.slice(0, 60)}
                          {s.last_sync_error.length > 60 ? "…" : ""}
                        </div>
                      )}
                    </td>

                    {/* Enabled toggle */}
                    <td style={{ padding: "10px 14px" }}>
                      <label style={{ cursor: "pointer", display: "flex", alignItems: "center", gap: 6 }}>
                        <input
                          type="checkbox"
                          checked={s.enabled}
                          onChange={() => toggleEnabled(s)}
                          style={{ accentColor: "var(--primary)" }}
                          disabled={updateMutation.isPending}
                        />
                        <span style={{ fontSize: 11.5, color: "var(--fg-muted)" }}>
                          {s.enabled ? "On" : "Off"}
                        </span>
                      </label>
                    </td>

                    {/* Auto-sync toggle */}
                    <td style={{ padding: "10px 14px" }}>
                      <label style={{ cursor: "pointer", display: "flex", alignItems: "center", gap: 6 }}>
                        <input
                          type="checkbox"
                          checked={s.auto_sync}
                          onChange={() => toggleAutoSync(s)}
                          style={{ accentColor: "var(--primary)" }}
                          disabled={updateMutation.isPending}
                        />
                        <span style={{ fontSize: 11.5, color: "var(--fg-muted)" }}>
                          {s.auto_sync ? "On" : "Off"}
                        </span>
                      </label>
                    </td>

                    {/* Actions */}
                    <td style={{ padding: "10px 14px" }}>
                      <div style={{ display: "flex", gap: 4, justifyContent: "flex-end" }}>
                        <button
                          className="sccap-btn sccap-btn-icon sccap-btn-ghost sccap-btn-sm"
                          title="Edit"
                          onClick={() => setEditingSource(s)}
                        >
                          <Icon.Edit size={12} />
                        </button>
                        <button
                          className="sccap-btn sccap-btn-icon sccap-btn-ghost sccap-btn-sm"
                          title="Sync now"
                          onClick={() => syncMutation.mutate(s.id)}
                          disabled={s.last_sync_status === "running" || syncMutation.isPending}
                        >
                          <Icon.Refresh size={12} />
                        </button>
                        <button
                          className="sccap-btn sccap-btn-icon sccap-btn-ghost sccap-btn-sm"
                          title="View sync runs"
                          onClick={() => setRunsSource(s)}
                        >
                          <Icon.History size={12} />
                        </button>
                        <button
                          className="sccap-btn sccap-btn-icon sccap-btn-ghost sccap-btn-sm"
                          title="Delete"
                          onClick={() => setConfirmDeleteId(s.id)}
                        >
                          <Icon.Trash size={12} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <EditModal
        source={editingSource}
        onClose={() => setEditingSource(null)}
        onSave={(id, data) => updateMutation.mutate({ id, data })}
        saving={updateMutation.isPending}
      />

      <SyncRunsDrawer source={runsSource} onClose={() => setRunsSource(null)} />

      <Modal
        open={confirmDeleteId !== null}
        onClose={() => setConfirmDeleteId(null)}
        title="Delete rule source?"
        width={420}
        footer={
          <>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={() => setConfirmDeleteId(null)}
              disabled={deleteMutation.isPending}
            >
              Cancel
            </button>
            <button
              className="sccap-btn sccap-btn-danger sccap-btn-sm"
              onClick={() => {
                if (confirmDeleteId) deleteMutation.mutate(confirmDeleteId);
              }}
              disabled={deleteMutation.isPending}
            >
              {deleteMutation.isPending ? "Deleting…" : "Delete"}
            </button>
          </>
        }
      >
        <div style={{ color: "var(--fg-muted)", fontSize: 13, lineHeight: 1.6 }}>
          This will remove the rule source and all associated rules from SCCAP. Existing
          scan findings are not affected. This action cannot be undone.
        </div>
      </Modal>
    </div>
  );
};

export default SemgrepRulesTab;
