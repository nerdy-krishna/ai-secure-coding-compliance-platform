// secure-code-ui/src/pages/admin/SystemConfigTab.tsx
//
// Platform-wide system settings: log level, LLM optimization mode, CORS
// policy, and raw system_config CRUD. Ported to SCCAP primitives.
// Wiring is unchanged — the same systemConfigService + logService endpoints
// drive everything; only the presentation moves off antd.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useEffect, useState } from "react";
import apiClient from "../../shared/api/apiClient";
import { logService } from "../../shared/api/logService";
import { systemConfigService } from "../../shared/api/systemConfigService";
import type { JsonValue } from "../../shared/types/api";
import { useNotificationPermission } from "../../shared/hooks/useNotificationPermission";
import { Icon } from "../../shared/ui/Icon";
import { Modal } from "../../shared/ui/Modal";
import { useToast } from "../../shared/ui/Toast";

interface SystemConfig {
  key: string;
  value: JsonValue;
  description: string;
  is_secret: boolean;
  encrypted: boolean;
  created_at: string;
  updated_at: string;
}

type LogLevel = "DEBUG" | "INFO" | "WARNING" | "ERROR";
type LlmMode = "multi_provider" | "anthropic_optimized";

const LOG_LEVELS: { value: LogLevel; label: string }[] = [
  { value: "DEBUG", label: "DEBUG (verbose — includes prompts)" },
  { value: "INFO", label: "INFO (standard)" },
  { value: "WARNING", label: "WARNING (errors only)" },
  { value: "ERROR", label: "ERROR" },
];

const LLM_MODES: { value: LlmMode; label: string }[] = [
  { value: "anthropic_optimized", label: "Anthropic optimized (prompt caching + tuned variants)" },
  { value: "multi_provider", label: "Multi-provider (generic, no caching)" },
];

const emptyForm = {
  key: "",
  value: "",
  description: "",
  is_secret: false,
  encrypted: true,
};
type FormState = typeof emptyForm;

const SystemConfigTab: React.FC = () => {
  const toast = useToast();
  const queryClient = useQueryClient();
  const notif = useNotificationPermission();

  const [logLevel, setLogLevel] = useState<LogLevel>("INFO");
  const [pendingLogLevel, setPendingLogLevel] = useState<LogLevel>("INFO");
  const [llmMode, setLlmMode] = useState<LlmMode>("multi_provider");
  const [pendingLlmMode, setPendingLlmMode] = useState<LlmMode>("multi_provider");
  const [corsEnabled, setCorsEnabled] = useState(false);
  const [allowedOrigins, setAllowedOrigins] = useState<string[]>([]);
  const [originInput, setOriginInput] = useState("");

  const [loadingMeta, setLoadingMeta] = useState(true);
  const [savingLog, setSavingLog] = useState(false);
  const [savingMode, setSavingMode] = useState(false);
  const [savingCors, setSavingCors] = useState(false);

  // Session lifetime (M11: 1..168 hours, default 24h). null = use settings default.
  const [sessionHours, setSessionHours] = useState<number | null>(null);
  const [pendingSessionHours, setPendingSessionHours] = useState<string>("24");
  const [savingSession, setSavingSession] = useState(false);

  const [modalOpen, setModalOpen] = useState(false);
  const [editingKey, setEditingKey] = useState<string | null>(null);
  const [form, setForm] = useState<FormState>(emptyForm);
  const [confirmDeleteKey, setConfirmDeleteKey] = useState<string | null>(null);

  const { data: configs, isLoading } = useQuery({
    queryKey: ["system-configs"],
    queryFn: async () => {
      const res = await apiClient.get<SystemConfig[]>("/admin/system-config/");
      return res.data;
    },
  });

  const createMutation = useMutation({
    mutationFn: (data: {
      key: string;
      value: JsonValue;
      description?: string;
      is_secret?: boolean;
      encrypted?: boolean;
    }) => apiClient.put(`/admin/system-config/${data.key}`, data),
    onSuccess: () => {
      toast.success("Setting saved.");
      setModalOpen(false);
      setForm(emptyForm);
      queryClient.invalidateQueries({ queryKey: ["system-configs"] });
      loadMeta();
    },
    onError: () => toast.error("Failed to save setting."),
  });

  const deleteMutation = useMutation({
    mutationFn: (key: string) =>
      apiClient.delete(`/admin/system-config/${key}`),
    onSuccess: () => {
      toast.success("Setting deleted.");
      queryClient.invalidateQueries({ queryKey: ["system-configs"] });
    },
    onError: () => toast.error("Failed to delete setting."),
  });

  const loadMeta = async () => {
    setLoadingMeta(true);
    try {
      const [logRes, all] = await Promise.all([
        logService.getLogLevel().catch(() => null),
        systemConfigService.getAll().catch(() => []),
      ]);
      if (logRes?.level) {
        setLogLevel(logRes.level as LogLevel);
        setPendingLogLevel(logRes.level as LogLevel);
      }

      const corsCfg = all.find((c) => c.key === "security.cors_enabled");
      if (corsCfg?.value !== undefined)
        setCorsEnabled(Boolean(corsCfg.value));

      const originsCfg = all.find((c) => c.key === "security.allowed_origins");
      if (
        originsCfg?.value &&
        typeof originsCfg.value === "object" &&
        !Array.isArray(originsCfg.value) &&
        Array.isArray((originsCfg.value as { origins?: unknown }).origins)
      ) {
        setAllowedOrigins(
          (originsCfg.value as { origins: string[] }).origins,
        );
      }

      const modeCfg = all.find((c) => c.key === "llm.optimization_mode");
      if (modeCfg?.value) {
        const raw = modeCfg.value;
        const mode =
          typeof raw === "string" ? raw : (raw as { mode?: string }).mode;
        if (mode === "anthropic_optimized" || mode === "multi_provider") {
          setLlmMode(mode);
          setPendingLlmMode(mode);
        }
      }

      const slhCfg = all.find(
        (c) => c.key === "security.session_lifetime_hours",
      );
      if (
        slhCfg?.value &&
        typeof slhCfg.value === "object" &&
        !Array.isArray(slhCfg.value) &&
        typeof (slhCfg.value as { hours?: unknown }).hours === "number"
      ) {
        const h = (slhCfg.value as { hours: number }).hours;
        setSessionHours(h);
        setPendingSessionHours(String(h));
      }
    } finally {
      setLoadingMeta(false);
    }
  };

  useEffect(() => {
    loadMeta();
  }, []);

  const handleSaveLogLevel = async () => {
    if (
      pendingLogLevel === "DEBUG" &&
      !window.confirm(
        "DEBUG logs include full LLM prompts which can contain secrets and PII. Continue?",
      )
    ) {
      setPendingLogLevel(logLevel);
      return;
    }
    setSavingLog(true);
    try {
      await logService.setLogLevel(pendingLogLevel);
      setLogLevel(pendingLogLevel);
      toast.success(`Log level set to ${pendingLogLevel}.`);
    } catch {
      toast.error("Failed to update log level.");
      setPendingLogLevel(logLevel);
    } finally {
      setSavingLog(false);
    }
  };

  const handleSaveLlmMode = async () => {
    setSavingMode(true);
    try {
      await systemConfigService.update("llm.optimization_mode", {
        value: { mode: pendingLlmMode },
      });
      setLlmMode(pendingLlmMode);
      toast.success(
        pendingLlmMode === "anthropic_optimized"
          ? "Switched to Anthropic-optimized. Prompt caches invalidate on next scan."
          : "Switched to multi-provider generic mode.",
      );
      queryClient.invalidateQueries({ queryKey: ["system-configs"] });
    } catch {
      toast.error("Failed to update LLM optimization mode.");
      setPendingLlmMode(llmMode);
    } finally {
      setSavingMode(false);
    }
  };

  const handleSaveSessionHours = async () => {
    const parsed = parseInt(pendingSessionHours, 10);
    if (Number.isNaN(parsed) || parsed < 1 || parsed > 168) {
      toast.error("Session lifetime must be between 1 and 168 hours.");
      return;
    }
    setSavingSession(true);
    try {
      await systemConfigService.update("security.session_lifetime_hours", {
        value: { hours: parsed },
      });
      setSessionHours(parsed);
      toast.success(
        `Session lifetime set to ${parsed} hour${parsed === 1 ? "" : "s"}.`,
      );
      queryClient.invalidateQueries({ queryKey: ["system-configs"] });
    } catch {
      toast.error("Failed to update session lifetime.");
    } finally {
      setSavingSession(false);
    }
  };

  const handleCorsToggle = async (value: boolean) => {
    setSavingCors(true);
    const prev = corsEnabled;
    setCorsEnabled(value);
    try {
      await systemConfigService.update("security.cors_enabled", {
        value,
      });
      toast.success(`CORS ${value ? "enabled" : "disabled"}.`);
      queryClient.invalidateQueries({ queryKey: ["system-configs"] });
    } catch {
      setCorsEnabled(prev);
      toast.error("Failed to update CORS setting.");
    } finally {
      setSavingCors(false);
    }
  };

  const updateOrigins = async (next: string[]) => {
    setSavingCors(true);
    const prev = allowedOrigins;
    setAllowedOrigins(next);
    try {
      await systemConfigService.update("security.allowed_origins", {
        value: { origins: next },
      });
      toast.success("Allowed origins updated.");
      queryClient.invalidateQueries({ queryKey: ["system-configs"] });
    } catch {
      setAllowedOrigins(prev);
      toast.error("Failed to update allowed origins.");
    } finally {
      setSavingCors(false);
    }
  };

  const addOrigin = () => {
    const trimmed = originInput.trim();
    if (!trimmed) return;
    if (trimmed.length > 256) {
      toast.error("Origin must be 256 characters or fewer.");
      return;
    }
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(trimmed);
    } catch {
      toast.error("Enter a valid origin URL (e.g. https://example.com).");
      return;
    }
    if (parsedUrl.pathname !== "/" || parsedUrl.search || parsedUrl.hash) {
      toast.error("Origin must not include a path, query, or fragment.");
      return;
    }
    if (parsedUrl.protocol !== "https:" && parsedUrl.protocol !== "http:") {
      toast.error("Only https:// or http:// origins are allowed.");
      return;
    }
    if (
      parsedUrl.protocol === "http:" &&
      parsedUrl.hostname !== "localhost" &&
      parsedUrl.hostname !== "127.0.0.1"
    ) {
      toast.error(
        "Only https:// origins are allowed (localhost may use http://).",
      );
      return;
    }
    if (allowedOrigins.includes(trimmed)) {
      toast.warn("Origin already exists.");
      return;
    }
    updateOrigins([...allowedOrigins, trimmed]);
    setOriginInput("");
  };

  const openEdit = (cfg: SystemConfig) => {
    setEditingKey(cfg.key);
    setForm({
      key: cfg.key,
      // Secret values are write-only: show empty so the server retains the
      // existing value when the admin saves without entering a new one.
      value: cfg.is_secret
        ? ""
        : typeof cfg.value === "object"
          ? JSON.stringify(cfg.value, null, 2)
          : String(cfg.value ?? ""),
      description: cfg.description ?? "",
      is_secret: cfg.is_secret,
      encrypted: cfg.encrypted,
    });
    setModalOpen(true);
  };

  const openCreate = () => {
    setEditingKey(null);
    setForm(emptyForm);
    setModalOpen(true);
  };

  const onSave = () => {
    if (!editingKey && !/^[a-zA-Z0-9_.-]{1,128}$/.test(form.key)) {
      toast.error(
        "Key must be 1–128 characters and contain only letters, digits, underscores, dots, or hyphens.",
      );
      return;
    }
    if (form.description.length > 1024) {
      toast.error("Description must be 1 024 characters or fewer.");
      return;
    }
    if (form.is_secret && !form.encrypted) {
      toast.error("Secret values must be encrypted at rest.");
      return;
    }
    // For existing secret rows, an empty value means "keep the existing server value".
    const isSecretUnchanged = !!editingKey && form.is_secret && form.value === "";
    if (!isSecretUnchanged) {
      if (form.value.length > 65536) {
        toast.error("Value must be 65 536 characters or fewer.");
        return;
      }
      let parsed: JsonValue;
      try {
        parsed = JSON.parse(form.value) as JsonValue;
      } catch {
        toast.error("Invalid JSON for Value.");
        return;
      }
      createMutation.mutate({
        key: form.key,
        value: parsed,
        description: form.description,
        is_secret: form.is_secret,
        encrypted: form.encrypted,
      });
    } else {
      // Omit value so the server retains the existing secret.
      createMutation.mutate({
        key: form.key,
        description: form.description,
        is_secret: form.is_secret,
        encrypted: form.encrypted,
      } as Parameters<typeof createMutation.mutate>[0]);
    }
  };

  return (
    <div className="fade-in" style={{ display: "grid", gap: 20 }}>
      <div>
        <h1 style={{ color: "var(--fg)" }}>Platform settings</h1>
        <div style={{ color: "var(--fg-muted)", marginTop: 4 }}>
          Core system behavior, LLM mode, CORS, and raw config key/values.
        </div>
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: 16,
        }}
      >
        <SettingsCard
          title="System logs"
          description="Backend log verbosity. DEBUG includes full LLM prompts and responses."
        >
          <select
            className="sccap-input"
            value={pendingLogLevel}
            onChange={(e) => setPendingLogLevel(e.target.value as LogLevel)}
            disabled={savingLog || loadingMeta}
            style={{ maxWidth: 380 }}
          >
            {LOG_LEVELS.map((l) => (
              <option key={l.value} value={l.value}>
                {l.label}
              </option>
            ))}
          </select>
          {pendingLogLevel !== logLevel && (
            <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
              <button
                className="sccap-btn sccap-btn-primary sccap-btn-sm"
                onClick={handleSaveLogLevel}
                disabled={savingLog}
              >
                {savingLog ? "Saving…" : "Save"}
              </button>
              <button
                className="sccap-btn sccap-btn-sm"
                onClick={() => setPendingLogLevel(logLevel)}
                disabled={savingLog}
              >
                Cancel
              </button>
            </div>
          )}
        </SettingsCard>

        <SettingsCard
          title="LLM optimization mode"
          description="Anthropic-optimized enables prompt caching and tuned variants (needs an Anthropic model). Generic is portable across providers."
        >
          <select
            className="sccap-input"
            value={pendingLlmMode}
            onChange={(e) => setPendingLlmMode(e.target.value as LlmMode)}
            disabled={savingMode || loadingMeta}
            style={{ maxWidth: 380 }}
          >
            {LLM_MODES.map((m) => (
              <option key={m.value} value={m.value}>
                {m.label}
              </option>
            ))}
          </select>
          <div style={{ marginTop: 8, fontSize: 11.5, color: "var(--fg-subtle)" }}>
            Switching invalidates Anthropic prompt caches on the next scan.
          </div>
          {pendingLlmMode !== llmMode && (
            <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
              <button
                className="sccap-btn sccap-btn-primary sccap-btn-sm"
                onClick={handleSaveLlmMode}
                disabled={savingMode}
              >
                {savingMode ? "Saving…" : "Save"}
              </button>
              <button
                className="sccap-btn sccap-btn-sm"
                onClick={() => setPendingLlmMode(llmMode)}
                disabled={savingMode}
              >
                Cancel
              </button>
            </div>
          )}
        </SettingsCard>
      </div>

      <SettingsCard
        title="Session lifetime"
        description="Hard ceiling on how long a single login session lives before requiring re-authentication. Refresh-token rotation cannot extend a session past this absolute limit. Capped at 168 hours (7 days)."
      >
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <input
            type="number"
            className="sccap-input"
            min={1}
            max={168}
            step={1}
            value={pendingSessionHours}
            onChange={(e) => setPendingSessionHours(e.target.value)}
            disabled={savingSession || loadingMeta}
            style={{ maxWidth: 120 }}
          />
          <span style={{ fontSize: 13, color: "var(--fg-muted)" }}>hours</span>
          <button
            className="sccap-btn sccap-btn-primary sccap-btn-sm"
            onClick={handleSaveSessionHours}
            disabled={
              savingSession ||
              loadingMeta ||
              parseInt(pendingSessionHours, 10) === sessionHours
            }
          >
            {savingSession ? "Saving…" : "Save"}
          </button>
          {sessionHours !== null && (
            <span style={{ fontSize: 11.5, color: "var(--fg-subtle)" }}>
              currently {sessionHours} h
            </span>
          )}
        </div>
        <div
          style={{
            marginTop: 10,
            fontSize: 11.5,
            color: "var(--fg-subtle)",
          }}
        >
          Default 24 h. Lower = stronger compliance posture; higher = fewer
          re-logins.
        </div>
      </SettingsCard>

      <SettingsCard
        title="CORS configuration"
        description="Restrict API access to specific domains. When disabled, the default middleware policy applies."
      >
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div
            className={`sccap-switch ${corsEnabled ? "on" : ""}`}
            role="switch"
            aria-checked={corsEnabled}
            tabIndex={0}
            onClick={() => !savingCors && handleCorsToggle(!corsEnabled)}
            onKeyDown={(e) => {
              if ((e.key === " " || e.key === "Enter") && !savingCors) {
                e.preventDefault();
                handleCorsToggle(!corsEnabled);
              }
            }}
          />
          <span style={{ fontSize: 13, color: "var(--fg)" }}>
            {corsEnabled ? "CORS enforcement enabled" : "CORS enforcement disabled"}
          </span>
        </div>

        {corsEnabled && (
          <div
            style={{
              marginTop: 16,
              paddingTop: 14,
              borderTop: "1px solid var(--border)",
            }}
          >
            <div
              style={{
                fontSize: 11,
                color: "var(--fg-muted)",
                textTransform: "uppercase",
                letterSpacing: ".06em",
                marginBottom: 8,
              }}
            >
              Allowed origins
            </div>
            <div style={{ display: "flex", gap: 8, marginBottom: 10 }}>
              <input
                className="sccap-input"
                placeholder="https://my-domain.com"
                value={originInput}
                maxLength={256}
                onChange={(e) => setOriginInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    addOrigin();
                  }
                }}
                style={{ flex: 1, maxWidth: 420 }}
              />
              <button
                className="sccap-btn sccap-btn-primary sccap-btn-sm"
                onClick={addOrigin}
                disabled={savingCors || !originInput.trim()}
              >
                <Icon.Plus size={12} /> Add
              </button>
            </div>
            <div style={{ fontSize: 11, color: "var(--fg-subtle)", marginBottom: 8 }}>
              https:// only — http is rejected for non-loopback origins.
            </div>
            {allowedOrigins.length === 0 ? (
              <div style={{ fontSize: 12, color: "var(--fg-subtle)" }}>
                No origins yet. All cross-origin requests will be blocked.
              </div>
            ) : (
              <div
                style={{
                  display: "flex",
                  flexWrap: "wrap",
                  gap: 6,
                }}
              >
                {allowedOrigins.map((o) => (
                  <span
                    key={o}
                    className="chip"
                    style={{ paddingRight: 6 }}
                  >
                    <span className="mono" style={{ fontSize: 11 }}>
                      {o}
                    </span>
                    <button
                      aria-label={`Remove ${o}`}
                      onClick={() =>
                        updateOrigins(
                          allowedOrigins.filter((x) => x !== o),
                        )
                      }
                      style={{
                        border: "none",
                        background: "transparent",
                        color: "var(--fg-muted)",
                        cursor: "pointer",
                        padding: 0,
                        lineHeight: 1,
                      }}
                    >
                      <Icon.X size={11} />
                    </button>
                  </span>
                ))}
              </div>
            )}
          </div>
        )}
      </SettingsCard>

      <SettingsCard
        title="Desktop notifications"
        description="Receive a browser notification when a scan finishes, even if you've navigated away. Stored per browser."
      >
        {!notif.supported ? (
          <div style={{ fontSize: 13, color: "var(--fg-muted)" }}>
            Desktop notifications are not supported in this browser.
          </div>
        ) : notif.permission === "denied" ? (
          <div style={{ fontSize: 13, color: "var(--fg-muted)" }}>
            Notifications are <strong>blocked</strong> by your browser. Click the lock icon in the
            address bar and allow notifications for this site to re-enable.
          </div>
        ) : notif.permission === "granted" ? (
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
            <div style={{ fontSize: 13, color: "var(--fg)", fontWeight: 500 }}>Desktop notifications enabled</div>
            <button className="sccap-btn sccap-btn-sm" onClick={() => { notif.dismiss(); toast.info("Desktop notifications turned off."); }}>
              Disable
            </button>
          </div>
        ) : (
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
            <div style={{ fontSize: 13, color: "var(--fg)", fontWeight: 500 }}>Desktop notifications off</div>
            <button
              className="sccap-btn sccap-btn-primary sccap-btn-sm"
              onClick={async () => {
                const result = await notif.request();
                if (result === "granted") toast.success("Desktop notifications enabled.");
                else if (result === "denied") toast.warn("Blocked by browser — re-enable in site settings.");
              }}
            >
              <Icon.Bell size={12} /> Enable
            </button>
          </div>
        )}
      </SettingsCard>

      <div className="surface" style={{ padding: 0 }}>
        <div
          className="section-head"
          style={{ padding: "14px 18px 10px", marginBottom: 0 }}
        >
          <h3 style={{ margin: 0 }}>Raw system configuration</h3>
          <button
            className="sccap-btn sccap-btn-primary sccap-btn-sm"
            onClick={openCreate}
          >
            <Icon.Plus size={12} /> Add setting
          </button>
        </div>
        {isLoading ? (
          <div
            style={{
              padding: 40,
              textAlign: "center",
              color: "var(--fg-muted)",
            }}
          >
            Loading…
          </div>
        ) : !configs || configs.length === 0 ? (
          <div
            style={{
              padding: 40,
              textAlign: "center",
              color: "var(--fg-muted)",
            }}
          >
            No custom settings stored.
          </div>
        ) : (
          <table className="sccap-t">
            <thead>
              <tr>
                <th>Key</th>
                <th>Value</th>
                <th>Description</th>
                <th>Secret</th>
                <th style={{ width: 80 }} />
              </tr>
            </thead>
            <tbody>
              {configs.map((cfg) => (
                <tr key={cfg.key} style={{ cursor: "default" }}>
                  <td className="mono" style={{ fontWeight: 500 }}>
                    {cfg.key}
                  </td>
                  <td
                    className="mono"
                    style={{
                      fontSize: 12,
                      maxWidth: 320,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      color: "var(--fg-muted)",
                    }}
                  >
                    {cfg.is_secret
                      ? "••••••••"
                      : typeof cfg.value === "object"
                        ? JSON.stringify(cfg.value)
                        : String(cfg.value)}
                  </td>
                  <td style={{ color: "var(--fg-muted)", fontSize: 12.5 }}>
                    {cfg.description || ""}
                  </td>
                  <td>
                    {cfg.is_secret ? (
                      <span className="chip chip-medium">Secret</span>
                    ) : (
                      <span
                        className="chip"
                        style={{ color: "var(--fg-subtle)" }}
                      >
                        No
                      </span>
                    )}
                  </td>
                  <td>
                    <div style={{ display: "flex", gap: 4 }}>
                      <button
                        className="sccap-btn sccap-btn-icon sccap-btn-ghost"
                        aria-label="Edit"
                        onClick={() => openEdit(cfg)}
                      >
                        <Icon.Edit size={12} />
                      </button>
                      <button
                        className="sccap-btn sccap-btn-icon sccap-btn-ghost"
                        aria-label="Delete"
                        style={{ color: "var(--critical)" }}
                        onClick={() => setConfirmDeleteKey(cfg.key)}
                      >
                        <Icon.Trash size={12} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <Modal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        title={editingKey ? "Edit setting" : "Add setting"}
        width={640}
        footer={
          <>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={() => setModalOpen(false)}
              disabled={createMutation.isPending}
            >
              Cancel
            </button>
            <button
              className="sccap-btn sccap-btn-primary sccap-btn-sm"
              onClick={onSave}
              disabled={createMutation.isPending}
            >
              {createMutation.isPending ? "Saving…" : "Save"}
            </button>
          </>
        }
      >
        <div style={{ display: "grid", gap: 12 }}>
          <label style={{ display: "grid", gap: 4 }}>
            <span style={{ fontSize: 11, color: "var(--fg-muted)" }}>
              Key
            </span>
            <input
              className="sccap-input mono"
              placeholder="e.g. GLOBAL_ALERT_MESSAGE"
              value={form.key}
              maxLength={128}
              onChange={(e) => setForm({ ...form, key: e.target.value })}
              disabled={!!editingKey}
            />
          </label>
          <label style={{ display: "grid", gap: 4 }}>
            <span style={{ fontSize: 11, color: "var(--fg-muted)" }}>
              Value (JSON)
            </span>
            <textarea
              className="sccap-input mono"
              rows={6}
              placeholder={
                editingKey && form.is_secret
                  ? "Leave blank to keep the existing secret value."
                  : '{"message": "Maintenance mode"}'
              }
              value={form.value}
              onChange={(e) => setForm({ ...form, value: e.target.value })}
              style={{ fontSize: 12.5 }}
            />
          </label>
          <label style={{ display: "grid", gap: 4 }}>
            <span style={{ fontSize: 11, color: "var(--fg-muted)" }}>
              Description
            </span>
            <input
              className="sccap-input"
              placeholder="Short description"
              value={form.description}
              maxLength={1024}
              onChange={(e) =>
                setForm({ ...form, description: e.target.value })
              }
            />
          </label>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              marginTop: 4,
            }}
          >
            <div
              className={`sccap-switch ${form.is_secret ? "on" : ""}`}
              role="switch"
              aria-checked={form.is_secret}
              tabIndex={0}
              onClick={() => {
                const next = !form.is_secret;
                // Auto-enable encryption when marking as secret.
                setForm({ ...form, is_secret: next, encrypted: next ? true : form.encrypted });
              }}
              onKeyDown={(e) => {
                if (e.key === " " || e.key === "Enter") {
                  e.preventDefault();
                  const next = !form.is_secret;
                  setForm({ ...form, is_secret: next, encrypted: next ? true : form.encrypted });
                }
              }}
            />
            <span style={{ fontSize: 13, color: "var(--fg)" }}>
              Mark as secret (value hidden in UI)
            </span>
          </div>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              marginTop: 4,
            }}
          >
            <div
              className={`sccap-switch ${form.encrypted ? "on" : ""}`}
              role="switch"
              aria-checked={form.encrypted}
              tabIndex={0}
              onClick={() => setForm({ ...form, encrypted: !form.encrypted })}
              onKeyDown={(e) => {
                if (e.key === " " || e.key === "Enter") {
                  e.preventDefault();
                  setForm({ ...form, encrypted: !form.encrypted });
                }
              }}
            />
            <span style={{ fontSize: 13, color: "var(--fg)" }}>
              Encrypt at rest
            </span>
            {form.is_secret && !form.encrypted && (
              <span style={{ fontSize: 11.5, color: "var(--color-danger, #e53e3e)", marginLeft: 6 }}>
                Secret values must be encrypted.
              </span>
            )}
          </div>
        </div>
      </Modal>

      <Modal
        open={confirmDeleteKey !== null}
        onClose={() => setConfirmDeleteKey(null)}
        title="Delete setting?"
        width={420}
        footer={
          <>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={() => setConfirmDeleteKey(null)}
              disabled={deleteMutation.isPending}
            >
              Cancel
            </button>
            <button
              className="sccap-btn sccap-btn-danger sccap-btn-sm"
              onClick={() => {
                if (confirmDeleteKey) {
                  deleteMutation.mutate(confirmDeleteKey);
                  setConfirmDeleteKey(null);
                }
              }}
              disabled={deleteMutation.isPending}
            >
              {deleteMutation.isPending ? "Deleting…" : "Delete"}
            </button>
          </>
        }
      >
        <div style={{ color: "var(--fg-muted)", fontSize: 13 }}>
          Removing this key reverts any feature reading it to the code
          default. This is irreversible from the UI.
        </div>
      </Modal>
    </div>
  );
};

const SettingsCard: React.FC<{
  title: string;
  description: string;
  children: React.ReactNode;
}> = ({ title, description, children }) => (
  <div className="sccap-card">
    <div style={{ fontWeight: 600, color: "var(--fg)", marginBottom: 4 }}>
      {title}
    </div>
    <div
      style={{
        color: "var(--fg-muted)",
        fontSize: 12.5,
        marginBottom: 12,
        lineHeight: 1.5,
      }}
    >
      {description}
    </div>
    {children}
  </div>
);

export default SystemConfigTab;
