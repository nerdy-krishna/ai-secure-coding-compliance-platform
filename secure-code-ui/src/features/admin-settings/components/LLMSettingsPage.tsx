// secure-code-ui/src/features/admin-settings/components/LLMSettingsPage.tsx
//
// LLM provider configurations CRUD. Ported to SCCAP primitives; wiring
// and endpoints are unchanged.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AxiosError } from "axios";
import React, { useEffect, useRef, useState } from "react";
import {
  llmConfigService,
  type LLMConfigurationUpdate,
} from "../../../shared/api/llmConfigService";
import type {
  LLMConfiguration,
  LLMConfigurationCreate,
} from "../../../shared/types/api";
import { Icon } from "../../../shared/ui/Icon";
import { useToast } from "../../../shared/ui/Toast";

const LLM_PROVIDERS = [
  "openai",
  "google",
  "anthropic",
  "deepseek",
  "xai",
] as const;
type Provider = (typeof LLM_PROVIDERS)[number];

// SECURITY (V15.1.5 dangerous functionality): api_key carries third-party LLM provider secrets.
// The backend Fernet-encrypts at rest (see CLAUDE.md Repository conventions).
// Frontend stores the cleartext only in component state for the duration of the form session;
// on unmount the value is GC'd. Never log this field, never persist to localStorage.
interface FormState {
  name: string;
  provider: Provider;
  model_name: string;
  tokenizer: string;
  input_cost_per_million: string;
  output_cost_per_million: string;
  api_key: string;
}

const EMPTY_FORM: FormState = {
  name: "",
  provider: "anthropic",
  model_name: "",
  tokenizer: "",
  input_cost_per_million: "",
  output_cost_per_million: "",
  api_key: "",
};

function axiosDetail(err: unknown): string {
  const e = err as {
    response?: { status?: number; data?: { detail?: string | { msg: string }[] } };
    message?: string;
  };
  const status = e.response?.status ?? 0;
  const detail = e.response?.data?.detail;
  // Log verbose details for developers only; never surface raw backend internals in the UI.
  const verbose = Array.isArray(detail)
    ? detail.map((d) => d.msg).join(", ")
    : detail || e.message || "Unknown error";
  console.error("[LLMSettingsPage] backend error:", verbose);
  if (status >= 500) return "Server error — please retry.";
  if (status >= 400) return "Could not save the configuration.";
  return "An unexpected error occurred.";
}

function parseAsUTC(dateString?: string | null): Date | null {
  if (!dateString) return null;
  const normalized = /Z|[+-]\d{2}:\d{2}$/.test(dateString)
    ? dateString
    : `${dateString}Z`;
  const d = new Date(normalized);
  return isNaN(d.getTime()) ? null : d;
}

const LLMSettingsPage: React.FC = () => {
  const toast = useToast();
  const queryClient = useQueryClient();
  const formRef = useRef<HTMLDivElement | null>(null);
  const [editing, setEditing] = useState<LLMConfiguration | null>(null);
  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [providerFilter, setProviderFilter] = useState<Provider | "all">("all");

  const { data: llmConfigs, isLoading, isError, error } = useQuery<
    LLMConfiguration[],
    Error
  >({
    queryKey: ["llmConfigs"],
    queryFn: llmConfigService.getLlmConfigs,
  });

  useEffect(() => {
    if (isError) {
      toast.error(`Failed to load LLM configurations: ${error.message}`);
    }
  }, [isError, error, toast]);

  useEffect(() => {
    if (editing) {
      setForm({
        name: editing.name,
        provider: (LLM_PROVIDERS as readonly string[]).includes(editing.provider)
          ? (editing.provider as Provider)
          : "anthropic",
        model_name: editing.model_name,
        tokenizer: editing.tokenizer ?? "",
        input_cost_per_million: String(editing.input_cost_per_million ?? ""),
        output_cost_per_million: String(editing.output_cost_per_million ?? ""),
        api_key: "",
      });
      formRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [editing]);

  const onError = (err: AxiosError, verb: string) =>
    toast.error(`Failed to ${verb} configuration: ${axiosDetail(err)}`);

  const createMutation = useMutation<
    LLMConfiguration,
    AxiosError,
    LLMConfigurationCreate
  >({
    mutationFn: llmConfigService.createLlmConfig,
    onSuccess: () => {
      toast.success("LLM configuration created.");
      queryClient.invalidateQueries({ queryKey: ["llmConfigs"] });
      setForm(EMPTY_FORM);
    },
    onError: (err) => onError(err, "create"),
  });

  const updateMutation = useMutation<
    LLMConfiguration,
    AxiosError,
    { id: string; data: LLMConfigurationUpdate }
  >({
    mutationFn: ({ id, data }) => llmConfigService.updateLlmConfig(id, data),
    onSuccess: () => {
      toast.success("LLM configuration updated.");
      queryClient.invalidateQueries({ queryKey: ["llmConfigs"] });
      setEditing(null);
      setForm(EMPTY_FORM);
    },
    onError: (err) => onError(err, "update"),
  });

  const deleteMutation = useMutation<void, AxiosError, string>({
    mutationFn: llmConfigService.deleteLlmConfig,
    onSuccess: () => {
      toast.success("LLM configuration deleted.");
      queryClient.invalidateQueries({ queryKey: ["llmConfigs"] });
    },
    onError: (err) => onError(err, "delete"),
  });

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // Input/output cost fields are optional — leaving them blank (or zero)
    // lets the backend pull live pricing from LiteLLM's maintained map.
    // Only validate format; zero is a legal sentinel for "use LiteLLM".
    const input = form.input_cost_per_million === ""
      ? 0
      : Number(form.input_cost_per_million);
    const output = form.output_cost_per_million === ""
      ? 0
      : Number(form.output_cost_per_million);
    if (
      !form.name ||
      !form.provider ||
      !form.model_name ||
      isNaN(input) ||
      input < 0 ||
      isNaN(output) ||
      output < 0
    ) {
      toast.error("Please fill all required fields with valid values.");
      return;
    }
    // V2.2.1 / V2.3.2: enforce field length and cost upper-bound limits.
    if (
      form.name.length > 100 ||
      form.model_name.length > 200 ||
      (form.tokenizer && form.tokenizer.length > 100) ||
      input > 1000 ||
      output > 1000
    ) {
      toast.error("Field exceeds allowed length or cost > $1000/M tokens.");
      return;
    }
    // V2.2.1: provider allow-list check (defense in depth beyond <select>).
    if (!(LLM_PROVIDERS as readonly string[]).includes(form.provider)) {
      toast.error("Invalid provider.");
      return;
    }
    if (!editing && !form.api_key) {
      toast.error("API key is required for new configurations.");
      return;
    }

    const payload: LLMConfigurationCreate = {
      name: form.name,
      provider: form.provider,
      model_name: form.model_name,
      tokenizer: form.tokenizer || null,
      input_cost_per_million: input,
      output_cost_per_million: output,
      api_key: form.api_key,
    };
    if (editing) {
      // V15.3.3: explicit allowlist of mutable fields prevents mass-assignment bugs.
      const updatePayload: LLMConfigurationUpdate = {
        name: payload.name,
        tokenizer: payload.tokenizer,
        input_cost_per_million: payload.input_cost_per_million,
        output_cost_per_million: payload.output_cost_per_million,
        ...(form.api_key ? { api_key: payload.api_key } : {}),
      };
      updateMutation.mutate({ id: editing.id, data: updatePayload });
    } else {
      createMutation.mutate(payload);
    }
  };

  const isMutating = createMutation.isPending || updateMutation.isPending;

  const filtered = (llmConfigs ?? []).filter((c) =>
    providerFilter === "all" ? true : c.provider === providerFilter,
  );

  return (
    <div className="fade-in" style={{ display: "grid", gap: 16 }}>
      <div>
        <h1 style={{ color: "var(--fg)" }}>LLM configurations</h1>
        <div style={{ color: "var(--fg-muted)", marginTop: 4 }}>
          Models and API keys consumed by the scan and advisor workflows.
        </div>
      </div>

      <div className="surface" ref={formRef} style={{ padding: 22 }}>
        <h3 style={{ color: "var(--fg)", marginBottom: 4 }}>
          {editing ? `Edit: ${editing.name}` : "Create new LLM configuration"}
        </h3>
        <div
          style={{
            color: "var(--fg-muted)",
            fontSize: 12.5,
            marginBottom: 14,
          }}
        >
          {editing
            ? "Leave the API key blank to keep the existing secret."
            : "All three scan slots can share a single configuration."}
        </div>
        <form onSubmit={onSubmit} style={{ display: "grid", gap: 12 }}>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: 12,
            }}
          >
            <Field label="Name">
              <input
                className="sccap-input"
                placeholder="OpenAI GPT-4o Mini"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                required
              />
            </Field>
            <Field label="Provider">
              <select
                className="sccap-input"
                value={form.provider}
                onChange={(e) =>
                  setForm({ ...form, provider: e.target.value as Provider })
                }
                required
              >
                {LLM_PROVIDERS.map((p) => (
                  <option key={p} value={p}>
                    {p[0].toUpperCase() + p.slice(1)}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Model name">
              <input
                className="sccap-input mono"
                placeholder="claude-sonnet-4.5"
                value={form.model_name}
                onChange={(e) =>
                  setForm({ ...form, model_name: e.target.value })
                }
                required
              />
            </Field>
            <Field label="Tokenizer" hint="(optional, inferred)">
              <input
                className="sccap-input mono"
                placeholder="e.g. cl100k_base"
                value={form.tokenizer}
                onChange={(e) =>
                  setForm({ ...form, tokenizer: e.target.value })
                }
              />
            </Field>
            <Field label="Input cost ($ per 1M tokens)" hint="(optional)">
              <input
                className="sccap-input mono"
                type="number"
                step="0.01"
                min="0"
                placeholder="auto — LiteLLM map"
                value={form.input_cost_per_million}
                onChange={(e) =>
                  setForm({
                    ...form,
                    input_cost_per_million: e.target.value,
                  })
                }
              />
            </Field>
            <Field label="Output cost ($ per 1M tokens)" hint="(optional)">
              <input
                className="sccap-input mono"
                type="number"
                step="0.01"
                min="0"
                placeholder="auto — LiteLLM map"
                value={form.output_cost_per_million}
                onChange={(e) =>
                  setForm({
                    ...form,
                    output_cost_per_million: e.target.value,
                  })
                }
              />
            </Field>
          </div>
          <div
            style={{
              fontSize: 11.5,
              color: "var(--fg-subtle)",
              marginTop: -4,
            }}
          >
            Leave input/output cost blank to pull live pricing from LiteLLM's
            community-maintained model-price map. Override only for custom
            or enterprise endpoints that don't match a public model name.
          </div>
          <Field label="API key">
            <div style={{ fontSize: 11, color: "var(--fg-muted)", marginBottom: 4 }}>
              Stored encrypted at rest. Never echoed back. Leave blank on edit to keep the existing key.
            </div>
            <input
              className="sccap-input mono"
              type="password"
              placeholder={
                editing
                  ? "Leave blank to keep existing key"
                  : "sk-ant-…"
              }
              value={form.api_key}
              onChange={(e) => setForm({ ...form, api_key: e.target.value })}
              autoComplete="off"
              spellCheck={false}
            />
          </Field>

          <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
            <button
              type="submit"
              className="sccap-btn sccap-btn-primary"
              disabled={isMutating}
            >
              {editing ? <Icon.Edit size={13} /> : <Icon.Plus size={13} />}
              {isMutating
                ? "Saving…"
                : editing
                  ? "Update configuration"
                  : "Create configuration"}
            </button>
            {editing && (
              <button
                type="button"
                className="sccap-btn"
                onClick={() => {
                  setEditing(null);
                  setForm(EMPTY_FORM);
                }}
              >
                Cancel
              </button>
            )}
          </div>
        </form>
      </div>

      <div className="surface" style={{ padding: 0 }}>
        <div
          className="section-head"
          style={{ padding: "14px 18px 10px", marginBottom: 0 }}
        >
          <h3 style={{ margin: 0 }}>
            Existing configurations ({filtered.length})
          </h3>
          <select
            className="sccap-input"
            value={providerFilter}
            onChange={(e) =>
              setProviderFilter(e.target.value as Provider | "all")
            }
            style={{ width: 180, fontSize: 12.5 }}
          >
            <option value="all">All providers</option>
            {LLM_PROVIDERS.map((p) => (
              <option key={p} value={p}>
                {p[0].toUpperCase() + p.slice(1)}
              </option>
            ))}
          </select>
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
        ) : filtered.length === 0 ? (
          <div
            style={{
              padding: 40,
              textAlign: "center",
              color: "var(--fg-muted)",
            }}
          >
            No configurations match the current filter.
          </div>
        ) : (
          <table className="sccap-t">
            <thead>
              <tr>
                <th>Name</th>
                <th>Provider</th>
                <th>Model</th>
                <th>Tokenizer</th>
                <th>Input $/1M</th>
                <th>Output $/1M</th>
                <th>Created</th>
                <th style={{ width: 80 }} />
              </tr>
            </thead>
            <tbody>
              {filtered.map((cfg) => (
                <tr key={cfg.id} style={{ cursor: "default" }}>
                  <td style={{ fontWeight: 500 }}>{cfg.name}</td>
                  <td>
                    <span className="chip">{cfg.provider.toUpperCase()}</span>
                  </td>
                  <td className="mono" style={{ fontSize: 12 }}>
                    {cfg.model_name}
                  </td>
                  <td className="mono" style={{ fontSize: 11.5 }}>
                    {cfg.tokenizer ? (
                      cfg.tokenizer
                    ) : (
                      <span style={{ color: "var(--fg-subtle)" }}>auto</span>
                    )}
                  </td>
                  <td
                    className="mono"
                    style={{ fontVariantNumeric: "tabular-nums" }}
                  >
                    ${cfg.input_cost_per_million?.toFixed(6) ?? "0.00"}
                  </td>
                  <td
                    className="mono"
                    style={{ fontVariantNumeric: "tabular-nums" }}
                  >
                    ${cfg.output_cost_per_million?.toFixed(6) ?? "0.00"}
                  </td>
                  <td style={{ color: "var(--fg-muted)", fontSize: 12 }}>
                    {parseAsUTC(cfg.created_at)?.toLocaleDateString() ?? "—"}
                  </td>
                  <td>
                    <div style={{ display: "flex", gap: 4 }}>
                      <button
                        className="sccap-btn sccap-btn-icon sccap-btn-ghost"
                        aria-label="Edit"
                        onClick={() => setEditing(cfg)}
                        disabled={deleteMutation.isPending || updateMutation.isPending || editing?.id === cfg.id}
                      >
                        <Icon.Edit size={12} />
                      </button>
                      <button
                        className="sccap-btn sccap-btn-icon sccap-btn-ghost"
                        aria-label="Delete"
                        style={{ color: "var(--critical)" }}
                        onClick={() => setConfirmDeleteId(cfg.id)}
                        disabled={deleteMutation.isPending || updateMutation.isPending}
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

      {confirmDeleteId && (
        <div
          role="dialog"
          aria-modal="true"
          onClick={() => setConfirmDeleteId(null)}
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,.45)",
            display: "grid",
            placeItems: "center",
            zIndex: 1000,
          }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="surface"
            style={{ width: 420, maxWidth: "90%" }}
          >
            <div
              style={{
                padding: "16px 20px",
                borderBottom: "1px solid var(--border)",
                fontWeight: 600,
              }}
            >
              Delete LLM configuration?
            </div>
            <div
              style={{
                padding: 20,
                fontSize: 13,
                color: "var(--fg-muted)",
              }}
            >
              This cannot be undone. Active scans referencing this config
              will fail.
            </div>
            <div
              style={{
                borderTop: "1px solid var(--border)",
                padding: "12px 20px",
                display: "flex",
                justifyContent: "flex-end",
                gap: 8,
              }}
            >
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
                  if (confirmDeleteId) {
                    deleteMutation.mutate(confirmDeleteId);
                    setConfirmDeleteId(null);
                  }
                }}
                disabled={deleteMutation.isPending}
              >
                {deleteMutation.isPending ? "Deleting…" : "Delete"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

const Field: React.FC<{
  label: string;
  hint?: string;
  children: React.ReactNode;
}> = ({ label, hint, children }) => (
  <label style={{ display: "grid", gap: 6 }}>
    <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
      {label}
      {hint && (
        <span
          style={{
            marginLeft: 8,
            color: "var(--fg-subtle)",
            fontWeight: 400,
          }}
        >
          {hint}
        </span>
      )}
    </span>
    {children}
  </label>
);

export default LLMSettingsPage;
