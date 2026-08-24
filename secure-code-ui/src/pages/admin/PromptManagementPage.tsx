// secure-code-ui/src/pages/admin/PromptManagementPage.tsx
//
// Prompt template management. Two-pane layout: left list of prompts
// grouped by agent; right a big editor textarea with template-type
// and variant selectors. CRUD wiring unchanged.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useEffect, useMemo, useState } from "react";
import { agentService } from "../../shared/api/agentService";
import { promptService } from "../../shared/api/promptService";
import type {
  AgentRead,
  PromptTemplateCreate,
  PromptTemplateRead,
  PromptTemplateUpdate,
} from "../../shared/types/api";
import { Icon } from "../../shared/ui/Icon";
import { RestoreDefaultsButton } from "../../shared/ui/RestoreDefaultsButton";
import { useToast } from "../../shared/ui/Toast";

const TEMPLATE_TYPES = ["QUICK_AUDIT", "DETAILED_REMEDIATION", "CHAT"];
const VARIANTS: { value: "generic" | "anthropic"; label: string }[] = [
  { value: "generic", label: "Generic (multi-provider)" },
  { value: "anthropic", label: "Anthropic optimized" },
];

const EMPTY_FORM = {
  id: null as string | null,
  name: "",
  template_type: TEMPLATE_TYPES[0],
  agent_name: "",
  variant: "generic" as "generic" | "anthropic",
  version: 1,
  template_text: "",
};
type FormState = typeof EMPTY_FORM;

const PromptManagementPage: React.FC = () => {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const { data: prompts = [], isLoading } = useQuery<
    PromptTemplateRead[],
    Error
  >({
    queryKey: ["prompts"],
    queryFn: promptService.getPrompts,
  });

  const { data: agents = [] } = useQuery<AgentRead[], Error>({
    queryKey: ["agents"],
    queryFn: agentService.getAgents,
  });

  useEffect(() => {
    if (!selectedId) {
      setForm(EMPTY_FORM);
      return;
    }
    const found = prompts.find((p) => p.id === selectedId);
    if (found) {
      setForm({
        id: found.id,
        name: found.name,
        template_type: found.template_type,
        agent_name: found.agent_name ?? "",
        variant: (found.variant === "anthropic" ? "anthropic" : "generic"),
        version: found.version,
        template_text: found.template_text,
      });
    }
  }, [selectedId, prompts]);

  const createMutation = useMutation({
    mutationFn: (data: PromptTemplateCreate) => promptService.createPrompt(data),
    onSuccess: (created) => {
      toast.success("Prompt template created.");
      queryClient.invalidateQueries({ queryKey: ["prompts"] });
      setSelectedId(created.id);
    },
    onError: (e: Error) => toast.error(`Create failed: ${e.message}`),
  });

  const updateMutation = useMutation({
    mutationFn: (data: { id: string; data: PromptTemplateUpdate }) =>
      promptService.updatePrompt(data.id, data.data),
    onSuccess: () => {
      toast.success("Prompt template saved.");
      queryClient.invalidateQueries({ queryKey: ["prompts"] });
    },
    onError: (e: Error) => toast.error(`Save failed: ${e.message}`),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => promptService.deletePrompt(id),
    onSuccess: () => {
      toast.success("Prompt template deleted.");
      queryClient.invalidateQueries({ queryKey: ["prompts"] });
      setSelectedId(null);
    },
    onError: (e: Error) => toast.error(`Delete failed: ${e.message}`),
  });

  const pending = createMutation.isPending || updateMutation.isPending;

  const groupedByAgent = useMemo(() => {
    const groups = new Map<string, PromptTemplateRead[]>();
    for (const p of prompts) {
      const key = p.agent_name ?? "(unassigned)";
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key)!.push(p);
    }
    return Array.from(groups.entries()).sort(([a], [b]) => a.localeCompare(b));
  }, [prompts]);

  const onSave = () => {
    if (!form.name || !form.template_text) {
      toast.error("Name and content are required.");
      return;
    }
    if (form.name.length > 200) {
      toast.error("Template name must be 200 characters or fewer.");
      return;
    }
    if (form.template_text.length > 32768) {
      toast.error("Template content must be 32 768 characters or fewer.");
      return;
    }
    if (
      !Number.isInteger(form.version) ||
      form.version < 1 ||
      form.version > 1000
    ) {
      toast.error("Version must be an integer between 1 and 1000.");
      return;
    }
    const payload = {
      name: form.name,
      template_type: form.template_type,
      agent_name: form.agent_name || null,
      variant: form.variant,
      version: form.version,
      template_text: form.template_text,
    };
    if (form.id) {
      updateMutation.mutate({ id: form.id, data: payload });
    } else {
      createMutation.mutate(payload);
    }
  };

  const onNew = () => {
    setSelectedId(null);
    setForm(EMPTY_FORM);
  };

  return (
    <div className="fade-in" style={{ display: "grid", gap: 16 }}>
      <div
        className="admin-page-heading"
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-end",
          gap: 12,
        }}
      >
        <div>
          <h1 style={{ color: "var(--fg)" }}>Prompt templates</h1>
          <div style={{ color: "var(--fg-muted)", marginTop: 4 }}>
            Per-agent prompts; generic and Anthropic-tuned variants with
            automatic fallback.
          </div>
        </div>
        <div className="admin-page-heading-actions" style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <RestoreDefaultsButton
            label="Prompts"
            invalidateKeys={[["prompts"], ["agents"], ["frameworks"]]}
          />
          <button className="sccap-btn sccap-btn-primary" onClick={onNew}>
            <Icon.Plus size={13} /> New template
          </button>
        </div>
      </div>

      <div
        className="prompt-management-layout"
        style={{
          display: "grid",
          gap: 16,
          alignItems: "start",
        }}
      >
        <div
          className="surface"
          style={{
            padding: 8,
            maxHeight: "72vh",
            overflowY: "auto",
          }}
        >
          {isLoading ? (
            <div
              style={{
                padding: 16,
                color: "var(--fg-muted)",
                fontSize: 12.5,
              }}
            >
              Loading…
            </div>
          ) : groupedByAgent.length === 0 ? (
            <div
              style={{
                padding: 16,
                color: "var(--fg-muted)",
                fontSize: 12.5,
              }}
            >
              No prompts yet. Create one to get started.
            </div>
          ) : (
            groupedByAgent.map(([agent, list]) => (
              <div key={agent} style={{ marginBottom: 10 }}>
                <div
                  style={{
                    fontSize: 10.5,
                    color: "var(--fg-subtle)",
                    textTransform: "uppercase",
                    letterSpacing: ".06em",
                    padding: "6px 10px 4px",
                  }}
                >
                  {agent}
                </div>
                {list.map((p) => {
                  const active = p.id === selectedId;
                  return (
                    <button
                      key={p.id}
                      onClick={() => setSelectedId(p.id)}
                      className="sccap-btn sccap-btn-ghost"
                      style={{
                        width: "100%",
                        justifyContent: "space-between",
                        padding: "8px 10px",
                        background: active
                          ? "var(--bg-soft)"
                          : "transparent",
                        color: active ? "var(--fg)" : "var(--fg-muted)",
                        fontSize: 12.5,
                      }}
                    >
                      <span
                        className="mono"
                        style={{
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                          flex: 1,
                          textAlign: "left",
                        }}
                      >
                        {p.name}
                      </span>
                      <span
                        className="chip"
                        style={{
                          fontSize: 10,
                          padding: "1px 7px",
                          background: "transparent",
                          color:
                            p.variant === "anthropic"
                              ? "var(--primary)"
                              : "var(--fg-subtle)",
                        }}
                      >
                        {p.variant === "anthropic" ? "AN" : "GN"} v{p.version}
                      </span>
                    </button>
                  );
                })}
              </div>
            ))
          )}
        </div>

        <div className="surface" style={{ padding: 18 }}>
          <div
            className="prompt-editor-heading"
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: 14,
              gap: 8,
            }}
          >
            <h3
              className="mono"
              style={{
                fontSize: 14,
                color: "var(--fg)",
                margin: 0,
                minWidth: 0,
                overflowWrap: "anywhere",
              }}
            >
              {form.id ? form.name : "New template"}
            </h3>
            <div style={{ display: "flex", gap: 6 }}>
              {form.id && (
                <button
                  className="sccap-btn sccap-btn-sm sccap-btn-danger"
                  onClick={() => setConfirmDelete(true)}
                  disabled={deleteMutation.isPending}
                >
                  <Icon.Trash size={12} /> Delete
                </button>
              )}
              <button
                className="sccap-btn sccap-btn-primary sccap-btn-sm"
                onClick={onSave}
                disabled={pending}
              >
                <Icon.Check size={12} /> {pending ? "Saving…" : "Save"}
              </button>
            </div>
          </div>

          <div
            className="settings-two-column"
            style={{
              display: "grid",
              gap: 10,
              marginBottom: 10,
            }}
          >
            <label style={{ display: "grid", gap: 4 }}>
              <span style={{ fontSize: 11, color: "var(--fg-muted)" }}>
                Name
              </span>
              <input
                className="sccap-input"
                placeholder="e.g. python.sqli.detailed_fix"
                value={form.name}
                maxLength={200}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
              />
            </label>
            <label style={{ display: "grid", gap: 4 }}>
              <span style={{ fontSize: 11, color: "var(--fg-muted)" }}>
                Associated agent
              </span>
              <select
                className="sccap-input"
                value={form.agent_name}
                onChange={(e) =>
                  setForm({ ...form, agent_name: e.target.value })
                }
              >
                <option value="">— none —</option>
                {agents.map((a) => (
                  <option key={a.id} value={a.name}>
                    {a.name}
                  </option>
                ))}
              </select>
            </label>
            <label style={{ display: "grid", gap: 4 }}>
              <span style={{ fontSize: 11, color: "var(--fg-muted)" }}>
                Template type
              </span>
              <select
                className="sccap-input"
                value={form.template_type}
                onChange={(e) =>
                  setForm({ ...form, template_type: e.target.value })
                }
              >
                {TEMPLATE_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </label>
            <label style={{ display: "grid", gap: 4 }}>
              <span style={{ fontSize: 11, color: "var(--fg-muted)" }}>
                Variant
              </span>
              <select
                className="sccap-input"
                value={form.variant}
                onChange={(e) =>
                  setForm({
                    ...form,
                    variant: e.target.value as "generic" | "anthropic",
                  })
                }
              >
                {VARIANTS.map((v) => (
                  <option key={v.value} value={v.value}>
                    {v.label}
                  </option>
                ))}
              </select>
            </label>
          </div>

          <label style={{ display: "grid", gap: 4 }}>
            <span style={{ fontSize: 11, color: "var(--fg-muted)" }}>
              Template content
            </span>
            <textarea
              className="sccap-input mono"
              rows={18}
              placeholder="Enter the full prompt template text…"
              value={form.template_text}
              maxLength={32768}
              onChange={(e) =>
                setForm({ ...form, template_text: e.target.value })
              }
              style={{ fontSize: 12.5, lineHeight: 1.5 }}
            />
          </label>
        </div>
      </div>

      {confirmDelete && (
        <div
          role="dialog"
          aria-modal="true"
          onClick={() => setConfirmDelete(false)}
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
              Delete prompt template?
            </div>
            <div
              style={{
                padding: 20,
                color: "var(--fg-muted)",
                fontSize: 13,
              }}
            >
              This removes {form.name}. If a matching variant exists the
              runtime will fall back to it; otherwise agents using this
              template will surface an error at scan time.
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
                onClick={() => setConfirmDelete(false)}
                disabled={deleteMutation.isPending}
              >
                Cancel
              </button>
              <button
                className="sccap-btn sccap-btn-danger sccap-btn-sm"
                onClick={() => {
                  if (form.id) {
                    deleteMutation.mutate(form.id);
                    setConfirmDelete(false);
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

export default PromptManagementPage;
