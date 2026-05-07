// secure-code-ui/src/pages/admin/AgentManagementPage.tsx
//
// Admin surface for the specialized AI security agents. CRUD wiring
// stays on agentService (/admin/agents/); presentation is ported to
// SCCAP primitives — card-grid plus a shared modal for create/edit.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AxiosError } from "axios";
import React, { useEffect, useState } from "react";
import { agentService } from "../../shared/api/agentService";
import type {
  AgentCreate,
  AgentRead,
  AgentUpdate,
} from "../../shared/types/api";
import { Icon } from "../../shared/ui/Icon";
import { Modal } from "../../shared/ui/Modal";
import { RestoreDefaultsButton } from "../../shared/ui/RestoreDefaultsButton";
import { useToast } from "../../shared/ui/Toast";

interface FormState {
  name: string;
  description: string;
  domain_query: string;
}

const EMPTY_FORM: FormState = { name: "", description: "", domain_query: "" };

const AgentManagementPage: React.FC = () => {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<AgentRead | null>(null);
  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);

  const { data: agents, isLoading, isError, error } = useQuery<
    AgentRead[],
    Error
  >({
    queryKey: ["agents"],
    queryFn: agentService.getAgents,
  });

  useEffect(() => {
    if (isError) {
      toast.error(`Failed to load agents: ${error.message}`);
    }
  }, [isError, error, toast]);

  useEffect(() => {
    if (editing) {
      setForm({
        name: editing.name,
        description: editing.description,
        domain_query:
          typeof editing.domain_query === "string"
            ? editing.domain_query
            : JSON.stringify(editing.domain_query, null, 2),
      });
      setModalOpen(true);
    }
  }, [editing]);

  const onApiError = (err: unknown, verb: string) => {
    const detail =
      err instanceof AxiosError
        ? (err.response?.data as { detail?: string })?.detail
        : "Unknown error";
    toast.error(`Failed to ${verb} agent: ${detail ?? "unknown error"}`);
  };

  const createMutation = useMutation({
    mutationFn: agentService.createAgent,
    onSuccess: () => {
      toast.success("Agent created.");
      queryClient.invalidateQueries({ queryKey: ["agents"] });
      closeModal();
    },
    onError: (err) => onApiError(err, "create"),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: AgentUpdate }) =>
      agentService.updateAgent(id, data),
    onSuccess: () => {
      toast.success("Agent updated.");
      queryClient.invalidateQueries({ queryKey: ["agents"] });
      closeModal();
    },
    onError: (err) => onApiError(err, "update"),
  });

  const deleteMutation = useMutation({
    mutationFn: agentService.deleteAgent,
    onSuccess: () => {
      toast.success("Agent deleted.");
      queryClient.invalidateQueries({ queryKey: ["agents"] });
    },
    onError: (err) => onApiError(err, "delete"),
  });

  const closeModal = () => {
    setModalOpen(false);
    setEditing(null);
    setForm(EMPTY_FORM);
  };

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name || !form.description || !form.domain_query) {
      toast.error("All fields are required.");
      return;
    }
    if (
      form.name.length > 128 ||
      form.description.length > 1024 ||
      form.domain_query.length > 4096
    ) {
      toast.error("One or more fields exceed the allowed length.");
      return;
    }
    // `domain_query` is stored server-side as an object; the admin UI
    // edits it as raw text. Try parsing JSON; fall back to the raw
    // string which the backend accepts as a free-text RAG query.
    let domainQuery: unknown = form.domain_query;
    try {
      domainQuery = JSON.parse(form.domain_query);
    } catch {
      // keep as string
    }
    const payload = {
      name: form.name,
      description: form.description,
      domain_query: domainQuery,
    };
    if (editing) {
      updateMutation.mutate({
        id: editing.id,
        data: payload as unknown as AgentUpdate,
      });
    } else {
      createMutation.mutate(payload as unknown as AgentCreate);
    }
  };

  const pending = createMutation.isPending || updateMutation.isPending;

  return (
    <div className="fade-in" style={{ display: "grid", gap: 16 }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-end",
          gap: 12,
        }}
      >
        <div>
          <h1 style={{ color: "var(--fg)" }}>AI agents</h1>
          <div style={{ color: "var(--fg-muted)", marginTop: 4 }}>
            Specialized analysis agents and their RAG retrieval queries.
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <RestoreDefaultsButton
            label="Agents"
            invalidateKeys={[["agents"], ["prompts"], ["frameworks"]]}
          />
          <button
            className="sccap-btn sccap-btn-primary"
            onClick={() => {
              setEditing(null);
              setForm(EMPTY_FORM);
              setModalOpen(true);
            }}
          >
            <Icon.Plus size={13} /> Create agent
          </button>
        </div>
      </div>

      {isLoading ? (
        <div
          className="sccap-card"
          style={{
            padding: 40,
            textAlign: "center",
            color: "var(--fg-muted)",
          }}
        >
          Loading agents…
        </div>
      ) : !agents || agents.length === 0 ? (
        <div
          className="sccap-card"
          style={{ padding: 60, textAlign: "center" }}
        >
          <div style={{ color: "var(--fg)", fontWeight: 500, marginBottom: 4 }}>
            No agents yet
          </div>
          <div style={{ color: "var(--fg-muted)", fontSize: 13 }}>
            Create your first specialized analysis agent.
          </div>
        </div>
      ) : (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(340px, 1fr))",
            gap: 14,
          }}
        >
          {agents.map((a) => (
            <div key={a.id} className="sccap-card">
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "flex-start",
                  marginBottom: 10,
                }}
              >
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 10,
                  }}
                >
                  <div
                    style={{
                      width: 36,
                      height: 36,
                      borderRadius: 9,
                      background: "var(--primary-weak)",
                      color: "var(--primary)",
                      display: "grid",
                      placeItems: "center",
                    }}
                  >
                    <Icon.Sparkle size={16} />
                  </div>
                  <div>
                    <div style={{ fontWeight: 600, color: "var(--fg)" }}>
                      {a.name}
                    </div>
                    <div
                      style={{ fontSize: 11, color: "var(--fg-subtle)" }}
                      className="mono"
                    >
                      {a.id.slice(0, 8)}
                    </div>
                  </div>
                </div>
                <div style={{ display: "flex", gap: 4 }}>
                  <button
                    className="sccap-btn sccap-btn-icon sccap-btn-ghost"
                    aria-label="Edit"
                    onClick={() => setEditing(a)}
                  >
                    <Icon.Edit size={13} />
                  </button>
                  <button
                    className="sccap-btn sccap-btn-icon sccap-btn-ghost"
                    aria-label="Delete"
                    style={{ color: "var(--critical)" }}
                    onClick={() => setConfirmDeleteId(a.id)}
                  >
                    <Icon.Trash size={13} />
                  </button>
                </div>
              </div>

              <div
                style={{
                  fontSize: 12.5,
                  color: "var(--fg-muted)",
                  lineHeight: 1.5,
                  marginBottom: 10,
                  minHeight: 36,
                }}
              >
                {a.description || <em>No description.</em>}
              </div>

              <div
                style={{
                  fontSize: 10.5,
                  color: "var(--fg-subtle)",
                  textTransform: "uppercase",
                  letterSpacing: ".06em",
                  marginBottom: 4,
                }}
              >
                RAG query
              </div>
              <div
                className="inset mono"
                style={{
                  padding: "8px 10px",
                  fontSize: 11.5,
                  maxHeight: 80,
                  overflow: "hidden",
                  color: "var(--fg-muted)",
                }}
              >
                {typeof a.domain_query === "string"
                  ? a.domain_query
                  : JSON.stringify(a.domain_query)}
              </div>
            </div>
          ))}
        </div>
      )}

      <Modal
        open={modalOpen}
        onClose={closeModal}
        title={editing ? "Edit agent" : "Create new agent"}
        width={640}
        footer={
          <>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={closeModal}
              disabled={pending}
            >
              Cancel
            </button>
            <button
              className="sccap-btn sccap-btn-primary sccap-btn-sm"
              onClick={onSubmit}
              disabled={pending}
            >
              {pending
                ? "Saving…"
                : editing
                  ? "Save changes"
                  : "Create agent"}
            </button>
          </>
        }
      >
        <form onSubmit={onSubmit} style={{ display: "grid", gap: 14 }}>
          <label style={{ display: "grid", gap: 6 }}>
            <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
              Agent name
            </span>
            <input
              className="sccap-input"
              placeholder="e.g. TerraformSecurityAgent"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              required
              autoFocus
              maxLength={128}
            />
          </label>
          <label style={{ display: "grid", gap: 6 }}>
            <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
              Description
            </span>
            <textarea
              className="sccap-input"
              rows={3}
              placeholder="What does this agent focus on?"
              value={form.description}
              onChange={(e) =>
                setForm({ ...form, description: e.target.value })
              }
              required
              maxLength={1024}
            />
          </label>
          <label style={{ display: "grid", gap: 6 }}>
            <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
              Domain query for RAG
            </span>
            <textarea
              className="sccap-input mono"
              rows={4}
              placeholder="Comma-separated keywords or JSON query spec…"
              value={form.domain_query}
              onChange={(e) =>
                setForm({ ...form, domain_query: e.target.value })
              }
              required
              maxLength={4096}
            />
          </label>
          <button type="submit" style={{ display: "none" }} />
        </form>
      </Modal>

      <Modal
        open={confirmDeleteId !== null}
        onClose={() => setConfirmDeleteId(null)}
        title="Delete agent?"
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
                if (confirmDeleteId) {
                  deleteMutation.mutate(confirmDeleteId);
                  setConfirmDeleteId(null);
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
          This removes the agent from framework mappings and future scans.
          Past scan results are unaffected.
        </div>
      </Modal>
    </div>
  );
};

export default AgentManagementPage;
