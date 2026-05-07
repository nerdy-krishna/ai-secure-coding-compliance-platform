// secure-code-ui/src/pages/chat/SecurityAdvisorPage.tsx
//
// SCCAP Security Advisor. Port of the design bundle's Misc.jsx Advisor
// wired to chatService (/chat/sessions, /chat/sessions/:id/messages,
// /chat/sessions/:id/ask, /chat/sessions/:id DELETE).
//
// Layout (3 columns):
//   - Left rail: session list grouped by today / yesterday / older,
//     with a "New chat" button that opens a small modal to pick the
//     LLM config + framework scope.
//   - Center: message thread with user/AI bubbles, quick-reply chips,
//     and a textarea + send button at the bottom.
//   - Right rail: context stub (referenced findings / files / knowledge
//     sources). This is currently static text — wiring it to real scan
//     context per session needs a backend endpoint and will follow when
//     the Advisor grows a "drop finding into chat" affordance.

import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { Modal } from "../../shared/ui/Modal";
import { useToast } from "../../shared/ui/Toast";
import { chatService } from "../../shared/api/chatService";
import type { ChatSessionContext } from "../../shared/api/chatService";
import { frameworkService } from "../../shared/api/frameworkService";
import { llmConfigService } from "../../shared/api/llmConfigService";
import { Icon } from "../../shared/ui/Icon";
import type {
  ChatMessage,
  ChatSession,
  FrameworkRead,
  LLMConfiguration,
} from "../../shared/types/api";

function bucketSessions(sessions: ChatSession[]): Record<string, ChatSession[]> {
  const now = Date.now();
  const buckets: Record<string, ChatSession[]> = {
    Today: [],
    Yesterday: [],
    Older: [],
  };
  for (const s of sessions) {
    const t = new Date(s.created_at).getTime();
    const daysAgo = Math.floor((now - t) / (24 * 60 * 60 * 1000));
    if (daysAgo < 1) buckets.Today.push(s);
    else if (daysAgo < 2) buckets.Yesterday.push(s);
    else buckets.Older.push(s);
  }
  return buckets;
}

const QUICK_REPLIES = [
  "Explain this finding",
  "Map findings to SOC 2",
  "Summarize the scan",
];

const MAX_QUESTION_LEN = 8000;
const MAX_TITLE_LEN = 200;

const SecurityAdvisorPage: React.FC = () => {
  const queryClient = useQueryClient();
  const toast = useToast();
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  const [newChatOpen, setNewChatOpen] = useState(false);
  const [newTitle, setNewTitle] = useState("");
  const [newLlmId, setNewLlmId] = useState<string>("");
  const [newFrameworks, setNewFrameworks] = useState<string[]>([]);
  const threadRef = useRef<HTMLDivElement | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);
  const lastSendRef = useRef<number>(0);

  const handleCopyMessage = async (content: string) => {
    try {
      await navigator.clipboard.writeText(content);
      toast.info("Copied");
    } catch {
      toast.error("Copy failed");
    }
  };

  const handleEditMessage = (content: string) => {
    setDraft(content);
    // Defer focus + cursor placement until after the controlled input
    // has rendered the new value.
    requestAnimationFrame(() => {
      const ta = textareaRef.current;
      if (ta) {
        ta.focus();
        ta.setSelectionRange(content.length, content.length);
      }
    });
  };

  const { data: sessions = [], isLoading: loadingSessions } = useQuery<
    ChatSession[]
  >({
    queryKey: ["chatSessions"],
    queryFn: chatService.getSessions,
  });

  const { data: llmConfigs } = useQuery<LLMConfiguration[]>({
    queryKey: ["llmConfigs"],
    queryFn: llmConfigService.getLlmConfigs,
  });

  const { data: frameworks } = useQuery<FrameworkRead[]>({
    queryKey: ["frameworks"],
    queryFn: frameworkService.getFrameworks,
  });

  // Select the newest session whenever the list loads or changes if none
  // is currently selected.
  useEffect(() => {
    if (!activeSessionId && sessions.length > 0) {
      setActiveSessionId(sessions[0].id);
    }
  }, [sessions, activeSessionId]);

  const { data: messages = [], isLoading: loadingMessages } = useQuery<
    ChatMessage[]
  >({
    queryKey: ["chatMessages", activeSessionId],
    queryFn: () => chatService.getSessionMessages(activeSessionId!),
    enabled: !!activeSessionId,
  });

  const { data: sessionContext } = useQuery<ChatSessionContext>({
    queryKey: ["chatSessionContext", activeSessionId],
    queryFn: () => chatService.getSessionContext(activeSessionId!),
    enabled: !!activeSessionId,
  });

  // Auto-scroll to bottom when messages arrive.
  useEffect(() => {
    if (threadRef.current) {
      threadRef.current.scrollTop = threadRef.current.scrollHeight;
    }
  }, [messages]);

  const askMutation = useMutation({
    mutationFn: (question: string) =>
      chatService.askQuestion(activeSessionId!, question),
    // Optimistic update: append the user's message to the cache so the
    // bubble shows up instantly. The real (server-assigned) message
    // arrives via the invalidate-refetch in onSuccess and replaces this
    // temp one (negative id so it never collides with a real row).
    onMutate: async (question: string) => {
      const key = ["chatMessages", activeSessionId];
      await queryClient.cancelQueries({ queryKey: key });
      const previous = queryClient.getQueryData<ChatMessage[]>(key) ?? [];
      const optimistic: ChatMessage = {
        id: -Date.now(),
        role: "user",
        content: question,
        timestamp: new Date().toISOString(),
      };
      queryClient.setQueryData<ChatMessage[]>(key, [...previous, optimistic]);
      setDraft("");
      return { previous, key };
    },
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["chatMessages", activeSessionId],
      });
    },
    onError: (err: Error, _vars, ctx) => {
      if (process.env.NODE_ENV !== "production") console.error("[askMutation]", err);
      // Roll the optimistic append back so the failed message doesn't
      // linger in the thread without a response.
      if (ctx?.previous && ctx.key) {
        queryClient.setQueryData(ctx.key, ctx.previous);
      }
      toast.error("Ask failed");
    },
  });

  const createMutation = useMutation({
    mutationFn: () =>
      chatService.createSession({
        title: newTitle.trim() || "New conversation",
        llm_config_id: newLlmId,
        frameworks: newFrameworks,
      }),
    onSuccess: (created) => {
      queryClient.invalidateQueries({ queryKey: ["chatSessions"] });
      setActiveSessionId(created.id);
      setNewChatOpen(false);
      setNewTitle("");
      setNewFrameworks([]);
    },
    onError: (err: Error) => {
      if (process.env.NODE_ENV !== "production") console.error("[createMutation]", err);
      toast.error("Could not create session");
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (sessionId: string) => chatService.deleteSession(sessionId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["chatSessions"] });
      setActiveSessionId(null);
    },
    onError: (err: Error) => {
      if (process.env.NODE_ENV !== "production") console.error("[deleteMutation]", err);
      toast.error("Delete failed");
    },
  });

  const buckets = useMemo(() => bucketSessions(sessions), [sessions]);
  const activeSession =
    sessions.find((s) => s.id === activeSessionId) ?? null;

  const canSend =
    !!activeSessionId &&
    draft.trim().length > 0 &&
    draft.trim().length <= MAX_QUESTION_LEN &&
    !askMutation.isPending;

  const handleSend = () => {
    if (!canSend) return;
    if (draft.trim().length > MAX_QUESTION_LEN) {
      toast.error(`Question exceeds the ${MAX_QUESTION_LEN}-character limit.`);
      return;
    }
    const now = Date.now();
    if (now - lastSendRef.current < 1500) {
      toast.error("Please wait a moment between questions.");
      return;
    }
    lastSendRef.current = now;
    askMutation.mutate(draft.trim());
  };

  const openNewChat = () => {
    setNewTitle("");
    setNewLlmId(llmConfigs?.[0]?.id ?? "");
    setNewFrameworks([]);
    setNewChatOpen(true);
  };

  return (
    <div className="fade-in" style={{ display: "grid", gap: 12 }}>
      <div>
        <h1 style={{ color: "var(--fg)" }}>Security Advisor</h1>
        <div style={{ color: "var(--fg-muted)", marginTop: 4, fontSize: 13 }}>
          AI-powered security assistant with framework context.
        </div>
      </div>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "240px 1fr 280px",
          gap: 16,
          height: "calc(100vh - 170px)",
        }}
      >
      {/* Sessions rail */}
      <div
        className="surface"
        style={{
          padding: 10,
          display: "flex",
          flexDirection: "column",
          gap: 4,
          overflow: "hidden",
        }}
      >
        <button
          className="sccap-btn sccap-btn-primary"
          style={{ margin: 6 }}
          onClick={openNewChat}
        >
          <Icon.Plus size={12} /> New chat
        </button>
        <div style={{ overflow: "auto", flex: 1 }}>
          {loadingSessions && (
            <div
              style={{
                padding: "20px 10px",
                color: "var(--fg-subtle)",
                fontSize: 12,
              }}
            >
              Loading…
            </div>
          )}
          {!loadingSessions && sessions.length === 0 && (
            <div
              style={{
                padding: "20px 10px",
                color: "var(--fg-subtle)",
                fontSize: 12,
              }}
            >
              No chats yet — click <b>New chat</b> to start one.
            </div>
          )}
          {(["Today", "Yesterday", "Older"] as const).map((k) => {
            const list = buckets[k];
            if (!list.length) return null;
            return (
              <div key={k}>
                <div
                  style={{
                    fontSize: 10.5,
                    color: "var(--fg-subtle)",
                    textTransform: "uppercase",
                    letterSpacing: ".06em",
                    padding: "10px 10px 6px",
                  }}
                >
                  {k}
                </div>
                {list.map((s) => {
                  const active = s.id === activeSessionId;
                  return (
                    <div
                      key={s.id}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 6,
                      }}
                    >
                      <button
                        className="sccap-btn sccap-btn-ghost"
                        style={{
                          flex: 1,
                          justifyContent: "flex-start",
                          padding: "8px 10px",
                          fontSize: 12.5,
                          background: active
                            ? "var(--bg-soft)"
                            : "transparent",
                          color: active ? "var(--fg)" : "var(--fg-muted)",
                          overflow: "hidden",
                          textAlign: "left",
                        }}
                        onClick={() => setActiveSessionId(s.id)}
                      >
                        <Icon.Chat size={12} />
                        <span
                          style={{
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                            flex: 1,
                          }}
                        >
                          {s.title}
                        </span>
                      </button>
                      {active && (
                        <button
                          className="sccap-btn sccap-btn-icon sccap-btn-ghost"
                          onClick={() => deleteMutation.mutate(s.id)}
                          title="Delete session"
                          style={{ padding: 4, color: "var(--critical)" }}
                          aria-label="Delete session"
                        >
                          <Icon.Trash size={12} />
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>
            );
          })}
        </div>
      </div>

      {/* Thread */}
      <div
        className="surface"
        style={{
          display: "flex",
          flexDirection: "column",
          overflow: "hidden",
        }}
      >
        <div
          style={{
            padding: "14px 20px",
            borderBottom: "1px solid var(--border)",
            display: "flex",
            alignItems: "center",
            gap: 10,
          }}
        >
          <div
            style={{
              width: 28,
              height: 28,
              borderRadius: 8,
              background: "var(--primary)",
              color: "var(--primary-ink)",
              display: "grid",
              placeItems: "center",
            }}
          >
            <Icon.Sparkle size={14} />
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 600, color: "var(--fg)" }}>
              {activeSession?.title ?? "Security Advisor"}
            </div>
            <div style={{ fontSize: 11.5, color: "var(--fg-muted)" }}>
              {activeSession
                ? `${activeSession.frameworks?.length ?? 0} framework${
                    activeSession.frameworks?.length === 1 ? "" : "s"
                  } in scope`
                : "Pick or start a conversation"}
            </div>
          </div>
          <span
            className="chip chip-success"
            style={{ marginLeft: "auto" }}
          >
            <span
              className="dot"
              style={{ background: "currentColor" }}
            />{" "}
            online
          </span>
        </div>

        <div
          ref={threadRef}
          style={{
            flex: 1,
            overflow: "auto",
            padding: 24,
            display: "flex",
            flexDirection: "column",
            gap: 18,
          }}
        >
          {!activeSessionId ? (
            <div
              style={{
                color: "var(--fg-muted)",
                textAlign: "center",
                padding: 40,
              }}
            >
              Select or start a conversation to begin.
            </div>
          ) : loadingMessages ? (
            <div
              style={{
                color: "var(--fg-muted)",
                textAlign: "center",
                padding: 40,
              }}
            >
              Loading messages…
            </div>
          ) : messages.length === 0 ? (
            <div
              style={{
                color: "var(--fg-muted)",
                textAlign: "center",
                padding: 40,
              }}
            >
              New conversation — ask the advisor anything about a finding,
              fix, or framework gap.
            </div>
          ) : (
            messages.map((m) => {
              const isUser = m.role === "user";
              return (
                <div
                  key={m.id}
                  style={{
                    display: "flex",
                    gap: 12,
                    alignItems: "flex-start",
                    justifyContent: isUser ? "flex-end" : "flex-start",
                  }}
                >
                  {!isUser && (
                    <div
                      style={{
                        width: 28,
                        height: 28,
                        borderRadius: 8,
                        background: "var(--primary)",
                        color: "var(--primary-ink)",
                        display: "grid",
                        placeItems: "center",
                        flex: "none",
                      }}
                    >
                      <Icon.Sparkle size={13} />
                    </div>
                  )}
                  <div
                    style={{
                      maxWidth: "70%",
                      display: "flex",
                      flexDirection: "column",
                      alignItems: isUser ? "flex-end" : "flex-start",
                      gap: 4,
                    }}
                  >
                    <div
                      style={{
                        padding: "10px 14px",
                        borderRadius: isUser
                          ? "14px 14px 4px 14px"
                          : "14px 14px 14px 4px",
                        background: isUser
                          ? "var(--primary)"
                          : "var(--bg-soft)",
                        color: isUser ? "var(--primary-ink)" : "var(--fg)",
                        fontSize: 13.5,
                        lineHeight: 1.55,
                        whiteSpace: "pre-wrap",
                        overflowWrap: "break-word",
                        wordBreak: "break-word",
                      }}
                    >
                      {m.content}
                    </div>
                    <div
                      style={{
                        display: "flex",
                        gap: 4,
                        opacity: 0.75,
                      }}
                    >
                      <button
                        className="sccap-btn sccap-btn-icon sccap-btn-ghost"
                        title="Copy message"
                        aria-label="Copy message"
                        onClick={() => handleCopyMessage(m.content)}
                        style={{ padding: 4 }}
                      >
                        <Icon.Copy size={12} />
                      </button>
                      {isUser && (
                        <button
                          className="sccap-btn sccap-btn-icon sccap-btn-ghost"
                          title="Edit and resend"
                          aria-label="Edit and resend"
                          onClick={() => handleEditMessage(m.content)}
                          disabled={askMutation.isPending}
                          style={{ padding: 4 }}
                        >
                          <Icon.Edit size={12} />
                        </button>
                      )}
                    </div>
                  </div>
                  {isUser && (
                    <div
                      style={{
                        width: 28,
                        height: 28,
                        borderRadius: 8,
                        background: "var(--bg-soft)",
                        color: "var(--fg-muted)",
                        display: "grid",
                        placeItems: "center",
                        flex: "none",
                        fontSize: 11,
                        fontWeight: 600,
                      }}
                    >
                      <Icon.User size={14} />
                    </div>
                  )}
                </div>
              );
            })
          )}
          {askMutation.isPending && (
            <div
              style={{
                display: "flex",
                gap: 12,
                alignItems: "center",
                color: "var(--fg-muted)",
                fontSize: 12.5,
              }}
            >
              <div
                className="sccap-spin"
                style={{
                  width: 12,
                  height: 12,
                  border: "2px solid var(--primary)",
                  borderTopColor: "transparent",
                  borderRadius: "50%",
                }}
              />
              Advisor is thinking…
            </div>
          )}
        </div>

        <div
          style={{
            padding: 14,
            borderTop: "1px solid var(--border)",
          }}
        >
          <div
            style={{
              display: "flex",
              gap: 6,
              marginBottom: 8,
              flexWrap: "wrap",
            }}
          >
            {QUICK_REPLIES.map((s) => (
              <button
                key={s}
                className="sccap-btn sccap-btn-sm"
                onClick={() => setDraft(s)}
                disabled={!activeSessionId}
                style={{ fontSize: 11.5 }}
              >
                {s}
              </button>
            ))}
          </div>
          <div
            style={{ display: "flex", gap: 8, alignItems: "flex-end" }}
          >
            <textarea
              ref={textareaRef}
              className="sccap-textarea"
              rows={2}
              placeholder={
                activeSessionId
                  ? "Ask about a finding, fix, or compliance gap…"
                  : "Start a chat to enable the advisor."
              }
              value={draft}
              maxLength={MAX_QUESTION_LEN}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  handleSend();
                }
              }}
              disabled={!activeSessionId || askMutation.isPending}
              style={{ resize: "none" }}
            />
            <button
              className="sccap-btn sccap-btn-primary"
              style={{ height: 38 }}
              onClick={handleSend}
              disabled={!canSend}
              aria-label="Send"
            >
              <Icon.Send size={13} />
            </button>
          </div>
        </div>
      </div>

      {/* Context rail */}
      <div className="surface" style={{ padding: 16, overflow: "auto" }}>
        <h4 style={{ marginBottom: 10, color: "var(--fg)" }}>Context</h4>
        {activeSession ? (
          <>
            <RailSection label="Knowledge sources">
              {sessionContext?.knowledge_sources.length ? (
                sessionContext.knowledge_sources.map((k) => (
                  <div
                    key={`${k.type}-${k.name}`}
                    className="inset"
                    style={{
                      padding: "8px 10px",
                      fontSize: 12,
                      display: "flex",
                      justifyContent: "space-between",
                      gap: 8,
                    }}
                  >
                    <span>{k.name}</span>
                    <span style={{ color: "var(--fg-subtle)" }}>{k.type}</span>
                  </div>
                ))
              ) : (
                <RailEmpty text="No frameworks — advisor answers against the general knowledge base." />
              )}
            </RailSection>

            <RailSection label="Referenced findings">
              {sessionContext?.referenced_findings.length ? (
                sessionContext.referenced_findings.map((f) => (
                  <div
                    key={f.id}
                    className="inset"
                    style={{
                      padding: "8px 10px",
                      fontSize: 12,
                      display: "flex",
                      gap: 8,
                      alignItems: "center",
                    }}
                  >
                    <span
                      style={{
                        width: 8,
                        height: 8,
                        borderRadius: 2,
                        background: sevColor(f.severity),
                        flexShrink: 0,
                      }}
                    />
                    <span
                      style={{
                        flex: 1,
                        minWidth: 0,
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                      }}
                      title={f.title}
                    >
                      {f.title}
                    </span>
                  </div>
                ))
              ) : (
                <RailEmpty
                  text={
                    activeSession.project_id
                      ? "No open findings on the linked project yet."
                      : "Link this session to a project to surface findings."
                  }
                />
              )}
            </RailSection>

            <RailSection label="Referenced files">
              {sessionContext?.referenced_files.length ? (
                sessionContext.referenced_files.map((file) => (
                  <div
                    key={file.path}
                    className="inset"
                    style={{
                      padding: "6px 10px",
                      fontSize: 11.5,
                      fontFamily: "var(--font-mono)",
                      color: "var(--fg-muted)",
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                    title={file.path}
                  >
                    {file.path}
                  </div>
                ))
              ) : (
                <RailEmpty text="No file paths yet — ask about a finding to surface its file." />
              )}
            </RailSection>

            <div
              style={{
                fontSize: 11,
                color: "var(--fg-subtle)",
                fontFamily: "var(--font-mono)",
                marginTop: 8,
              }}
            >
              {activeSession.id.slice(0, 12)}… · created{" "}
              {new Date(activeSession.created_at).toLocaleString(undefined, {
                dateStyle: "medium",
                timeStyle: "short",
              })}
            </div>
          </>
        ) : (
          <div style={{ color: "var(--fg-muted)", fontSize: 12.5 }}>
            Pick a conversation to see its scope.
          </div>
        )}
      </div>

      <Modal
        open={newChatOpen}
        onClose={() => setNewChatOpen(false)}
        title="New conversation"
        footer={
          <>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={() => setNewChatOpen(false)}
              disabled={createMutation.isPending}
            >
              Cancel
            </button>
            <button
              className="sccap-btn sccap-btn-primary sccap-btn-sm"
              onClick={() => createMutation.mutate()}
              disabled={
                !newLlmId || !newTitle.trim() || createMutation.isPending
              }
            >
              {createMutation.isPending ? "Creating…" : "Create"}
            </button>
          </>
        }
      >
        <div style={{ display: "grid", gap: 14 }}>
          <label style={{ display: "grid", gap: 6 }}>
            <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
              Title
            </span>
            <input
              className="sccap-input"
              value={newTitle}
              maxLength={MAX_TITLE_LEN}
              onChange={(e) => setNewTitle(e.target.value)}
              placeholder="e.g., SQL injection walk-through"
              autoFocus
            />
          </label>
          <label style={{ display: "grid", gap: 6 }}>
            <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>LLM</span>
            <select
              className="sccap-input"
              value={newLlmId}
              onChange={(e) => setNewLlmId(e.target.value)}
            >
              <option value="">Select LLM</option>
              {llmConfigs?.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name} · {c.provider}/{c.model_name}
                </option>
              ))}
            </select>
          </label>
          <div style={{ display: "grid", gap: 6 }}>
            <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
              Frameworks in scope
            </span>
            {frameworks?.length ? (
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {frameworks.map((f) => {
                  const selected = newFrameworks.includes(f.name);
                  return (
                    <button
                      type="button"
                      key={f.id}
                      className="chip"
                      onClick={() =>
                        setNewFrameworks((prev) =>
                          selected
                            ? prev.filter((x) => x !== f.name)
                            : [...prev, f.name],
                        )
                      }
                      style={{
                        cursor: "pointer",
                        background: selected
                          ? "var(--primary-weak)"
                          : "transparent",
                        color: selected ? "var(--primary)" : "var(--fg-muted)",
                        border: selected
                          ? "1px solid var(--primary)"
                          : "1px solid var(--border)",
                      }}
                    >
                      {selected && <Icon.Check size={10} />} {f.name}
                    </button>
                  );
                })}
              </div>
            ) : (
              <div style={{ fontSize: 12, color: "var(--fg-subtle)" }}>
                No frameworks configured.
              </div>
            )}
          </div>
        </div>
      </Modal>
      </div>
    </div>
  );
};

const RailSection: React.FC<{
  label: string;
  children: React.ReactNode;
}> = ({ label, children }) => (
  <div style={{ marginBottom: 16 }}>
    <div
      style={{
        fontSize: 12,
        color: "var(--fg-muted)",
        marginBottom: 6,
      }}
    >
      {label}
    </div>
    <div style={{ display: "grid", gap: 6 }}>{children}</div>
  </div>
);

const RailEmpty: React.FC<{ text: string }> = ({ text }) => (
  <div style={{ fontSize: 12, color: "var(--fg-subtle)" }}>{text}</div>
);

function sevColor(sev: string | null | undefined): string {
  const s = (sev ?? "").toLowerCase();
  if (s === "critical") return "var(--critical)";
  if (s === "high") return "var(--high)";
  if (s === "medium") return "var(--medium)";
  if (s === "low") return "var(--low)";
  return "var(--info)";
}

export default SecurityAdvisorPage;
