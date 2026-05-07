// secure-code-ui/src/pages/analysis/LlmLogViewerPage.tsx
//
// SCCAP LLM cost + interaction viewer. Ported off antd Layout/Menu/Table
// onto SCCAP primitives (card grid + rail nav + expandable rows).

import { useQuery } from "@tanstack/react-query";
import React, { useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { scanService } from "../../shared/api/scanService";
import type { LLMInteractionResponse } from "../../shared/types/api";
import { useAuth } from "../../shared/hooks/useAuth";
import { redactSensitive } from "../../shared/lib/redact";
import { Icon } from "../../shared/ui/Icon";
import { PageHeader } from "../../shared/ui/PageHeader";

const INTERNAL_ERROR_INDICATORS = [
  "traceback",
  "at line",
  "sql:",
  "sqlalchemy",
  "file \"",
  "exception",
  "stacktrace",
  "stack trace",
];

/** Sanitize a backend error string for non-superuser display. */
function sanitizeErrorMessage(raw: string): string | null {
  const lower = raw.toLowerCase();
  const looksLikeInternals = INTERNAL_ERROR_INDICATORS.some((indicator) =>
    lower.includes(indicator),
  );
  if (looksLikeInternals) return null; // caller renders a generic message
  // Truncate to first sentence or 200 chars, whichever is shorter.
  const firstSentenceEnd = raw.search(/[.!?]\s/);
  const truncated =
    firstSentenceEnd > 0 && firstSentenceEnd < 200
      ? raw.slice(0, firstSentenceEnd + 1)
      : raw.slice(0, 200);
  return truncated !== raw ? `${truncated}…` : truncated;
}

const LlmLogViewerPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const { user } = useAuth();
  const isSuperuser = user?.is_superuser === true;
  const [selectedFilePath, setSelectedFilePath] = useState<string>("All Files");
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [showTechDetails, setShowTechDetails] = useState<Record<number, boolean>>({});

  const { data: interactions = [], isLoading, isError, error } = useQuery<
    LLMInteractionResponse[],
    Error
  >({
    queryKey: ["llmInteractionsForScan", scanId],
    queryFn: () => {
      if (!scanId) throw new Error("Scan ID is missing");
      return scanService.getLlmInteractionsForScan(scanId);
    },
    enabled: !!scanId,
  });

  const overallStats = useMemo(() => {
    const acc = {
      totalCost: 0,
      totalInputTokens: 0,
      totalOutputTokens: 0,
      totalOverallTokens: 0,
    };
    for (const i of interactions) {
      acc.totalCost += i.cost || 0;
      acc.totalInputTokens += i.input_tokens || 0;
      acc.totalOutputTokens += i.output_tokens || 0;
      acc.totalOverallTokens += i.total_tokens || 0;
    }
    return acc;
  }, [interactions]);

  const filePaths = useMemo(() => {
    const paths = new Set<string>();
    for (const i of interactions) {
      if (i.file_path) paths.add(i.file_path);
    }
    return ["All Files", ...Array.from(paths).sort()];
  }, [interactions]);

  const filteredInteractions = useMemo(() => {
    if (selectedFilePath === "All Files") return interactions;
    return interactions.filter((i) => i.file_path === selectedFilePath);
  }, [interactions, selectedFilePath]);

  const fileStats = useMemo(() => {
    if (selectedFilePath === "All Files") return null;
    const acc = {
      totalCost: 0,
      totalInputTokens: 0,
      totalOutputTokens: 0,
      totalOverallTokens: 0,
    };
    for (const i of filteredInteractions) {
      acc.totalCost += i.cost || 0;
      acc.totalInputTokens += i.input_tokens || 0;
      acc.totalOutputTokens += i.output_tokens || 0;
      acc.totalOverallTokens += i.total_tokens || 0;
    }
    return acc;
  }, [filteredInteractions, selectedFilePath]);

  if (isLoading) {
    return (
      <div
        className="sccap-card"
        style={{
          padding: 60,
          textAlign: "center",
          color: "var(--fg-muted)",
        }}
      >
        Loading LLM interaction logs…
      </div>
    );
  }

  if (isError) {
    return (
      <div
        className="sccap-card"
        style={{
          padding: 20,
          background: "var(--critical-weak)",
          borderColor: "var(--critical)",
          color: "var(--critical)",
        }}
      >
        {error?.message ?? "Failed to load logs."}
      </div>
    );
  }

  return (
    <div className="fade-in" style={{ display: "grid", gap: 16 }}>
      <PageHeader
        crumbs={[
          {
            label: `Scan ${scanId?.slice(0, 12) ?? "…"}`,
            to: `/analysis/results/${scanId}`,
          },
          { label: "LLM cost & interactions" },
        ]}
        title={
          <>
            <Icon.Dollar size={18} /> LLM cost & interactions
          </>
        }
        subtitle={
          <>
            Scan{" "}
            <span className="mono" style={{ fontSize: 11 }}>
              {scanId}
            </span>
          </>
        }
      />

      <div
        className="surface"
        style={{
          padding: 18,
          display: "grid",
          gridTemplateColumns: "repeat(4, 1fr)",
          gap: 18,
        }}
      >
        <Stat label="Total scan cost" value={`$${overallStats.totalCost.toFixed(6)}`} />
        <Stat
          label="Total input tokens"
          value={overallStats.totalInputTokens.toLocaleString()}
        />
        <Stat
          label="Total output tokens"
          value={overallStats.totalOutputTokens.toLocaleString()}
        />
        <Stat
          label="Total overall tokens"
          value={overallStats.totalOverallTokens.toLocaleString()}
        />
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "280px 1fr",
          gap: 16,
          alignItems: "start",
        }}
      >
        <div
          className="surface"
          style={{
            padding: 8,
            maxHeight: "70vh",
            overflowY: "auto",
          }}
        >
          <div
            style={{
              fontSize: 10.5,
              color: "var(--fg-subtle)",
              textTransform: "uppercase",
              letterSpacing: ".06em",
              padding: "6px 10px 4px",
            }}
          >
            Files involved
          </div>
          {filePaths.map((p) => {
            const active = p === selectedFilePath;
            return (
              <button
                key={p}
                className="sccap-btn sccap-btn-ghost"
                style={{
                  width: "100%",
                  justifyContent: "flex-start",
                  padding: "8px 10px",
                  background: active ? "var(--bg-soft)" : "transparent",
                  color: active ? "var(--fg)" : "var(--fg-muted)",
                  fontSize: 12.5,
                }}
                onClick={() => setSelectedFilePath(p)}
                title={p}
              >
                <span
                  style={{
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    flex: 1,
                    textAlign: "left",
                    fontWeight: p === "All Files" ? 600 : 400,
                  }}
                  className={p === "All Files" ? "" : "mono"}
                >
                  {p}
                </span>
              </button>
            );
          })}
        </div>

        <div className="surface" style={{ padding: 0 }}>
          {fileStats && (
            <div
              style={{
                padding: 14,
                background: "var(--bg-soft)",
                borderBottom: "1px solid var(--border)",
                display: "grid",
                gridTemplateColumns: "repeat(4, 1fr)",
                gap: 14,
              }}
            >
              <Stat
                small
                label="File cost"
                value={`$${fileStats.totalCost.toFixed(6)}`}
              />
              <Stat
                small
                label="Input tokens"
                value={fileStats.totalInputTokens.toLocaleString()}
              />
              <Stat
                small
                label="Output tokens"
                value={fileStats.totalOutputTokens.toLocaleString()}
              />
              <Stat
                small
                label="Overall tokens"
                value={fileStats.totalOverallTokens.toLocaleString()}
              />
            </div>
          )}

          {filteredInteractions.length === 0 ? (
            <div
              style={{
                padding: 40,
                textAlign: "center",
                color: "var(--fg-muted)",
                fontSize: 13,
              }}
            >
              {selectedFilePath === "All Files"
                ? "This scan may not have reached analysis, or no AI interactions were required."
                : `No interactions found for file: ${selectedFilePath}`}
            </div>
          ) : (
            <table className="sccap-t">
              <thead>
                <tr>
                  <th style={{ width: 180 }}>Timestamp</th>
                  <th>Agent</th>
                  <th style={{ textAlign: "right" }}>Tokens (I/O/T)</th>
                  <th style={{ textAlign: "right" }}>Cost</th>
                  <th style={{ width: 30 }} />
                </tr>
              </thead>
              <tbody>
                {filteredInteractions.map((r) => {
                  const open = expandedId === r.id;
                  return (
                    <React.Fragment key={r.id}>
                      <tr
                        onClick={() => setExpandedId(open ? null : r.id)}
                        style={{ cursor: "pointer" }}
                      >
                        <td style={{ fontSize: 12 }}>
                          {new Date(r.timestamp).toLocaleString()}
                        </td>
                        <td>
                          <span
                            className="chip"
                            style={{
                              background: "var(--info-weak)",
                              color: "var(--info)",
                              border: "none",
                            }}
                          >
                            {r.agent_name}
                          </span>
                        </td>
                        <td
                          style={{
                            textAlign: "right",
                            fontVariantNumeric: "tabular-nums",
                          }}
                        >
                          <div style={{ fontSize: 12 }}>
                            {(r.input_tokens ?? 0).toLocaleString()} /{" "}
                            {(r.output_tokens ?? 0).toLocaleString()}
                          </div>
                          <div style={{ fontWeight: 600 }}>
                            {(r.total_tokens ?? 0).toLocaleString()}
                          </div>
                        </td>
                        <td
                          style={{
                            textAlign: "right",
                            fontVariantNumeric: "tabular-nums",
                          }}
                        >
                          {r.cost ? `$${r.cost.toFixed(6)}` : "—"}
                        </td>
                        <td style={{ textAlign: "center" }}>
                          {open ? (
                            <Icon.ChevronU size={12} />
                          ) : (
                            <Icon.ChevronD size={12} />
                          )}
                        </td>
                      </tr>
                      {open && (
                        <tr>
                          <td colSpan={5} style={{ padding: 0 }}>
                            <div
                              style={{
                                padding: 18,
                                background: "var(--bg-soft)",
                                display: "grid",
                                gap: 12,
                              }}
                            >
                              <div>
                                <Label>Prompt template</Label>
                                <div className="mono" style={{ fontSize: 12 }}>
                                  {r.prompt_template_name ?? "N/A"}
                                </div>
                              </div>
                              <div>
                                <Label>Prompt context</Label>
                                <pre className="sccap-code">
                                  {JSON.stringify(
                                    redactSensitive(r.prompt_context),
                                    null,
                                    2,
                                  )}
                                </pre>
                              </div>
                              <div>
                                <Label>Parsed output</Label>
                                <pre className="sccap-code">
                                  {JSON.stringify(
                                    redactSensitive(r.parsed_output),
                                    null,
                                    2,
                                  )}
                                </pre>
                              </div>
                              {r.error && (
                                <div>
                                  <Label>Error</Label>
                                  <div
                                    className="sccap-card"
                                    style={{
                                      padding: 10,
                                      background: "var(--critical-weak)",
                                      borderColor: "var(--critical)",
                                      color: "var(--critical)",
                                      fontSize: 12.5,
                                    }}
                                  >
                                    {(() => {
                                      const safe = sanitizeErrorMessage(r.error);
                                      const genericMessage =
                                        "An internal error occurred during this LLM call. See backend logs for details.";
                                      const displayText = safe ?? genericMessage;
                                      const hasTechnicalDetails =
                                        isSuperuser && safe !== r.error;
                                      const techVisible =
                                        showTechDetails[r.id] ?? false;
                                      return (
                                        <>
                                          <span>{displayText}</span>
                                          {hasTechnicalDetails && (
                                            <>
                                              {" "}
                                              <button
                                                onClick={(e) => {
                                                  e.stopPropagation();
                                                  setShowTechDetails((prev) => ({
                                                    ...prev,
                                                    [r.id]: !prev[r.id],
                                                  }));
                                                }}
                                                style={{
                                                  background: "none",
                                                  border: "none",
                                                  cursor: "pointer",
                                                  color: "var(--critical)",
                                                  fontSize: 11,
                                                  textDecoration: "underline",
                                                  padding: 0,
                                                }}
                                              >
                                                {techVisible
                                                  ? "Hide technical details"
                                                  : "Show technical details"}
                                              </button>
                                              {techVisible && (
                                                <pre
                                                  style={{
                                                    marginTop: 8,
                                                    whiteSpace: "pre-wrap",
                                                    wordBreak: "break-all",
                                                    fontSize: 11,
                                                    opacity: 0.85,
                                                  }}
                                                >
                                                  {r.error}
                                                </pre>
                                              )}
                                            </>
                                          )}
                                        </>
                                      );
                                    })()}
                                  </div>
                                </div>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
};

const Stat: React.FC<{
  label: string;
  value: React.ReactNode;
  small?: boolean;
}> = ({ label, value, small }) => (
  <div>
    <div
      style={{
        fontSize: small ? 10.5 : 11,
        color: "var(--fg-subtle)",
        textTransform: "uppercase",
        letterSpacing: ".06em",
      }}
    >
      {label}
    </div>
    <div
      style={{
        fontSize: small ? 16 : 22,
        fontWeight: 600,
        color: "var(--fg)",
        marginTop: 4,
        fontVariantNumeric: "tabular-nums",
      }}
    >
      {value}
    </div>
  </div>
);

const Label: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div
    style={{
      fontSize: 10.5,
      color: "var(--fg-subtle)",
      textTransform: "uppercase",
      letterSpacing: ".06em",
      marginBottom: 4,
    }}
  >
    {children}
  </div>
);

export default LlmLogViewerPage;
