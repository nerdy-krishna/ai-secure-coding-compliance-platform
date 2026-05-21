// Compact mini debug panel for the bottom of scan results page.
// Expandable finding rows with full LLM details.

import React, { useEffect, useState } from "react";
import { debugService, type ScanFindingsDebug } from "../../shared/api/debugService";
import type { Finding } from "../../shared/types/api";
import { Icon } from "../../shared/ui/Icon";

interface Props {
  scanId: string;
}

type Bucket = "sast" | "raw_llm" | "consolidated";

const BUCKET_COLOR: Record<Bucket, string> = {
  sast: "#f59e0b",
  raw_llm: "#6366f1",
  consolidated: "#10b981",
};

const BUCKET_LABEL: Record<Bucket, string> = {
  sast: "SAST",
  raw_llm: "Raw LLM",
  consolidated: "Consolidated",
};

export const FindingsDebugPanel: React.FC<Props> = ({ scanId }) => {
  const [data, setData] = useState<ScanFindingsDebug | null>(null);
  const [loading, setLoading] = useState(true);
  const [collapsed, setCollapsed] = useState(true);
  const [activeBucket, setActiveBucket] = useState<Bucket>("raw_llm");
  const [expandedId, setExpandedId] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    debugService
      .getFindingsDebug(scanId)
      .then((d) => { if (!cancelled) setData(d); })
      .catch(() => {})
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [scanId]);

  if (loading || !data) return null;

  const totalRaw = data.sast_findings.length + data.raw_llm_findings.length;
  const findingsMap: Record<Bucket, Finding[]> = {
    sast: data.sast_findings,
    raw_llm: data.raw_llm_findings,
    consolidated: data.consolidated_findings,
  };
  const findings = findingsMap[activeBucket];

  return (
    <div className="surface" style={{ padding: 0, overflow: "hidden" }}>
      {/* Compact header — always visible */}
      <div
        onClick={() => setCollapsed(!collapsed)}
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "12px 18px",
          cursor: "pointer",
          background: collapsed ? "transparent" : "var(--bg-soft)",
          borderBottom: collapsed ? "none" : "1px solid var(--border)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 12, fontSize: 13 }}>
          <Icon.Layers size={14} />
          <span style={{ fontWeight: 600 }}>Findings Pipeline</span>
          <span style={{ color: "var(--fg-muted)" }}>
            {totalRaw} raw → {data.consolidated_findings.length} consolidated
          </span>
          {totalRaw - data.consolidated_findings.length > 0 && (
            <span style={{ color: "var(--critical)", fontSize: 12 }}>
              {totalRaw - data.consolidated_findings.length} dropped/merged
            </span>
          )}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {(["sast", "raw_llm", "consolidated"] as Bucket[]).map((b) => (
            <span
              key={b}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 4,
                fontSize: 11,
                color: BUCKET_COLOR[b],
                fontWeight: activeBucket === b ? 600 : 400,
                opacity: activeBucket === b ? 1 : 0.6,
              }}
            >
              <span style={{ width: 7, height: 7, borderRadius: "50%", background: BUCKET_COLOR[b], flexShrink: 0 }} />
              {findingsMap[b].length}
            </span>
          ))}
          <Icon.ChevronR size={12} style={{ transform: collapsed ? "rotate(0deg)" : "rotate(90deg)", transition: "transform .2s" }} />
        </div>
      </div>

      {/* Expanded details */}
      {!collapsed && (
        <div style={{ padding: "12px 18px 18px", display: "grid", gap: 12 }}>
          {/* Bucket tabs */}
          <div className="radio-group" style={{ width: "fit-content" }}>
            {(Object.keys(BUCKET_LABEL) as Bucket[]).map((b) => (
              <button
                key={b}
                className={activeBucket === b ? "active" : ""}
                onClick={(e) => { e.stopPropagation(); setActiveBucket(b); }}
              >
                {BUCKET_LABEL[b]} ({findingsMap[b].length})
              </button>
            ))}
          </div>

          {/* Finding rows with expand/collapse */}
          <div style={{ maxHeight: 350, overflow: "auto" }}>
            {findings.map((f, i) => {
              const isExpanded = expandedId === (f.id ?? i);
              return (
                <div
                  key={f.id ?? i}
                  style={{
                    borderBottom: "1px solid var(--border)",
                    background: i % 2 === 0 ? "var(--bg-soft)" : "transparent",
                  }}
                >
                  {/* Row header — click to expand */}
                  <div
                    onClick={() => setExpandedId(isExpanded ? null : (f.id ?? i))}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                      padding: "6px 8px",
                      cursor: "pointer",
                      fontSize: 12,
                    }}
                  >
                    <Icon.ChevronR
                      size={10}
                      style={{
                        transform: isExpanded ? "rotate(90deg)" : "rotate(0deg)",
                        transition: "transform .15s",
                        flexShrink: 0,
                      }}
                    />
                    <span
                      style={{
                        fontWeight: 600,
                        color:
                          f.severity === "Critical" || f.severity === "CRITICAL"
                            ? "var(--critical)"
                            : f.severity === "High" || f.severity === "HIGH"
                              ? "var(--high)"
                              : "var(--fg)",
                        fontSize: 11,
                        flexShrink: 0,
                        width: 50,
                      }}
                    >
                      {(f.severity ?? "?").slice(0, 6)}
                    </span>
                    <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {f.title}
                    </span>
                    <span style={{ color: "var(--fg-muted)", fontSize: 11, flexShrink: 0 }}>
                      {f.source ?? "—"} · {f.file_path.split("/").pop()}:{f.line_number}
                    </span>
                  </div>

                  {/* Expanded details */}
                  {isExpanded && (
                    <div style={{ padding: "8px 12px 12px 28px", fontSize: 12, display: "grid", gap: 6, color: "var(--fg-muted)" }}>
                      <div><b style={{ color: "var(--fg)" }}>Description:</b> {f.description}</div>
                      {f.remediation && <div><b style={{ color: "var(--fg)" }}>Remediation:</b> {f.remediation}</div>}
                      <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
                        <span>Confidence: <b style={{ color: "var(--fg)" }}>{f.confidence}</b></span>
                        {f.cwe && <span>CWE: <b style={{ color: "var(--fg)" }}>{f.cwe}</b></span>}
                        {typeof f.cvss_score === "number" && <span>CVSS: <b style={{ color: "var(--fg)" }}>{f.cvss_score}</b></span>}
                        {f.cvss_vector && <span style={{ fontSize: 10, wordBreak: "break-all" }}>{f.cvss_vector}</span>}
                      </div>
                      {f.corroborating_agents && f.corroborating_agents.length > 0 && (
                        <div>Corroborating: <b style={{ color: "var(--fg)" }}>{f.corroborating_agents.join(", ")}</b></div>
                      )}
                      {f.detected_by_llms && f.detected_by_llms.length > 0 && (
                        <div>Detected by: <b style={{ color: "var(--fg)" }}>{f.detected_by_llms.join(", ")}</b></div>
                      )}
                      {f.cross_file_status && (
                        <div>Cross-file: <b style={{ color: "var(--fg)" }}>{f.cross_file_status}</b> — {f.cross_file_rationale}</div>
                      )}
                      {f.affected_locations && f.affected_locations.length > 0 && (
                        <div>
                          Affected locations:{" "}
                          {f.affected_locations.map((l, j) => (
                            <span key={j} style={{ marginRight: 8, fontSize: 10 }}>
                              L{l.line_number}
                            </span>
                          ))}
                        </div>
                      )}
                      {f.references && f.references.length > 0 && (
                        <div style={{ wordBreak: "break-all" }}>
                          Refs: {f.references.slice(0, 3).join(", ")}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
