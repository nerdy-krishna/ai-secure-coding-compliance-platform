// Findings debug panel — raw vs consolidated comparison + Sankey flow.
// Accessible from the scan results page for agent-quality debugging.

import React, { useEffect, useState } from "react";
import { debugService, type ScanFindingsDebug } from "../../shared/api/debugService";
import type { Finding } from "../../shared/types/api";
import { Icon } from "../../shared/ui/Icon";
import { SectionHead } from "../../shared/ui/DashboardPrimitives";
import { FindingsSankey } from "./FindingsSankey";

interface Props {
  scanId: string;
}

type Bucket = "sast" | "raw_llm" | "consolidated";

const BUCKET_LABEL: Record<Bucket, string> = {
  sast: "SAST scanners",
  raw_llm: "Raw LLM (pre-consolidation)",
  consolidated: "Consolidated (final)",
};

const BUCKET_COLOR: Record<Bucket, string> = {
  sast: "#f59e0b",
  raw_llm: "#6366f1",
  consolidated: "#10b981",
};

const TABLE_COLS = [
  { key: "title" as const, label: "Title", w: 200 },
  { key: "severity" as const, label: "Sev", w: 70 },
  { key: "source" as const, label: "Source", w: 90 },
  { key: "file_path" as const, label: "File", w: 140 },
  { key: "line_number" as const, label: "Line", w: 50 },
  { key: "confidence" as const, label: "Conf", w: 60 },
];

const Th: React.FC<{ w: number; children: React.ReactNode }> = ({
  w,
  children,
}) => (
  <th
    style={{
      width: w,
      textAlign: "left",
      padding: "6px 8px",
      fontSize: 11,
      fontWeight: 600,
      color: "var(--fg-muted)",
      textTransform: "uppercase",
      letterSpacing: ".04em",
      borderBottom: "1px solid var(--border)",
    }}
  >
    {children}
  </th>
);

const Td: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <td
    style={{
      padding: "5px 8px",
      fontSize: 12,
      borderBottom: "1px solid var(--border)",
      maxWidth: 240,
      overflow: "hidden",
      textOverflow: "ellipsis",
      whiteSpace: "nowrap",
    }}
  >
    {children}
  </td>
);

export const FindingsDebugPanel: React.FC<Props> = ({ scanId }) => {
  const [data, setData] = useState<ScanFindingsDebug | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeBucket, setActiveBucket] = useState<Bucket>("raw_llm");

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    debugService
      .getFindingsDebug(scanId)
      .then((d) => {
        if (!cancelled) setData(d);
      })
      .catch((e: { message?: string }) => {
        if (!cancelled) setError(e.message || "Failed to load debug data");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [scanId]);

  if (loading) {
    return (
      <div className="surface" style={{ padding: 24, color: "var(--fg-muted)" }}>
        Loading findings debug data…
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="surface" style={{ padding: 24, color: "var(--critical)" }}>
        {error || "No debug data available."}
      </div>
    );
  }

  const findingsMap: Record<Bucket, Finding[]> = {
    sast: data.sast_findings,
    raw_llm: data.raw_llm_findings,
    consolidated: data.consolidated_findings,
  };
  const findings = findingsMap[activeBucket];

  const totalRaw = data.sast_findings.length + data.raw_llm_findings.length;

  return (
    <div className="surface" style={{ padding: 24, display: "grid", gap: 20 }}>
      <SectionHead
        title={
          <>
            <Icon.Terminal size={16} /> Findings debug
          </>
        }
      />

      {/* Sankey flow */}
      <div style={{ display: "flex", justifyContent: "center", padding: "12px 0" }}>
        <FindingsSankey nodes={data.sankey_nodes} links={data.sankey_links} />
      </div>

      {/* Summary stats */}
      <div
        style={{
          display: "flex",
          gap: 24,
          fontSize: 13,
          color: "var(--fg-muted)",
        }}
      >
        <span>
          SAST: <b style={{ color: BUCKET_COLOR.sast }}>{data.sast_findings.length}</b>
        </span>
        <span>
          Raw LLM:{" "}
          <b style={{ color: BUCKET_COLOR.raw_llm }}>{data.raw_llm_findings.length}</b>
        </span>
        <span>
          Total pre-consolidation:{" "}
          <b style={{ color: "var(--fg)" }}>{totalRaw}</b>
        </span>
        <span>
          Consolidated:{" "}
          <b style={{ color: BUCKET_COLOR.consolidated }}>
            {data.consolidated_findings.length}
          </b>
        </span>
        <span>
          Dropped / merged:{" "}
          <b style={{ color: "var(--critical)" }}>
            {totalRaw - data.consolidated_findings.length}
          </b>
        </span>
      </div>

      {/* Bucket tabs */}
      <div className="radio-group" style={{ width: "fit-content" }}>
        {(["sast", "raw_llm", "consolidated"] as Bucket[]).map((b) => {
          const count = findingsMap[b].length;
          return (
            <button
              key={b}
              className={activeBucket === b ? "active" : ""}
              onClick={() => setActiveBucket(b)}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 6,
              }}
            >
              <span
                style={{
                  width: 8,
                  height: 8,
                  borderRadius: "50%",
                  background: BUCKET_COLOR[b],
                  flexShrink: 0,
                }}
              />
              {BUCKET_LABEL[b]} ({count})
            </button>
          );
        })}
      </div>

      {/* Findings table */}
      <div style={{ overflow: "auto", maxHeight: 400 }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              {TABLE_COLS.map((c) => (
                <Th key={c.key} w={c.w}>
                  {c.label}
                </Th>
              ))}
            </tr>
          </thead>
          <tbody>
            {findings.length === 0 ? (
              <tr>
                <td
                  colSpan={TABLE_COLS.length}
                  style={{
                    padding: 16,
                    textAlign: "center",
                    color: "var(--fg-subtle)",
                    fontSize: 13,
                  }}
                >
                  No findings in this bucket.
                </td>
              </tr>
            ) : (
              findings.map((f, i) => (
                <tr
                  key={f.id ?? i}
                  style={{
                    background: i % 2 === 0 ? "var(--bg-soft)" : "transparent",
                  }}
                >
                  <Td>{f.title}</Td>
                  <Td>
                    <span
                      style={{
                        color:
                          f.severity === "Critical" ||
                          f.severity === "CRITICAL"
                            ? "var(--critical)"
                            : f.severity === "High" || f.severity === "HIGH"
                              ? "var(--high)"
                              : "var(--fg-muted)",
                        fontWeight: 600,
                      }}
                    >
                      {(f.severity ?? "").slice(0, 4)}
                    </span>
                  </Td>
                  <Td>{f.source ?? "—"}</Td>
                  <Td>{f.file_path}</Td>
                  <Td>{f.line_number ?? "—"}</Td>
                  <Td>{f.confidence ?? "—"}</Td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
