// Scan Diagnostics page — "Pipeline & Logs"
// Tab 1: Findings Pipeline (Sankey + breakdown tables)
// Tab 2: LLM Calls (existing interaction log)

import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { debugService, type ScanFindingsDebug } from "../../shared/api/debugService";
import { scanService } from "../../shared/api/scanService";
import type { Finding, LLMInteractionResponse } from "../../shared/types/api";
import { Icon } from "../../shared/ui/Icon";
import { SectionHead } from "../../shared/ui/DashboardPrimitives";
import { PageHeader } from "../../shared/ui/PageHeader";
import { ElaborateSankey, type SankeyMode } from "../../features/scans/ElaborateSankey";

type Tab = "pipeline" | "llm";

const MODE_LABELS: Record<SankeyMode, string> = {
  source: "By Source",
  source_type: "By Type",
  severity: "By Severity",
  cwe: "By CWE",
};

export const ScanDiagnosticsPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const [tab, setTab] = useState<Tab>("pipeline");
  const [debug, setDebug] = useState<ScanFindingsDebug | null>(null);
  const [interactions, setInteractions] = useState<LLMInteractionResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [sankeyMode, setSankeyMode] = useState<SankeyMode>("source_type");

  useEffect(() => {
    if (!scanId) return;
    let cancelled = false;
    setLoading(true);
    Promise.all([
      debugService.getFindingsDebug(scanId),
      scanService.getLlmInteractionsForScan(scanId),
    ])
      .then(([d, i]) => {
        if (!cancelled) {
          setDebug(d);
          setInteractions(i);
        }
      })
      .catch(() => {})
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, [scanId]);

  if (loading) {
    return <div className="surface" style={{ padding: 24 }}>Loading diagnostics…</div>;
  }

  return (
    <div className="fade-in" style={{ display: "grid", gap: 20 }}>
      <PageHeader
        crumbs={[{ label: `Scan ${scanId?.slice(0, 8) ?? "…"}` }]}
        title="Pipeline & Logs"
        subtitle="Findings pipeline flow and LLM call inspection for this scan."
      />

      {/* Tabs */}
      <div className="radio-group" style={{ width: "fit-content" }}>
        <button className={tab === "pipeline" ? "active" : ""} onClick={() => setTab("pipeline")}>
          <Icon.Layers size={13} /> Findings Pipeline
        </button>
        <button className={tab === "llm" ? "active" : ""} onClick={() => setTab("llm")}>
          <Icon.Terminal size={13} /> LLM Calls
        </button>
      </div>

      {tab === "pipeline" && debug && (
        <PipelineTab debug={debug} sankeyMode={sankeyMode} onModeChange={setSankeyMode} />
      )}

      {tab === "llm" && (
        <LLMTab interactions={interactions} />
      )}
    </div>
  );
};

// ── Pipeline tab ────────────────────────────────────────────────────

const PipelineTab: React.FC<{
  debug: ScanFindingsDebug;
  sankeyMode: SankeyMode;
  onModeChange: (m: SankeyMode) => void;
}> = ({ debug, sankeyMode, onModeChange }) => {
  const totalRaw = debug.sast_findings.length + debug.raw_llm_findings.length;
  return (
    <div style={{ display: "grid", gap: 20 }}>
      {/* Sankey mode selector */}
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>Group by:</span>
        <div className="radio-group" style={{ width: "fit-content" }}>
          {(Object.keys(MODE_LABELS) as SankeyMode[]).map((m) => (
            <button
              key={m}
              className={sankeyMode === m ? "active" : ""}
              onClick={() => onModeChange(m)}
            >
              {MODE_LABELS[m]}
            </button>
          ))}
        </div>
      </div>

      {/* Elaborate Sankey */}
      <div className="surface" style={{ padding: 24, display: "flex", justifyContent: "center" }}>
        <ElaborateSankey
          mode={sankeyMode}
          sourceGroups={debug.source_groups}
          severityGroups={debug.severity_groups}
          cweGroups={debug.cwe_groups}
          consolidatedCount={debug.consolidated_findings.length}
        />
      </div>

      {/* Stats bar */}
      <div style={{ display: "flex", gap: 24, fontSize: 13, color: "var(--fg-muted)" }}>
        <span>SAST: <b style={{ color: "#f59e0b" }}>{debug.sast_findings.length}</b></span>
        <span>Raw LLM: <b style={{ color: "#6366f1" }}>{debug.raw_llm_findings.length}</b></span>
        <span>Total pre: <b>{totalRaw}</b></span>
        <span>Consolidated: <b style={{ color: "#10b981" }}>{debug.consolidated_findings.length}</b></span>
        <span>Dropped: <b style={{ color: "var(--critical)" }}>{totalRaw - debug.consolidated_findings.length}</b></span>
      </div>

      {/* Findings breakdown table */}
      <FindingsBreakdown debug={debug} />
    </div>
  );
};

// ── Findings breakdown table ─────────────────────────────────────────

type Bucket = "sast" | "raw_llm" | "consolidated";
const BUCKET_LABEL: Record<Bucket, string> = {
  sast: "SAST scanners",
  raw_llm: "Raw LLM",
  consolidated: "Consolidated",
};

const FindingsBreakdown: React.FC<{ debug: ScanFindingsDebug }> = ({ debug }) => {
  const [bucket, setBucket] = useState<Bucket>("raw_llm");
  const findingsMap: Record<Bucket, Finding[]> = {
    sast: debug.sast_findings,
    raw_llm: debug.raw_llm_findings,
    consolidated: debug.consolidated_findings,
  };
  const findings = findingsMap[bucket];

  return (
    <div className="surface" style={{ padding: 0 }}>
      <SectionHead title="Findings breakdown" style={{ padding: "18px 20px 10px", margin: 0 }} />
      <div style={{ display: "flex", gap: 0, borderBottom: "1px solid var(--border)" }}>
        {(Object.keys(BUCKET_LABEL) as Bucket[]).map((b) => (
          <button
            key={b}
            onClick={() => setBucket(b)}
            style={{
              flex: 1,
              padding: "10px 16px",
              background: bucket === b ? "var(--primary-weak)" : "transparent",
              border: "none",
              borderBottom: bucket === b ? "2px solid var(--primary)" : "2px solid transparent",
              cursor: "pointer",
              fontSize: 13,
              fontWeight: bucket === b ? 600 : 400,
              color: bucket === b ? "var(--primary)" : "var(--fg-muted)",
            }}
          >
            {BUCKET_LABEL[b]} ({findingsMap[b].length})
          </button>
        ))}
      </div>
      <div style={{ maxHeight: 500, overflow: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              {["Title", "Sev", "Source", "File", "Line", "CWE"].map((h) => (
                <th key={h} style={{ textAlign: "left", padding: "6px 8px", fontSize: 11, fontWeight: 600, color: "var(--fg-muted)", textTransform: "uppercase", borderBottom: "1px solid var(--border)" }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {findings.map((f, i) => (
              <tr key={f.id ?? i} style={{ background: i % 2 === 0 ? "var(--bg-soft)" : "transparent", fontSize: 12 }}>
                <td style={{ padding: "5px 8px", maxWidth: 240, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.title}</td>
                <td style={{ padding: "5px 8px", fontWeight: 600, color: f.severity === "Critical" ? "var(--critical)" : f.severity === "High" ? "var(--high)" : "var(--fg-muted)" }}>{(f.severity ?? "").slice(0, 4)}</td>
                <td style={{ padding: "5px 8px" }}>{f.source ?? "—"}</td>
                <td style={{ padding: "5px 8px", maxWidth: 160, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.file_path}</td>
                <td style={{ padding: "5px 8px" }}>{f.line_number ?? "—"}</td>
                <td style={{ padding: "5px 8px" }}>{f.cwe ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// ── LLM Calls tab ────────────────────────────────────────────────────

const LLMTab: React.FC<{
  interactions: LLMInteractionResponse[];
}> = ({ interactions }) => {
  return (
    <div className="surface" style={{ padding: 0 }}>
      <SectionHead
        title={`LLM Calls (${interactions.length})`}
        style={{ padding: "18px 20px 10px", margin: 0 }}
      />
      <div style={{ maxHeight: 600, overflow: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
          <thead>
            <tr>
              {["Agent", "Model", "Tokens", "Cost", "Time"].map((h) => (
                <th key={h} style={{ textAlign: "left", padding: "6px 10px", fontSize: 11, fontWeight: 600, color: "var(--fg-muted)", textTransform: "uppercase", borderBottom: "1px solid var(--border)" }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {interactions.map((ix, i) => (
              <tr key={i} style={{ background: i % 2 === 0 ? "var(--bg-soft)" : "transparent" }}>
                <td style={{ padding: "6px 10px", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={ix.agent_name}>{ix.agent_name}</td>
                <td style={{ padding: "6px 10px", color: "var(--fg-muted)" }}>{ix.llm_name ?? "—"}</td>
                <td style={{ padding: "6px 10px", fontVariantNumeric: "tabular-nums" }}>{typeof ix.total_tokens === "number" ? ix.total_tokens.toLocaleString() : "—"}</td>
                <td style={{ padding: "6px 10px", fontVariantNumeric: "tabular-nums" }}>{typeof ix.cost === "number" ? `$${ix.cost.toFixed(4)}` : "—"}</td>
                <td style={{ padding: "6px 10px", color: "var(--fg-muted)", fontSize: 11 }}>{ix.timestamp ? new Date(ix.timestamp).toLocaleTimeString() : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default ScanDiagnosticsPage;
