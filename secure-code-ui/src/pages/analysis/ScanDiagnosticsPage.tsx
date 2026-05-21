// Scan Diagnostics page — "Pipeline & Logs"
// Tab 1: Findings Pipeline (Sankey + filters + expandable breakdown)
// Tab 2: LLM Calls (full interaction log with expandable details)

import React, { useEffect, useMemo, useState } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { debugService, type ScanFindingsDebug } from "../../shared/api/debugService";
import { scanService } from "../../shared/api/scanService";
import type { Finding, LLMInteractionResponse } from "../../shared/types/api";
import { useAuth } from "../../shared/hooks/useAuth";
import { redactSensitive } from "../../shared/lib/redact";
import { Icon } from "../../shared/ui/Icon";
import { SectionHead } from "../../shared/ui/DashboardPrimitives";
import { PageHeader } from "../../shared/ui/PageHeader";
import { ElaborateSankey, type SankeyMode } from "../../features/scans/ElaborateSankey";

type Tab = "pipeline" | "llm";

const MODE_LABELS: Record<SankeyMode, string> = {
  source: "By Source",
  source_type: "By Type",
  agent: "By Agent",
  severity: "By Severity",
  cwe: "By CWE",
};

// ── Entry point ──────────────────────────────────────────────────────

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
      .then(([d, i]) => { if (!cancelled) { setDebug(d); setInteractions(i); } })
      .catch(() => {})
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [scanId]);

  if (loading) return <div className="surface" style={{ padding: 24 }}>Loading diagnostics…</div>;

  return (
    <div className="fade-in" style={{ display: "grid", gap: 20 }}>
      <PageHeader
        crumbs={[{ label: `Scan ${scanId?.slice(0, 8) ?? "…"}`, to: `/analysis/results/${scanId}` }, { label: "Pipeline & Logs" }]}
        title="Pipeline & Logs"
        subtitle="Findings pipeline flow and LLM call inspection for this scan."
      />

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

      {tab === "llm" && scanId && (
        <LLMTab interactions={interactions} scanId={scanId} />
      )}
    </div>
  );
};

// ── Pipeline tab ────────────────────────────────────────────────────

type Bucket = "sast" | "raw_llm" | "consolidated";
const BUCKET_LABEL: Record<Bucket, string> = { sast: "SAST", raw_llm: "Raw LLM", consolidated: "Consolidated" };
const BUCKET_COLOR: Record<Bucket, string> = { sast: "#f59e0b", raw_llm: "#6366f1", consolidated: "#10b981" };

const PipelineTab: React.FC<{
  debug: ScanFindingsDebug;
  sankeyMode: SankeyMode;
  onModeChange: (m: SankeyMode) => void;
}> = ({ debug, sankeyMode, onModeChange }) => {
  const totalRaw = debug.sast_findings.length + debug.raw_llm_findings.length;
  return (
    <div style={{ display: "grid", gap: 20 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>Group by:</span>
        <div className="radio-group" style={{ width: "fit-content" }}>
          {(Object.keys(MODE_LABELS) as SankeyMode[]).map((m) => (
            <button key={m} className={sankeyMode === m ? "active" : ""} onClick={() => onModeChange(m)}>
              {MODE_LABELS[m]}
            </button>
          ))}
        </div>
      </div>

      <div className="surface" style={{ padding: 24, display: "flex", justifyContent: "center" }}>
        <ElaborateSankey
          mode={sankeyMode}
          sourceGroups={debug.source_groups}
          severityGroups={debug.severity_groups}
          cweGroups={debug.cwe_groups}
          agentGroups={debug.agent_groups}
          fullSankeyNodes={debug.full_sankey_nodes}
          fullSankeyLinks={debug.full_sankey_links}
          consolidatedCount={debug.consolidated_findings.length}
        />
      </div>

      <div style={{ display: "flex", gap: 24, fontSize: 13, color: "var(--fg-muted)" }}>
        <span>SAST: <b style={{ color: BUCKET_COLOR.sast }}>{debug.sast_findings.length}</b></span>
        <span>Raw LLM: <b style={{ color: BUCKET_COLOR.raw_llm }}>{debug.raw_llm_findings.length}</b></span>
        <span>Total pre: <b>{totalRaw}</b></span>
        <span>Consolidated: <b style={{ color: BUCKET_COLOR.consolidated }}>{debug.consolidated_findings.length}</b></span>
        <span>Dropped: <b style={{ color: "var(--critical)" }}>{totalRaw - debug.consolidated_findings.length}</b></span>
      </div>

      <FindingsBreakdown debug={debug} />
    </div>
  );
};

// ── Findings breakdown (with filters + expandable rows) ──────────────

const SAST_CATEGORIES = ["Semgrep", "Bandit", "Gitleaks", "OSV"];
const SOURCE_CATEGORIES = ["All Sources", "LLM", ...SAST_CATEGORIES];

type SourceCategory = (typeof SOURCE_CATEGORIES)[number];

const FindingsBreakdown: React.FC<{ debug: ScanFindingsDebug }> = ({ debug }) => {
  const [bucket, setBucket] = useState<Bucket>("raw_llm");
  const [sevFilter, setSevFilter] = useState<string>("All");
  const [sourceCat, setSourceCat] = useState<SourceCategory>("All Sources");
  const [sourceAgent, setSourceAgent] = useState<string>("All Agents");
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const findingsMap: Record<Bucket, Finding[]> = {
    sast: debug.sast_findings,
    raw_llm: debug.raw_llm_findings,
    consolidated: debug.consolidated_findings,
  };

  const llmAgents = useMemo(() => {
    const s = new Set<string>();
    findingsMap[bucket].forEach(f => {
      const src = (f.source ?? "").toLowerCase();
      if (f.source && !SAST_CATEGORIES.map(c => c.toLowerCase()).includes(src)) {
        s.add(f.source);
      }
    });
    return ["All Agents", ...Array.from(s).sort()];
  }, [bucket, findingsMap]);

  const sevs = useMemo(() => {
    const s = new Set<string>();
    findingsMap[bucket].forEach(f => { if (f.severity) s.add(f.severity); });
    return ["All", ...Array.from(s).sort()];
  }, [bucket, findingsMap]);

  const filtered = useMemo(() => {
    return findingsMap[bucket].filter(f => {
      if (sevFilter !== "All" && f.severity !== sevFilter) return false;
      // Two-tier source filter
      if (sourceCat !== "All Sources") {
        const src = (f.source ?? "").toLowerCase();
        if (SAST_CATEGORIES.includes(sourceCat)) {
          // Direct SAST match
          if (src !== sourceCat.toLowerCase()) return false;
        } else if (sourceCat === "LLM") {
          // LLM: exclude SAST sources
          if (SAST_CATEGORIES.map(c => c.toLowerCase()).includes(src)) return false;
          // Second tier: specific agent
          if (sourceAgent !== "All Agents" && f.source !== sourceAgent) return false;
        }
      }
      return true;
    });
  }, [findingsMap, bucket, sevFilter, sourceCat, sourceAgent]);

  // Reset expanded and agent sub-filter when main filters change
  useEffect(() => { setExpandedId(null); }, [bucket, sevFilter, sourceCat]);
  useEffect(() => { if (sourceCat !== "LLM") setSourceAgent("All Agents"); }, [sourceCat]);

  const resetFilters = () => { setBucket("raw_llm"); setSevFilter("All"); setSourceCat("All Sources"); setSourceAgent("All Agents"); };

  return (
    <div className="surface" style={{ padding: 0 }}>
      <SectionHead title="Findings breakdown" style={{ padding: "18px 20px 10px", margin: 0 }} />
      <div style={{ display: "flex", gap: 0, borderBottom: "1px solid var(--border)" }}>
        {(Object.keys(BUCKET_LABEL) as Bucket[]).map((b) => (
          <button key={b} onClick={() => { setBucket(b); resetFilters(); }}
            style={{
              flex: 1, padding: "10px 16px", background: bucket === b ? "var(--primary-weak)" : "transparent",
              border: "none", borderBottom: bucket === b ? "2px solid var(--primary)" : "2px solid transparent",
              cursor: "pointer", fontSize: 13, fontWeight: bucket === b ? 600 : 400,
              color: bucket === b ? "var(--primary)" : "var(--fg-muted)",
            }}>
            {BUCKET_LABEL[b]} ({findingsMap[b].length})
          </button>
        ))}
      </div>

      {/* Filters */}
      <div style={{ display: "flex", gap: 12, padding: "10px 18px", borderBottom: "1px solid var(--border)", flexWrap: "wrap", alignItems: "center" }}>
        <span style={{ fontSize: 11, color: "var(--fg-subtle)", textTransform: "uppercase" }}>Severity</span>
        <select value={sevFilter} onChange={e => setSevFilter(e.target.value)}
          style={{ background: "var(--bg-soft)", border: "1px solid var(--border)", borderRadius: 6, padding: "4px 8px", fontSize: 12, color: "var(--fg)" }}>
          {sevs.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <span style={{ fontSize: 11, color: "var(--fg-subtle)", textTransform: "uppercase" }}>Source</span>
        <select value={sourceCat} onChange={e => setSourceCat(e.target.value as SourceCategory)}
          style={{ background: "var(--bg-soft)", border: "1px solid var(--border)", borderRadius: 6, padding: "4px 8px", fontSize: 12, color: "var(--fg)" }}>
          {SOURCE_CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
        {sourceCat === "LLM" && (
          <select value={sourceAgent} onChange={e => setSourceAgent(e.target.value)}
            style={{ background: "var(--bg-soft)", border: "1px solid var(--primary)", borderRadius: 6, padding: "4px 8px", fontSize: 12, color: "var(--fg)" }}>
            {llmAgents.map(a => <option key={a} value={a}>{a}</option>)}
          </select>
        )}
        <span style={{ fontSize: 11, color: "var(--fg-muted)", marginLeft: "auto" }}>{filtered.length} of {findingsMap[bucket].length}</span>
      </div>

      <div style={{ maxHeight: 500, overflow: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              {["", "Sev", "Title", "Source", "File", "Line", "CWE"].map((h, i) => (
                <th key={i} style={{ textAlign: "left", padding: "6px 8px", fontSize: 11, fontWeight: 600, color: "var(--fg-muted)", textTransform: "uppercase", borderBottom: "1px solid var(--border)", width: i === 2 ? undefined : i === 0 ? 28 : "auto" }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((f, i) => {
              const open = expandedId === (f.id ?? i);
              return (
                <React.Fragment key={f.id ?? i}>
                  <tr onClick={() => setExpandedId(open ? null : (f.id ?? i))}
                    style={{ cursor: "pointer", background: i % 2 === 0 ? "var(--bg-soft)" : "transparent", fontSize: 12 }}>
                    <td style={{ padding: "5px 8px", textAlign: "center" }}>
                      {open ? <Icon.ChevronU size={10} /> : <Icon.ChevronD size={10} />}
                    </td>
                    <td style={{ padding: "5px 8px", fontWeight: 600, color: (f.severity === "Critical" || f.severity === "CRITICAL") ? "var(--critical)" : (f.severity === "High" || f.severity === "HIGH") ? "var(--high)" : "var(--fg-muted)" }}>
                      {(f.severity ?? "").slice(0, 4)}
                    </td>
                    <td style={{ padding: "5px 8px", maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.title}</td>
                    <td style={{ padding: "5px 8px" }}>{f.source ?? "—"}</td>
                    <td style={{ padding: "5px 8px", maxWidth: 160, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.file_path}</td>
                    <td style={{ padding: "5px 8px" }}>{f.line_number ?? "—"}</td>
                    <td style={{ padding: "5px 8px" }}>{f.cwe ?? "—"}</td>
                  </tr>
                  {open && (
                    <tr>
                      <td colSpan={7} style={{ padding: 0 }}>
                        <div style={{ padding: "14px 18px", background: "var(--bg-soft)", display: "grid", gap: 8, fontSize: 12, color: "var(--fg-muted)" }}>
                          <div><b style={{ color: "var(--fg)" }}>Description:</b> {f.description}</div>
                          {f.remediation && <div><b style={{ color: "var(--fg)" }}>Remediation:</b> {f.remediation}</div>}
                          <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
                            <span>Confidence: <b style={{ color: "var(--fg)" }}>{f.confidence}</b></span>
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
                            <div>Affected locations: {f.affected_locations.map((l, j) => (
                              <span key={j} style={{ marginRight: 8, fontSize: 10 }}>L{l.line_number}</span>
                            ))}</div>
                          )}
                          {f.references && f.references.length > 0 && (
                            <div style={{ wordBreak: "break-all" }}>Refs: {f.references.slice(0, 3).join(", ")}</div>
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
      </div>
    </div>
  );
};

// ── LLM Calls tab (restored full functionality) ──────────────────────

const INTERNAL_ERROR_INDICATORS = ["traceback", "at line", "sql:", "sqlalchemy", "file \"", "exception", "stacktrace", "stack trace"];

function sanitizeErrorMessage(raw: string): string | null {
  const lower = raw.toLowerCase();
  if (INTERNAL_ERROR_INDICATORS.some(i => lower.includes(i))) return null;
  const idx = raw.search(/[.!?]\s/);
  const t = idx > 0 && idx < 200 ? raw.slice(0, idx + 1) : raw.slice(0, 200);
  return t !== raw ? `${t}…` : t;
}

const LLMTab: React.FC<{ interactions: LLMInteractionResponse[]; scanId: string }> = ({ interactions }) => {
  const { user } = useAuth();
  const isSuperuser = user?.is_superuser === true;
  const [searchParams, setSearchParams] = useSearchParams();
  const [selectedModel, setSelectedModel] = useState(() => searchParams.get("model") ?? "All Models");
  const [selectedFile, setSelectedFile] = useState("All Files");
  const [selectedAgent, setSelectedAgent] = useState("All Agents");
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [showTech, setShowTech] = useState<Record<number, boolean>>({});

  const agents = useMemo(() => {
    const s = new Set<string>();
    interactions.forEach(i => { if (i.agent_name) s.add(i.agent_name); });
    return ["All Agents", ...Array.from(s).sort()];
  }, [interactions]);

  const models = useMemo(() => {
    const s = new Set<string>();
    interactions.forEach(i => { if (i.llm_name) s.add(i.llm_name); });
    return ["All Models", ...Array.from(s).sort()];
  }, [interactions]);

  const files = useMemo(() => {
    const s = new Set<string>();
    interactions.forEach(i => { if (i.file_path) s.add(i.file_path); });
    return ["All Files", ...Array.from(s).sort()];
  }, [interactions]);

  useEffect(() => {
    const p = searchParams.get("model");
    if (p && p !== selectedModel) setSelectedModel(p);
  }, [searchParams, selectedModel]);

  const selectModel = (m: string) => {
    setSelectedModel(m);
    const n = new URLSearchParams(searchParams);
    if (m === "All Models") n.delete("model"); else n.set("model", m);
    setSearchParams(n, { replace: true });
  };

  const filtered = useMemo(() => interactions.filter(i => {
    if (selectedModel !== "All Models" && i.llm_name !== selectedModel) return false;
    if (selectedFile !== "All Files" && i.file_path !== selectedFile) return false;
    if (selectedAgent !== "All Agents" && i.agent_name !== selectedAgent) return false;
    return true;
  }), [interactions, selectedModel, selectedFile, selectedAgent]);

  const overall = useMemo(() => {
    let cost = 0, inp = 0, out = 0, tot = 0;
    interactions.forEach(i => { cost += i.cost || 0; inp += i.input_tokens || 0; out += i.output_tokens || 0; tot += i.total_tokens || 0; });
    return { cost, inp, out, tot };
  }, [interactions]);

  const fileStats = useMemo(() => {
    if (selectedFile === "All Files") return null;
    let cost = 0, inp = 0, out = 0, tot = 0;
    filtered.forEach(i => { cost += i.cost || 0; inp += i.input_tokens || 0; out += i.output_tokens || 0; tot += i.total_tokens || 0; });
    return { cost, inp, out, tot };
  }, [filtered, selectedFile]);

  return (
    <div style={{ display: "grid", gap: 16 }}>

      {/* Stats */}
      <div className="surface" style={{ padding: 18, display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 18 }}>
        <Stat label="Total scan cost" value={`$${overall.cost.toFixed(6)}`} />
        <Stat label="Input tokens" value={overall.inp.toLocaleString()} />
        <Stat label="Output tokens" value={overall.out.toLocaleString()} />
        <Stat label="Total tokens" value={overall.tot.toLocaleString()} />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "260px 1fr", gap: 16, alignItems: "start" }}>
        {/* Sidebar filters */}
        <div className="surface" style={{ padding: 8, maxHeight: "70vh", overflowY: "auto" }}>
          {models.length > 1 && <>
            <div style={{ fontSize: 10.5, color: "var(--fg-subtle)", textTransform: "uppercase", letterSpacing: ".06em", padding: "6px 10px 4px" }}>Models</div>
            {models.map(m => (
              <button key={m} className="sccap-btn sccap-btn-ghost" onClick={() => selectModel(m)}
                style={{ width: "100%", justifyContent: "flex-start", padding: "8px 10px", background: m === selectedModel ? "var(--bg-soft)" : "transparent", color: m === selectedModel ? "var(--fg)" : "var(--fg-muted)", fontSize: 12.5, fontWeight: m === "All Models" ? 600 : 400 }}>
                <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1, textAlign: "left" }}>{m}</span>
              </button>
            ))}
            <div style={{ borderTop: "1px solid var(--border)", margin: "8px 4px" }} />
          </>}
          {agents.length > 1 && <>
            <div style={{ fontSize: 10.5, color: "var(--fg-subtle)", textTransform: "uppercase", letterSpacing: ".06em", padding: "6px 10px 4px" }}>Agents</div>
            {agents.map(a => (
              <button key={a} className="sccap-btn sccap-btn-ghost" onClick={() => setSelectedAgent(a)}
                style={{ width: "100%", justifyContent: "flex-start", padding: "8px 10px", background: a === selectedAgent ? "var(--bg-soft)" : "transparent", color: a === selectedAgent ? "var(--fg)" : "var(--fg-muted)", fontSize: 12.5, fontWeight: a === "All Agents" ? 600 : 400 }}>
                <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1, textAlign: "left" }}>{a}</span>
              </button>
            ))}
            <div style={{ borderTop: "1px solid var(--border)", margin: "8px 4px" }} />
          </>}
          <div style={{ fontSize: 10.5, color: "var(--fg-subtle)", textTransform: "uppercase", letterSpacing: ".06em", padding: "6px 10px 4px" }}>Files</div>
          {files.map(f => (
            <button key={f} className="sccap-btn sccap-btn-ghost" onClick={() => setSelectedFile(f)}
              style={{ width: "100%", justifyContent: "flex-start", padding: "8px 10px", background: f === selectedFile ? "var(--bg-soft)" : "transparent", color: f === selectedFile ? "var(--fg)" : "var(--fg-muted)", fontSize: 12.5, fontWeight: f === "All Files" ? 600 : 400 }}>
              <span className={f === "All Files" ? "" : "mono"} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1, textAlign: "left" }}>{f}</span>
            </button>
          ))}
        </div>

        {/* Table */}
        <div className="surface" style={{ padding: 0 }}>
          {fileStats && (
            <div style={{ padding: 14, background: "var(--bg-soft)", borderBottom: "1px solid var(--border)", display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 14 }}>
              <Stat small label="File cost" value={`$${fileStats.cost.toFixed(6)}`} />
              <Stat small label="Input tokens" value={fileStats.inp.toLocaleString()} />
              <Stat small label="Output tokens" value={fileStats.out.toLocaleString()} />
              <Stat small label="Total tokens" value={fileStats.tot.toLocaleString()} />
            </div>
          )}
          {filtered.length === 0 ? (
            <div style={{ padding: 40, textAlign: "center", color: "var(--fg-muted)", fontSize: 13 }}>
              No LLM interactions found.
            </div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table className="sccap-t">
                <thead>
                  <tr>
                    <th style={{ width: 170 }}>Timestamp</th>
                    <th>Agent</th>
                    <th style={{ textAlign: "right" }}>Tokens (I/O/T)</th>
                    <th style={{ textAlign: "right" }}>Cost</th>
                    <th style={{ width: 30 }} />
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(r => {
                    const open = expandedId === r.id;
                    return (
                      <React.Fragment key={r.id}>
                        <tr onClick={() => setExpandedId(open ? null : r.id)} style={{ cursor: "pointer" }}>
                          <td style={{ fontSize: 12 }}>{new Date(r.timestamp).toLocaleString()}</td>
                          <td>
                            <span className="chip" style={{ background: "var(--info-weak)", color: "var(--info)", border: "none" }}>{r.agent_name}</span>
                            {r.llm_name && <div style={{ fontSize: 11, color: "var(--fg-subtle)", marginTop: 3 }}>{r.llm_name}</div>}
                          </td>
                          <td style={{ textAlign: "right", fontVariantNumeric: "tabular-nums" }}>
                            <div style={{ fontSize: 12 }}>{(r.input_tokens ?? 0).toLocaleString()} / {(r.output_tokens ?? 0).toLocaleString()}</div>
                            <div style={{ fontWeight: 600 }}>{(r.total_tokens ?? 0).toLocaleString()}</div>
                          </td>
                          <td style={{ textAlign: "right", fontVariantNumeric: "tabular-nums" }}>{r.cost ? `$${r.cost.toFixed(6)}` : "—"}</td>
                          <td style={{ textAlign: "center" }}>{open ? <Icon.ChevronU size={12} /> : <Icon.ChevronD size={12} />}</td>
                        </tr>
                        {open && (
                          <tr>
                            <td colSpan={5} style={{ padding: 0 }}>
                              <div style={{ padding: 18, background: "var(--bg-soft)", display: "grid", gap: 12 }}>
                                <div>
                                  <Lbl>Prompt template</Lbl>
                                  <div className="mono" style={{ fontSize: 12 }}>{r.prompt_template_name ?? "N/A"}</div>
                                </div>
                                <div>
                                  <Lbl>Prompt context</Lbl>
                                  <pre className="sccap-code" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", overflow: "auto", maxWidth: "100%", maxHeight: 360 }}>
                                    {JSON.stringify(redactSensitive(r.prompt_context), null, 2)}
                                  </pre>
                                </div>
                                <div>
                                  <Lbl>Parsed output</Lbl>
                                  <pre className="sccap-code" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", overflow: "auto", maxWidth: "100%", maxHeight: 360 }}>
                                    {JSON.stringify(redactSensitive(r.parsed_output), null, 2)}
                                  </pre>
                                </div>
                                {r.error && (
                                  <div>
                                    <Lbl>Error</Lbl>
                                    <div className="sccap-card" style={{ padding: 10, background: "var(--critical-weak)", borderColor: "var(--critical)", color: "var(--critical)", fontSize: 12.5 }}>
                                      {(() => {
                                        const safe = sanitizeErrorMessage(r.error);
                                        const generic = "An internal error occurred during this LLM call.";
                                        const display = safe ?? generic;
                                        const hasTech = isSuperuser && safe !== r.error;
                                        const techVis = showTech[r.id] ?? false;
                                        return (
                                          <>
                                            <span>{display}</span>
                                            {hasTech && <>
                                              {" "}
                                              <button onClick={e => { e.stopPropagation(); setShowTech(p => ({ ...p, [r.id]: !p[r.id] })); }}
                                                style={{ background: "none", border: "none", cursor: "pointer", color: "var(--critical)", fontSize: 11, textDecoration: "underline", padding: 0 }}>
                                                {techVis ? "Hide details" : "Show details"}
                                              </button>
                                              {techVis && <pre style={{ marginTop: 8, whiteSpace: "pre-wrap", wordBreak: "break-all", fontSize: 11, opacity: 0.85 }}>{r.error}</pre>}
                                            </>}
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
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

const Stat: React.FC<{ label: string; value: React.ReactNode; small?: boolean }> = ({ label, value, small }) => (
  <div>
    <div style={{ fontSize: small ? 10.5 : 11, color: "var(--fg-subtle)", textTransform: "uppercase", letterSpacing: ".06em" }}>{label}</div>
    <div style={{ fontSize: small ? 16 : 22, fontWeight: 600, color: "var(--fg)", marginTop: 4, fontVariantNumeric: "tabular-nums" }}>{value}</div>
  </div>
);

const Lbl: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div style={{ fontSize: 10.5, color: "var(--fg-subtle)", textTransform: "uppercase", letterSpacing: ".06em", marginBottom: 4 }}>{children}</div>
);

export default ScanDiagnosticsPage;
