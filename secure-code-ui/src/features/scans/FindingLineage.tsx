// Finding Lineage Graph — canonical expandable DAG with side panel,
// focus mode, server-side filters, and compact URL state.
// Uses React Flow with dagre layout.

import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  ReactFlow,
  Background,
  Controls,
  type Node as RFNode,
  type Edge as RFEdge,
  MarkerType,
  useNodesState,
  useEdgesState,
  Handle,
  Position,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import dagre from "dagre";
import { debugService } from "../../shared/api/debugService";

// ── Types ──────────────────────────────────────────────────────────

interface LineageNode {
  id: string; type: string; label: string; column: number;
  count: number; expandable: boolean; expanded: boolean;
  has_children?: boolean; child_count?: number;
  badges?: Array<{ label?: string; tone?: string }>;
}

interface LineageEdge {
  id: string; source: string; target: string; value: number;
  label?: string;
}

interface LineageData {
  nodes: LineageNode[];
  edges: LineageEdge[];
  lineage_quality: string;
  warnings: string[];
  available_expansions: Record<string, number>;
}

// ── Colour map ─────────────────────────────────────────────────────

const TYPE_COLORS: Record<string, string> = {
  file: "#3b82f6", file_group: "#3b82f6",
  source: "#a855f7", domain: "#10b981",
  cons: "#f59e0b", final: "#ef4444",
  dropped: "#ef4444", dropped_finding: "#ef4444",
  raw_finding: "#6366f1", overflow: "#64748b",
};

const BADGE_COLORS: Record<string, string> = {
  neutral: "#64748b", critical: "#dc2626",
  high: "#f97316", medium: "#eab308", low: "#22c55e",
};

function nodeStyle(type: string): React.CSSProperties {
  const color = TYPE_COLORS[type] || "#6366f1";
  return {
    background: `${color}15`,
    border: `1.5px solid ${color}`,
    borderRadius: 8, padding: "8px 14px", fontSize: 12,
    fontWeight: 600, color,
    minWidth: 80, textAlign: "center" as const,
    cursor: "pointer",
  };
}

// ── Dagre layout ───────────────────────────────────────────────────

function layoutGraph(lnodes: LineageNode[], ledges: LineageEdge[]) {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: "LR", nodesep: 40, ranksep: 120, marginx: 24, marginy: 24 });

  for (const n of lnodes) {
    g.setNode(n.id, { width: 160, height: 38 });
  }
  for (const e of ledges) {
    g.setEdge(e.source, e.target, {});
  }
  dagre.layout(g);

  const rfNodes: RFNode[] = lnodes.map((n) => {
    const pos = g.node(n.id);
    return {
      id: n.id,
      type: "lineageNode",
      position: { x: pos.x - 80, y: pos.y - 19 },
      data: {
        label: n.label, nodeType: n.type, count: n.count,
        expandable: n.expandable, expanded: n.expanded,
        badges: n.badges, hasChildren: n.has_children,
        childCount: n.child_count,
      },
      style: nodeStyle(n.type),
    };
  });

  const rfEdges: RFEdge[] = ledges.map((e) => ({
    id: e.id, source: e.source, target: e.target,
    animated: false,
    style: { stroke: "#94a3b8", strokeWidth: Math.max(1, Math.min(6, e.value)) },
    markerEnd: { type: MarkerType.ArrowClosed, color: "#94a3b8", width: 14, height: 14 },
  }));

  return { nodes: rfNodes, edges: rfEdges };
}

// ── Column headers ─────────────────────────────────────────────────

const COL_LABELS = ["Files", "Detection Sources", "Domains", "Consolidation", "Outputs"];
const COL_X = [0, 145, 320, 485, 650];

function ColumnHeaders() {
  return (
    <div className="column-headers" style={{
      position: "absolute", top: 0, left: 0, right: 0, height: 26,
      display: "flex", borderBottom: "1px solid var(--border)",
      background: "var(--bg-soft)", zIndex: 5,
    }}>
      {COL_LABELS.map((label, i) => (
        <div key={i} style={{
          position: "absolute", left: COL_X[i], width: 120,
          fontSize: 9, fontWeight: 600, color: "var(--fg-muted)",
          textTransform: "uppercase", letterSpacing: ".04em",
          textAlign: "center", lineHeight: "26px",
        }}>{label}</div>
      ))}
    </div>
  );
}

// ── Custom node ────────────────────────────────────────────────────

function LineageNodeComponent({ data }: { data: any }) {
  const { label, nodeType, expandable, expanded, badges, hasChildren, childCount } = data;
  const color = TYPE_COLORS[nodeType] || "#6366f1";
  const badgeList: Array<{ label: string; tone: string }> = Array.isArray(badges) ? badges : [];

  return (
    <div style={{
      background: `${color}12`, border: `1.5px solid ${color}`,
      borderRadius: 8, padding: "7px 12px", fontSize: 11,
      fontWeight: 600, color, position: "relative",
      display: "flex", alignItems: "center", gap: 6,
    }}>
      <Handle type="target" position={Position.Left} style={{ visibility: "hidden" }} />
      <Handle type="source" position={Position.Right} style={{ visibility: "hidden" }} />

      {expandable && (
        <span style={{ fontSize: 10, cursor: "pointer", minWidth: 12 }}>
          {expanded ? "▼" : "▶"}
        </span>
      )}
      <span style={{ maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {label}
      </span>
      {hasChildren && !expanded && (
        <span style={{ fontSize: 9, color: "var(--fg-muted)", opacity: 0.8 }}>
          ({childCount})
        </span>
      )}
      {badgeList.map((b: any, i: number) => (
        <span key={i} style={{
          fontSize: 8, padding: "1px 5px", borderRadius: 4,
          background: (BADGE_COLORS[b.tone] || "#64748b") + "20",
          color: BADGE_COLORS[b.tone] || "#64748b",
          maxWidth: 80, overflow: "hidden", textOverflow: "ellipsis",
        }}>{b.label}</span>
      ))}
    </div>
  );
}

// ── Side panel ─────────────────────────────────────────────────────

interface SelectedInfo {
  id: string; type: string; label: string; count: number;
  expandable: boolean; expanded: boolean;
  hasChildren?: boolean; childCount?: number;
  badges?: Array<{ label: string; tone: string }>;
}

function SidePanel({ selected, onClose, onFocus, onExpand }: {
  selected: SelectedInfo;
  onClose: () => void;
  onFocus: (id: string) => void;
  onExpand: (id: string) => void;
}) {
  const color = TYPE_COLORS[selected.type] || "#6366f1";
  return (
    <div className="surface" style={{
      width: 260, padding: 16, display: "grid", gap: 10, alignSelf: "start",
      border: `1px solid ${color}40`,
    }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <span style={{ fontWeight: 600, fontSize: 13, color }}>{selected.type}</span>
        <button onClick={onClose} style={{
          background: "none", border: "none", cursor: "pointer", color: "var(--fg-muted)", fontSize: 14,
        }}>✕</button>
      </div>
      <div style={{ fontSize: 12, color: "var(--fg)", wordBreak: "break-word" }}>{selected.label}</div>
      <div style={{ fontSize: 11, color: "var(--fg-muted)" }}>
        Count: <b>{selected.count}</b>
        {selected.hasChildren && <> · Children: <b>{selected.childCount}</b></>}
      </div>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
        {selected.expandable && (
          <button className="sccap-btn sccap-btn-ghost" style={{ fontSize: 11, padding: "4px 10px" }}
            onClick={() => onExpand(selected.id)}>
            {selected.expanded ? "Collapse" : "Expand"}
          </button>
        )}
        <button className="sccap-btn sccap-btn-ghost" style={{ fontSize: 11, padding: "4px 10px" }}
          onClick={() => onFocus(selected.id)}>
          Focus Lineage
        </button>
      </div>
      {selected.badges && selected.badges.length > 0 && (
        <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
          {selected.badges.map((b, i) => (
            <span key={i} style={{
              fontSize: 10, padding: "2px 6px", borderRadius: 4,
              background: (BADGE_COLORS[b.tone] || "#64748b") + "20",
              color: BADGE_COLORS[b.tone] || "#64748b",
            }}>{b.label}</span>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Props ──────────────────────────────────────────────────────────

interface Props { scanId: string; }

// ── Component ─────────────────────────────────────────────────────

export const FindingLineage: React.FC<Props> = ({ scanId }) => {
  const [searchParams, setSearchParams] = useSearchParams();
  const [lineage, setLineage] = useState<LineageData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<SelectedInfo | null>(null);
  const [filterText, setFilterText] = useState("");
  const [filterSev, setFilterSev] = useState("");

  // URL state
  const expandedIds = useMemo(
    () => (searchParams.get("e") || "").split(",").filter(Boolean),
    [searchParams],
  );
  const focusedId = searchParams.get("focus") || null;

  const fetchLineage = useCallback(async () => {
    if (!scanId) return;
    try {
      setLoading(true);
      const filters: Record<string, string[]> | undefined =
        filterText || filterSev ? {} : undefined;
      if (filterText) filters!["text"] = [filterText];
      if (filterSev) filters!["severity"] = [filterSev];
      const data = await debugService.getFindingLineage(
        scanId, expandedIds, focusedId, 250,
      );
      setLineage(data);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed");
    } finally {
      setLoading(false);
    }
  }, [scanId, expandedIds, focusedId, filterText, filterSev]);

  useEffect(() => { fetchLineage(); }, [fetchLineage]);

  const rfData = useMemo(() => {
    if (!lineage) return { nodes: [], edges: [] };
    return layoutGraph(lineage.nodes, lineage.edges);
  }, [lineage]);

  const [nodes, setNodes, onNodesChange] = useNodesState(rfData.nodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(rfData.edges);

  useEffect(() => {
    setNodes(rfData.nodes);
    setEdges(rfData.edges);
  }, [rfData, setNodes, setEdges]);

  const nodeTypes = useMemo(() => ({ lineageNode: LineageNodeComponent }), []);

  const toggleExpand = useCallback((nodeId: string) => {
    const n = new URLSearchParams(searchParams);
    const cur = (n.get("e") || "").split(",").filter(Boolean);
    const next = cur.includes(nodeId)
      ? cur.filter((x) => x !== nodeId)
      : [...cur, nodeId];
    n.delete("e");
    if (next.length) n.set("e", next.join(","));
    setSearchParams(n, { replace: true });
    setSelected(null);
  }, [searchParams, setSearchParams]);

  const setFocus = useCallback((nodeId: string | null) => {
    const n = new URLSearchParams(searchParams);
    if (nodeId) {
      n.set("focus", nodeId);
    } else {
      n.delete("focus");
    }
    setSearchParams(n, { replace: true });
    setSelected(null);
  }, [searchParams, setSearchParams]);

  const onNodeClick = useCallback((_e: React.MouseEvent, node: RFNode) => {
    const d: any = node.data;
    if (!d) return;
    setSelected({
      id: node.id,
      type: String(d.nodeType || ""),
      label: String(d.label || ""),
      count: Number(d.count ?? 0),
      expandable: Boolean(d.expandable),
      expanded: Boolean(d.expanded),
      hasChildren: d.hasChildren as boolean | undefined,
      childCount: d.childCount as number | undefined,
      badges: Array.isArray(d.badges) ? d.badges as Array<{ label: string; tone: string }> : undefined,
    });
  }, []);

  const nodeClickHandler = useCallback(
    (_e: React.MouseEvent, node: RFNode) => {
      if (node.data?.expandable && !_e.metaKey) {
        toggleExpand(node.id);
      } else {
        onNodeClick(_e, node);
      }
    },
    [toggleExpand, onNodeClick],
  );

  if (loading && !lineage) {
    return <div className="surface" style={{ padding: 24 }}>Loading lineage graph…</div>;
  }
  if (error) {
    return <div className="surface" style={{ padding: 24, color: "var(--critical)" }}>{error}</div>;
  }

  return (
    <div style={{ display: "grid", gap: 12 }}>
      {/* Warnings */}
      {lineage?.warnings && lineage.warnings.length > 0 && (
        <div style={{
          padding: "8px 14px", borderRadius: 6,
          background: "var(--warning-weak, #fef3c7)",
          color: "var(--warning-fg, #92400e)", fontSize: 12,
        }}>
          {lineage.warnings.map((w, i) => <div key={i}>⚠ {w}</div>)}
        </div>
      )}

      {/* Filters + controls */}
      <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
        <input
          type="text" placeholder="Search findings…" value={filterText}
          onChange={(e) => setFilterText(e.target.value)}
          style={{ padding: "5px 10px", borderRadius: 6, border: "1px solid var(--border)",
            fontSize: 12, width: 180, background: "var(--bg-soft)", color: "var(--fg)" }}
        />
        <select value={filterSev} onChange={(e) => setFilterSev(e.target.value)}
          style={{ padding: "5px 8px", borderRadius: 6, border: "1px solid var(--border)",
            fontSize: 12, background: "var(--bg-soft)", color: "var(--fg)" }}>
          <option value="">All severities</option>
          {["CRITICAL","HIGH","MEDIUM","LOW","INFORMATIONAL"].map(s =>
            <option key={s} value={s}>{s}</option>
          )}
        </select>
        <button className="sccap-btn sccap-btn-ghost" style={{ fontSize: 11 }}
          onClick={() => { setFilterText(""); setFilterSev(""); }}>
          Reset
        </button>
        {focusedId && (
          <button className="sccap-btn sccap-btn-ghost" style={{ fontSize: 11, color: "var(--primary)" }}
            onClick={() => setFocus(null)}>
            Clear focus
          </button>
        )}
        <span style={{ fontSize: 10, color: "var(--fg-muted)", marginLeft: "auto" }}>
          {lineage?.lineage_quality === "exact" ? "✓ exact" : "⚠ inferred"}
        </span>
      </div>

      {/* Graph + side panel */}
      <div style={{ display: "flex", gap: 12, alignItems: "flex-start" }}>
        <div className="surface" style={{
          flex: 1, height: 420, position: "relative", overflow: "hidden",
        }}>
          <ColumnHeaders />
          <div style={{ marginTop: 26, width: "100%", height: "calc(100% - 26px)" }}>
            <ReactFlow
              nodes={nodes} edges={edges}
              onNodesChange={onNodesChange} onEdgesChange={onEdgesChange}
              onNodeClick={nodeClickHandler}
              nodeTypes={nodeTypes}
              fitView fitViewOptions={{ padding: 0.3 }}
              nodesDraggable={false} nodesConnectable={false}
              minZoom={0.3} maxZoom={1.5}
            >
              <Background color="var(--border)" gap={20} />
              <Controls showInteractive={false} />
            </ReactFlow>
          </div>
        </div>

        {selected && (
          <SidePanel
            selected={selected}
            onClose={() => setSelected(null)}
            onFocus={setFocus}
            onExpand={toggleExpand}
          />
        )}
      </div>
    </div>
  );
};
