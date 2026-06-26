// Elaborate Sankey diagram for findings pipeline debugging.
// Three-column layout: SAST tools → Raw LLM agents → Consolidated (by severity)
// Pure SVG — no chart library dependency.

import React, { useMemo } from "react";

export type SankeyMode = "source" | "source_type" | "agent" | "severity" | "cwe";

interface SankeyNode {
  id: string;
  label: string;
}

interface SankeyLink {
  source: string;
  target: string;
  value: number;
}

interface FlowMapEntry {
  raw_title: string;
  raw_source: string;
  raw_severity: string;
  raw_cwe?: string | null;
  consolidated_title: string;
  status: string;
}

interface ConsolidatedFindingLike {
  title?: string | null;
  severity?: string | null;
  cwe?: string | null;
}

interface Props {
  mode: SankeyMode;
  sourceGroups: Record<string, number>;
  severityGroups: Record<string, number>;
  cweGroups: Record<string, number>;
  agentGroups: Record<string, number>;
  consolidatedCount: number;
  fullSankeyNodes?: SankeyNode[] | null;
  fullSankeyLinks?: SankeyLink[] | null;
  flowMap?: FlowMapEntry[] | null;
  consolidatedFindings?: ConsolidatedFindingLike[] | null;
}

const PALETTE = [
  "#6366f1", "#8b5cf6", "#a855f7", "#d946ef", "#ec4899",
  "#f43f5e", "#ef4444", "#f97316", "#eab308", "#84cc16",
  "#22c55e", "#10b981", "#14b8a6", "#06b6d4", "#0ea5e9",
  "#3b82f6", "#64748b", "#78716c",
];

const NODE_W = 140;
const NODE_H = 34;
const PAD_X = 20;
const PAD_Y = 20;
const CANVAS_W = 900;
const PAD_BETWEEN = 100;

// ── Simple mode: left nodes → consolidated (fallback) ─────────────

function buildNodes(mode: SankeyMode, groups: Record<string, number>): {
  nodes: Array<{ id: string; label: string; value: number; color: string }>;
} {
  const entries = Object.entries(groups)
    .filter(([, v]) => v > 0)
    .sort((a, b) => b[1] - a[1]);
  return {
    nodes: entries.map(([key, value], i) => ({
      id: key,
      label: mode === "source_type"
        ? key === "sast" ? "SAST Tools" : "LLM Agents"
        : key,
      value,
      color: PALETTE[i % PALETTE.length],
    })),
  };
}

// ── Full three-column sankey ──────────────────────────────────────

const COLORS: Record<string, string> = {
  bandit: "#3b82f6", semgrep: "#a855f7", gitleaks: "#dc2626", osv: "#0891b2",
  merged: "#6366f1", dropped: "#ef4444", passthrough: "#10b981",
  CRITICAL: "#dc2626", HIGH: "#f97316", MEDIUM: "#eab308", LOW: "#22c55e",
  INFORMATIONAL: "#64748b", INFO: "#64748b",
};

function hashColor(seed: string): string {
  let hash = 0;
  for (let i = 0; i < seed.length; i++) hash = (hash * 31 + seed.charCodeAt(i)) | 0;
  return PALETTE[Math.abs(hash) % PALETTE.length];
}

function nodeColor(nodeId: string): string {
  if (nodeId.startsWith("sast_")) {
    const tool = nodeId.replace("sast_", "");
    return COLORS[tool] || hashColor(tool);
  }
  if (nodeId.startsWith("raw_")) {
    if (nodeId.endsWith("_dropped")) return COLORS.dropped;
    if (nodeId.endsWith("_pass")) return COLORS.passthrough;
    return COLORS.merged;
  }
  if (nodeId.startsWith("stage_")) {
    const stage = nodeId.replace("stage_", "").toLowerCase();
    if (stage === "dropped") return COLORS.dropped;
    if (stage === "passthrough") return COLORS.passthrough;
    return COLORS.merged;
  }
  if (nodeId.startsWith("cons_")) {
    const sev = nodeId.replace("cons_", "");
    return COLORS[sev] || hashColor(sev);
  }
  if (nodeId.startsWith("group_")) return hashColor(nodeId);
  if (nodeId.startsWith("out_")) {
    const key = decodeURIComponent(nodeId.replace("out_", ""));
    return COLORS[key] || hashColor(key);
  }
  if (nodeId === "dropped") return COLORS.dropped;
  return "#64748b";
}

function columnPosition(col: 0 | 1 | 2): number {
  if (col === 0) return PAD_X;
  if (col === 1) return PAD_X + NODE_W + PAD_BETWEEN;
  return PAD_X + (NODE_W + PAD_BETWEEN) * 2;
}

function columnForId(id: string): 0 | 1 | 2 {
  if (id.startsWith("sast_") || id.startsWith("group_")) return 0;
  if (id.startsWith("raw_") || id.startsWith("stage_")) return 1;
  if (id.startsWith("cons_") || id.startsWith("out_") || id === "dropped") return 2;
  return 1;
}

function normaliseStatus(status: string | undefined): "merged" | "dropped" | "passthrough" {
  const s = (status || "passthrough").toLowerCase();
  if (s === "dropped") return "dropped";
  if (s === "merged") return "merged";
  return "passthrough";
}

function statusLabel(status: "merged" | "dropped" | "passthrough"): string {
  if (status === "merged") return "Merged";
  if (status === "dropped") return "Dropped";
  return "Passthrough";
}

function compactLabel(label: string, max = 22): string {
  return label.length > max ? `${label.slice(0, max - 1)}…` : label;
}

function addCount(map: Map<string, number>, key: string, inc = 1): void {
  map.set(key, (map.get(key) || 0) + inc);
}

function buildGroupedFlowSankey(
  mode: Exclude<SankeyMode, "source_type">,
  flowMap: FlowMapEntry[] | null | undefined,
  consolidatedFindings: ConsolidatedFindingLike[] | null | undefined,
): { nodes: SankeyNode[]; links: SankeyLink[] } | null {
  if (!flowMap || flowMap.length === 0) return null;

  const byTitle = new Map<string, ConsolidatedFindingLike>();
  for (const finding of consolidatedFindings || []) {
    if (finding.title) byTitle.set(finding.title, finding);
  }

  const groupCounts = new Map<string, number>();
  const statusCounts = new Map<string, number>();
  const outputCounts = new Map<string, number>();
  const leftToStage = new Map<string, number>();
  const stageToOutput = new Map<string, number>();

  for (const fm of flowMap) {
    const status = normaliseStatus(fm.status);
    const consolidated = byTitle.get(fm.consolidated_title);
    const group = (() => {
      if (mode === "source") return fm.raw_source || "unknown";
      if (mode === "agent") return fm.raw_source || "unknown";
      if (mode === "severity") return (fm.raw_severity || "INFO").toUpperCase();
      return fm.raw_cwe || "No CWE";
    })();
    const output = (() => {
      if (status === "dropped") return "Dropped";
      if (mode === "cwe") return consolidated?.cwe || "No CWE";
      return (consolidated?.severity || "INFO").toUpperCase();
    })();

    const groupId = `group_${encodeURIComponent(group)}`;
    const stageId = `stage_${status}`;
    const outputId = output === "Dropped" ? "dropped" : `out_${encodeURIComponent(output)}`;

    addCount(groupCounts, groupId);
    addCount(statusCounts, stageId);
    addCount(outputCounts, outputId);
    addCount(leftToStage, `${groupId}→${stageId}`);
    addCount(stageToOutput, `${stageId}→${outputId}`);
  }

  const nodes: SankeyNode[] = [];
  for (const [id, count] of Array.from(groupCounts.entries()).sort((a, b) => b[1] - a[1])) {
    const label = decodeURIComponent(id.replace("group_", ""));
    nodes.push({ id, label: `${compactLabel(label)} (${count})` });
  }
  for (const [id, count] of Array.from(statusCounts.entries()).sort((a, b) => b[1] - a[1])) {
    nodes.push({ id, label: `${statusLabel(normaliseStatus(id.replace("stage_", "")))} (${count})` });
  }
  for (const [id, count] of Array.from(outputCounts.entries()).sort((a, b) => b[1] - a[1])) {
    const label = id === "dropped" ? "Dropped" : decodeURIComponent(id.replace("out_", ""));
    nodes.push({ id, label: `${compactLabel(label)} (${count})` });
  }

  const links: SankeyLink[] = [];
  for (const [key, value] of leftToStage.entries()) {
    const [source, target] = key.split("→");
    links.push({ source, target, value });
  }
  for (const [key, value] of stageToOutput.entries()) {
    const [source, target] = key.split("→");
    links.push({ source, target, value });
  }

  return { nodes, links };
}

function renderFullSankey(
  nodes: SankeyNode[],
  links: SankeyLink[],
): React.ReactNode {
  // Group nodes by column
  const cols: SankeyNode[][] = [[], [], []];
  for (const n of nodes) {
    cols[columnForId(n.id)].push(n);
  }

  // Even-spaced layout within each column
  const layoutMap = new Map<string, { x: number; y: number }>();
  for (let ci = 0; ci < 3; ci++) {
    const colNodes = cols[ci];
    const colX = columnPosition(ci as 0 | 1 | 2);
    let y = PAD_Y;
    // If only one node, center it
    if (colNodes.length === 1) {
      const centerY = Math.max(80, PAD_Y);
      layoutMap.set(colNodes[0].id, { x: colX, y: centerY });
    } else {
      for (const n of colNodes) {
        layoutMap.set(n.id, { x: colX, y });
        y += NODE_H + 12;
      }
    }
  }

  const maxY = Math.max(160, ...Array.from(layoutMap.values()).map(l => l.y) as number[]) + NODE_H + PAD_Y;

  // Deduplicate links
  const linkMap = new Map<string, number>();
  for (const l of links) {
    const key = `${l.source}→${l.target}`;
    linkMap.set(key, (linkMap.get(key) || 0) + l.value);
  }

  return (
    <svg width={CANVAS_W} height={maxY} style={{ fontFamily: "var(--font-sans)", fontSize: 10 }}>
      {/* Links */}
      {Array.from(linkMap.entries()).map(([key, value]) => {
        const [src, tgt] = key.split("→");
        const sPos = layoutMap.get(src);
        const tPos = layoutMap.get(tgt);
        if (!sPos || !tPos) return null;
        const sx = sPos.x + NODE_W;
        const sy = sPos.y + NODE_H / 2;
        const tx = tPos.x;
        const ty = tPos.y + NODE_H / 2;
        const color = nodeColor(src);
        const w = Math.max(1.5, Math.min(12, (value / Math.max(1, links.length)) * 18));
        const path = `M${sx},${sy} C${sx + 60},${sy} ${tx - 60},${ty} ${tx},${ty}`;
        return (
          <g key={key}>
            <path d={path} fill="none" stroke={color} strokeWidth={w} strokeOpacity={0.35} />
            <text x={(sx + tx) / 2} y={sy + (ty - sy) * 0.4} textAnchor="middle" fill={color} fontSize={9} fontWeight={600}>
              {value}
            </text>
          </g>
        );
      })}

      {/* Nodes */}
      {Array.from(layoutMap.entries()).map(([id, pos]) => {
        const label = nodes.find(n => n.id === id)?.label ?? id;
        const color = nodeColor(id);
        const isDropped = id.endsWith("_dropped") || id === "dropped";
        return (
          <g key={id}>
            <rect x={pos.x} y={pos.y} width={NODE_W} height={NODE_H} rx={6}
              fill={color} fillOpacity={0.15} stroke={color}
              strokeWidth={isDropped ? 1 : 1.5}
              strokeDasharray={isDropped ? "4 2" : undefined} />
            <text x={pos.x + NODE_W / 2} y={pos.y + NODE_H / 2}
              textAnchor="middle" fill={color} fontSize={10} fontWeight={600}
              dominantBaseline="central"
              style={{ textTransform: "none" }}>
              {label}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

// ── Component ─────────────────────────────────────────────────────

export const ElaborateSankey: React.FC<Props> = ({
  mode,
  sourceGroups,
  severityGroups,
  cweGroups,
  agentGroups,
  consolidatedCount,
  fullSankeyNodes,
  fullSankeyLinks,
  flowMap,
  consolidatedFindings,
}) => {
  // Fallback: simple single-column sankey data (always computed)
  const data = useMemo(() => {
    let groups: Record<string, number>;
    if (mode === "source") {
      groups = sourceGroups;
    } else if (mode === "agent") {
      groups = agentGroups;
    } else if (mode === "severity") {
      groups = severityGroups;
    } else if (mode === "cwe") {
      groups = cweGroups;
    } else {
      const sastSources = new Set(["bandit", "semgrep", "gitleaks", "osv"]);
      let sast = 0;
      let llm = 0;
      for (const [k, v] of Object.entries(sourceGroups)) {
        if (sastSources.has(k)) sast += v;
        else llm += v;
      }
      groups = {};
      if (sast > 0) groups["sast"] = sast;
      if (llm > 0) groups["llm"] = llm;
    }
    return buildNodes(mode, groups);
  }, [mode, sourceGroups, severityGroups, cweGroups, agentGroups]);

  const groupedFlow = useMemo(
    () => mode === "source_type" ? null : buildGroupedFlowSankey(mode, flowMap, consolidatedFindings),
    [mode, flowMap, consolidatedFindings],
  );

  // Type uses the backend's detailed SAST → raw-agent → final-severity view.
  // Other modes build the same three-column shape from the flow map, grouped
  // by the selected dimension.
  if (
    mode === "source_type"
    && fullSankeyNodes
    && fullSankeyNodes.length > 0
    && fullSankeyLinks
    && fullSankeyLinks.length > 0
  ) {
    return <>{renderFullSankey(fullSankeyNodes, fullSankeyLinks)}</>;
  }
  if (groupedFlow && groupedFlow.nodes.length > 0 && groupedFlow.links.length > 0) {
    return <>{renderFullSankey(groupedFlow.nodes, groupedFlow.links)}</>;
  }

  const leftNodes = data.nodes.filter(n => n.id !== "consolidated");
  const rightNode = { id: "consolidated", label: `Consolidated (${consolidatedCount})`, value: consolidatedCount, color: "#10b981" };

  const totalLeft = leftNodes.reduce((s, n) => s + n.value, 0);
  const canvasH = Math.max(160, leftNodes.length * (NODE_H + 10) + PAD_Y * 2);

  return (
    <svg
      width={CANVAS_W}
      height={canvasH}
      style={{ fontFamily: "var(--font-sans)", fontSize: 11 }}
    >
      {leftNodes.map((node, i) => {
        const sy = PAD_Y + i * (NODE_H + 10) + NODE_H / 2;
        const tx = CANVAS_W - NODE_W - PAD_X;
        const ty = canvasH / 2;
        const path = `M${PAD_X + NODE_W},${sy} C${PAD_X + NODE_W + 80},${sy} ${tx - 80},${ty} ${tx},${ty}`;
        const w = Math.max(2, Math.min(18, (node.value / Math.max(1, totalLeft)) * 24));
        return (
          <g key={`link-${node.id}`}>
            <path d={path} fill="none" stroke={node.color} strokeWidth={w} strokeOpacity={0.5} />
            <text x={(PAD_X + NODE_W + tx) / 2} y={sy + (ty - sy) * 0.4} textAnchor="middle" fill={node.color} fontSize={11} fontWeight={600}>
              {node.value}
            </text>
          </g>
        );
      })}
      {leftNodes.map((node, i) => (
        <g key={node.id}>
          <rect x={PAD_X} y={PAD_Y + i * (NODE_H + 10)} width={NODE_W} height={NODE_H} rx={6} fill={node.color} fillOpacity={0.15} stroke={node.color} strokeWidth={1.5} />
          <text x={PAD_X + NODE_W / 2} y={PAD_Y + i * (NODE_H + 10) + NODE_H / 2} textAnchor="middle" fill={node.color} fontSize={11} fontWeight={600} dominantBaseline="central">
            {node.label} ({node.value})
          </text>
        </g>
      ))}
      <g>
        <rect x={CANVAS_W - NODE_W - PAD_X} y={canvasH / 2 - NODE_H / 2} width={NODE_W} height={NODE_H} rx={6} fill={rightNode.color} fillOpacity={0.2} stroke={rightNode.color} strokeWidth={2} />
        <text x={CANVAS_W - NODE_W / 2 - PAD_X} y={canvasH / 2} textAnchor="middle" fill={rightNode.color} fontSize={12} fontWeight={700} dominantBaseline="central">
          {rightNode.label}
        </text>
      </g>
    </svg>
  );
};
