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

interface Props {
  mode: SankeyMode;
  sourceGroups: Record<string, number>;
  severityGroups: Record<string, number>;
  cweGroups: Record<string, number>;
  agentGroups: Record<string, number>;
  consolidatedCount: number;
  fullSankeyNodes?: SankeyNode[] | null;
  fullSankeyLinks?: SankeyLink[] | null;
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

function nodeColor(nodeId: string): string {
  if (nodeId.startsWith("sast_")) {
    const tool = nodeId.replace("sast_", "");
    return COLORS[tool] || "#64748b";
  }
  if (nodeId.startsWith("raw_")) {
    if (nodeId.endsWith("_dropped")) return COLORS.dropped;
    if (nodeId.endsWith("_pass")) return COLORS.passthrough;
    return COLORS.merged;
  }
  if (nodeId.startsWith("cons_")) {
    const sev = nodeId.replace("cons_", "");
    return COLORS[sev] || "#64748b";
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
  if (id.startsWith("sast_")) return 0;
  if (id.startsWith("raw_")) return 1;
  if (id.startsWith("cons_") || id === "dropped") return 2;
  return 1;
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

  // If we have full sankey data, render the rich three-column version
  if (fullSankeyNodes && fullSankeyNodes.length > 0 && fullSankeyLinks && fullSankeyLinks.length > 0) {
    return <>{renderFullSankey(fullSankeyNodes, fullSankeyLinks)}</>;
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
