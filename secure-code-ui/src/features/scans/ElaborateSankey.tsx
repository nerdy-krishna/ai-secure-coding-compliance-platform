// Elaborate Sankey diagram for findings pipeline debugging.
// Supports grouping modes: by source, by severity, by CWE, by source-type.
// Pure SVG — no chart library dependency.

import React, { useMemo } from "react";

export type SankeyMode = "source" | "source_type" | "agent" | "severity" | "cwe";

interface Props {
  mode: SankeyMode;
  sourceGroups: Record<string, number>;
  severityGroups: Record<string, number>;
  cweGroups: Record<string, number>;
  agentGroups: Record<string, number>;
  consolidatedCount: number;
}

const PALETTE = [
  "#6366f1", "#8b5cf6", "#a855f7", "#d946ef", "#ec4899",
  "#f43f5e", "#ef4444", "#f97316", "#eab308", "#84cc16",
  "#22c55e", "#10b981", "#14b8a6", "#06b6d4", "#0ea5e9",
  "#3b82f6", "#64748b", "#78716c",
];

const NODE_W = 130;
const NODE_H = 34;
const PAD_X = 20;
const PAD_Y = 20;
const CANVAS_W = 700;

function buildNodes(mode: SankeyMode, groups: Record<string, number>): {
  nodes: Array<{ id: string; label: string; value: number; color: string }>;
} {
  const entries = Object.entries(groups)
    .filter(([, v]) => v > 0)
    .sort((a, b) => b[1] - a[1]);
  const nodes = entries.map(([key, value], i) => ({
    id: key,
    label: mode === "source_type"
      ? key === "sast" ? "SAST Tools" : "LLM Agents"
      : key,
    value,
    color: PALETTE[i % PALETTE.length],
  }));
  return { nodes };
}

export const ElaborateSankey: React.FC<Props> = ({
  mode,
  sourceGroups,
  severityGroups,
  cweGroups,
  agentGroups,
  consolidatedCount,
}) => {
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
      // source_type: group SAST tools together vs LLM agents
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
      {/* Links from left nodes to consolidated */}
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

      {/* Left nodes */}
      {leftNodes.map((node, i) => (
        <g key={node.id}>
          <rect x={PAD_X} y={PAD_Y + i * (NODE_H + 10)} width={NODE_W} height={NODE_H} rx={6} fill={node.color} fillOpacity={0.15} stroke={node.color} strokeWidth={1.5} />
          <text x={PAD_X + NODE_W / 2} y={PAD_Y + i * (NODE_H + 10) + NODE_H / 2} textAnchor="middle" fill={node.color} fontSize={11} fontWeight={600} dominantBaseline="central">
            {node.label} ({node.value})
          </text>
        </g>
      ))}

      {/* Right node (consolidated) */}
      <g>
        <rect x={CANVAS_W - NODE_W - PAD_X} y={canvasH / 2 - NODE_H / 2} width={NODE_W} height={NODE_H} rx={6} fill={rightNode.color} fillOpacity={0.2} stroke={rightNode.color} strokeWidth={2} />
        <text x={CANVAS_W - NODE_W / 2 - PAD_X} y={canvasH / 2} textAnchor="middle" fill={rightNode.color} fontSize={12} fontWeight={700} dominantBaseline="central">
          {rightNode.label}
        </text>
      </g>
    </svg>
  );
};
