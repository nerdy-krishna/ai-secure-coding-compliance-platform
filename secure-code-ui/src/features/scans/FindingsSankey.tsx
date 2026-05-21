// Simple Sankey flow for findings pipeline debugging.
// Three nodes: SAST → Consolidated, Raw LLM → Consolidated.
// Pure SVG — no chart library dependency.

import React from "react";
import type { SankeyNode, SankeyLink } from "../../shared/api/debugService";

interface Props {
  nodes: SankeyNode[];
  links: SankeyLink[];
}

const COLORS: Record<string, string> = {
  sast: "#f59e0b",        // amber
  raw_llm: "#6366f1",     // indigo
  consolidated: "#10b981", // emerald
};

const NODE_W = 140;
const NODE_H = 48;
const PAD = 30;
const CANVAS_W = 520;
const CANVAS_H = 200;

function nodeX(id: string): number {
  if (id === "sast" || id === "raw_llm") return PAD;
  return CANVAS_W - NODE_W - PAD;
}

function nodeY(id: string): number {
  if (id === "sast") return PAD + 10;
  if (id === "raw_llm") return CANVAS_H - NODE_H - PAD - 10;
  return (CANVAS_H - NODE_H) / 2;
}

export const FindingsSankey: React.FC<Props> = ({ nodes, links }) => {
  return (
    <svg
      width={CANVAS_W}
      height={CANVAS_H}
      style={{ fontFamily: "var(--font-sans)", fontSize: 12 }}
    >
      {/* Links (curved paths) */}
      {links.map((link) => {
        const sx = nodeX(link.source) + NODE_W;
        const sy = nodeY(link.source) + NODE_H / 2;
        const tx = nodeX(link.target);
        const ty = nodeY(link.target) + NODE_H / 2;
        const cy = (sy + ty) / 2;
        const path = `M${sx},${sy} C${sx + 60},${sy} ${tx - 60},${ty} ${tx},${ty}`;
        const color = COLORS[link.source] || "#888";
        const w = Math.max(3, Math.min(24, link.value * 3));
        return (
          <g key={`${link.source}-${link.target}`}>
            <path
              d={path}
              fill="none"
              stroke={color}
              strokeWidth={w}
              strokeOpacity={0.6}
            />
            <text
              x={(sx + tx) / 2}
              y={cy}
              textAnchor="middle"
              fill={color}
              fontSize={13}
              fontWeight={600}
              dominantBaseline="central"
            >
              {link.value}
            </text>
          </g>
        );
      })}

      {/* Nodes */}
      {nodes.map((node) => {
        const x = nodeX(node.id);
        const y = nodeY(node.id);
        const color = COLORS[node.id] || "#888";
        return (
          <g key={node.id}>
            <rect
              x={x}
              y={y}
              width={NODE_W}
              height={NODE_H}
              rx={8}
              fill={color}
              fillOpacity={0.15}
              stroke={color}
              strokeWidth={1.5}
            />
            <text
              x={x + NODE_W / 2}
              y={y + NODE_H / 2}
              textAnchor="middle"
              fill={color}
              fontSize={12}
              fontWeight={600}
              dominantBaseline="central"
            >
              {node.label}
            </text>
          </g>
        );
      })}
    </svg>
  );
};
