import React from "react";
import { Icon } from "./Icon";

export interface Tile {
  label: string;
  value: string;
  sub?: string;
  tone?: "ok" | "warn" | "bad";
  icon: React.ReactNode;
}

/** One number, one label, one qualifier — the only tile shape in the app. */
export const StatTile: React.FC<Tile> = ({ label, value, sub, tone, icon }) => (
  <div className={`stat-card${tone ? ` is-${tone}` : ""}`}>
    <div className="stat-icon">{icon}</div>
    <div>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  </div>
);

export const StatGrid: React.FC<{ tiles: Tile[] }> = ({ tiles }) => (
  <div className="stat-grid">
    {tiles.map((tile) => (
      <StatTile key={tile.label} {...tile} />
    ))}
  </div>
);

/**
 * The tiles every scanning surface shares, in one fixed order:
 * work → findings → what the model consumed.
 *
 * Both products and all three pages (overview, code-scanning projects, pentesting
 * projects) render this same prefix so a reader moving between them reads the same
 * numbers in the same position. Product-specific tiles follow it.
 */
export function sharedTiles(input: {
  projects: number;
  projectsSub?: string;
  projectsTone?: "ok" | "warn" | "bad";
  runsLabel: string;
  runs: number;
  runsSub?: string;
  runsTone?: "ok" | "warn" | "bad";
  findings: number;
  findingsSub?: string;
  findingsTone?: "ok" | "warn" | "bad";
  tokens: { input_tokens: number; output_tokens: number; total_tokens: number };
  cost: number | null;
}): Tile[] {
  const tokens = input.tokens.total_tokens || input.tokens.input_tokens + input.tokens.output_tokens;
  return [
    {
      label: "Projects",
      value: String(input.projects),
      sub: input.projectsSub ?? "assessed estates",
      tone: input.projectsTone,
      icon: <Icon.Folder size={15} />,
    },
    {
      label: input.runsLabel,
      value: String(input.runs),
      sub: input.runsSub,
      tone: input.runsTone,
      icon: <Icon.Layers size={15} />,
    },
    {
      label: "Findings",
      value: String(input.findings),
      sub: input.findingsSub ?? "none critical",
      tone: input.findingsTone,
      icon: <Icon.Flag size={15} />,
    },
    {
      label: "Tokens",
      value: compact(input.tokens.input_tokens),
      sub: `out ${compact(input.tokens.output_tokens)} · ${compact(tokens)} total`,
      icon: <Icon.Sparkle size={15} />,
    },
    {
      label: "Est. cost",
      value: input.cost != null ? `≈$${input.cost.toFixed(2)}` : "—",
      sub: input.cost != null ? "ledger-priced, 30 days" : "not priced yet",
      icon: <Icon.Dollar size={15} />,
    },
  ];
}

export function compact(value: number | null | undefined): string {
  if (value === null || value === undefined) return "0";
  if (value < 1000) return String(value);
  if (value < 1_000_000) return `${(value / 1000).toFixed(value < 10_000 ? 1 : 0)}k`;
  return `${(value / 1_000_000).toFixed(1)}M`;
}
