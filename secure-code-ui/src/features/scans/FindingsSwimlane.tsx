import React, { useMemo, useState } from "react";
import { Icon } from "../../shared/ui/Icon";
import type { Finding } from "../../shared/types/api";

/**
 * Findings swimlane — what each detection source claimed, and where those claims
 * ended up.
 *
 * Rows are lanes, one per detection source (an agent or a scanner). Left column:
 * the raw findings that source produced. Right column: the consolidated findings
 * they were folded into. An edge exists only where consolidation actually merged
 * a raw finding, so the picture answers "who said this, and what did it become" —
 * and a raw finding with no edge is one consolidation dropped.
 */

const SEV_COLOR: Record<string, string> = {
  CRITICAL: "var(--critical)",
  HIGH: "var(--high)",
  MEDIUM: "var(--medium)",
  LOW: "var(--low)",
  INFORMATIONAL: "var(--info)",
};

function sevColor(severity?: string | null): string {
  return SEV_COLOR[(severity || "").toUpperCase()] ?? "var(--fg-subtle)";
}

const NODE_H = 26;
const NODE_GAP = 7;
const LANE_HEADER_H = 24;
const LANE_PAD = 10;
const GUTTER_W = 172;
const RAW_X = GUTTER_W + 16;
const RAW_W = 300;
const CONSOL_X = RAW_X + RAW_W + 132;
const CONSOL_W = 340;
const CHART_TOP = 40;

interface Lane {
  source: string;
  label: string;
  raw: Finding[];
  height: number;
  top: number;
}

interface PlacedRaw {
  finding: Finding;
  laneIndex: number;
  x: number;
  y: number;
  dropped: boolean;
  consolidatedId: string | null;
}

interface PlacedConsolidated {
  finding: Finding;
  x: number;
  y: number;
  fromCount: number;
}

const truncate = (value: string, max: number): string =>
  value.length > max ? `${value.slice(0, max - 1)}…` : value;

export const FindingsSwimlane: React.FC<{ debug: {
  raw_llm_findings: Finding[];
  consolidated_findings: Finding[];
  sast_findings: Finding[];
} }> = ({ debug }) => {
  const [hovered, setHovered] = useState<string | null>(null);

  const model = useMemo(() => {
    const raw = debug.raw_llm_findings ?? [];
    const consolidated = debug.consolidated_findings ?? [];

    // raw_finding_id → consolidated finding (the consolidator records the inputs).
    const mergedInto = new Map<string, Finding>();
    for (const finding of consolidated) {
      for (const id of finding.contributing_raw_finding_ids ?? []) {
        mergedInto.set(String(id), finding);
      }
    }

    const bySource = new Map<string, Finding[]>();
    for (const finding of raw) {
      const source = finding.source || "unattributed";
      const bucket = bySource.get(source);
      if (bucket) bucket.push(finding);
      else bySource.set(source, [finding]);
    }

    const lanes: Lane[] = [...bySource.entries()]
      .sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]))
      .map(([source, findings]) => ({
        source,
        label: source.replace(/^Asvs/, "").replace(/Agent$/, "") || source,
        raw: findings,
        height: LANE_HEADER_H + findings.length * (NODE_H + NODE_GAP) + LANE_PAD,
        top: 0,
      }));

    let cursor = CHART_TOP;
    for (const lane of lanes) {
      lane.top = cursor;
      cursor += lane.height;
    }

    const placedRaw: PlacedRaw[] = [];
    lanes.forEach((lane, laneIndex) => {
      lane.raw.forEach((finding, index) => {
        const consolidatedFinding = mergedInto.get(String(finding.raw_finding_id));
        placedRaw.push({
          finding,
          laneIndex,
          x: RAW_X,
          y: lane.top + LANE_HEADER_H + index * (NODE_H + NODE_GAP),
          dropped: !consolidatedFinding,
          consolidatedId: consolidatedFinding ? String(consolidatedFinding.id) : null,
        });
      });
    });

    // Consolidated nodes sit opposite the middle of their contributors, pushed
    // down as needed so they never overlap.
    const byConsolidated = new Map<string, PlacedRaw[]>();
    for (const node of placedRaw) {
      if (!node.consolidatedId) continue;
      const bucket = byConsolidated.get(node.consolidatedId);
      if (bucket) bucket.push(node);
      else byConsolidated.set(node.consolidatedId, [node]);
    }

    const ordered = [...byConsolidated.entries()].sort(
      (a, b) =>
        a[1][0].y - b[1][0].y || a[1].length - b[1].length,
    );

    const placedConsolidated: PlacedConsolidated[] = [];
    let minY = CHART_TOP;
    for (const [id, contributors] of ordered) {
      const finding = contributors[0].consolidatedId
        ? consolidated.find((row) => String(row.id) === id)
        : undefined;
      if (!finding) continue;
      const centre =
        contributors.reduce((sum, node) => sum + node.y + NODE_H / 2, 0) /
        contributors.length;
      const y = Math.max(minY, centre - NODE_H / 2);
      placedConsolidated.push({
        finding,
        x: CONSOL_X,
        y,
        fromCount: contributors.length,
      });
      minY = y + NODE_H + NODE_GAP;
    }

    const orphaned = consolidated.filter(
      (finding) => !byConsolidated.has(String(finding.id)),
    );

    const width = CONSOL_X + CONSOL_W + 24;
    const height = Math.max(
      cursor,
      (placedConsolidated[placedConsolidated.length - 1]?.y ?? CHART_TOP) + NODE_H + 24,
    );

    return { lanes, placedRaw, placedConsolidated, orphaned, width, height };
  }, [debug]);

  const { lanes, placedRaw, placedConsolidated, orphaned, width, height } = model;
  const totalRaw = placedRaw.length;
  const dropped = placedRaw.filter((node) => node.dropped).length;

  if (totalRaw === 0 && placedConsolidated.length === 0) {
    return (
      <div className="surface" style={{ padding: 24, color: "var(--fg-muted)", fontSize: 13 }}>
        <Icon.Layers size={14} /> No LLM findings were produced by this scan, so
        there is nothing to consolidate.
      </div>
    );
  }

  const isDimmed = (kind: "raw" | "consolidated", id: string): boolean => {
    if (!hovered) return false;
    if (kind === "raw") {
      const node = placedRaw.find((candidate) => String(candidate.finding.id) === id);
      return !!node && node.consolidatedId !== hovered;
    }
    return id !== hovered;
  };

  return (
    <section className="sccap-card" style={{ display: "grid", gap: 12, padding: 16 }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
        <div>
          <div style={{ fontWeight: 600, fontSize: 13.5 }}>Findings consolidation</div>
          <div style={{ color: "var(--fg-muted)", fontSize: 12, marginTop: 2 }}>
            One lane per detection source. Raw claims on the left, the findings they
            became on the right; a line exists only where consolidation merged them.
          </div>
        </div>
        <div style={{ display: "flex", gap: 14, alignItems: "baseline", fontSize: 12 }}>
          <span style={{ color: "var(--fg-muted)" }}>
            <strong style={{ color: "var(--fg)", fontSize: 13 }}>{totalRaw}</strong> raw
          </span>
          <span style={{ color: "var(--fg-muted)" }}>
            <strong style={{ color: "var(--fg)", fontSize: 13 }}>
              {placedConsolidated.length}
            </strong>{" "}
            consolidated
          </span>
          <span style={{ color: "var(--fg-muted)" }}>
            <strong style={{ color: dropped ? "var(--high)" : "var(--fg)", fontSize: 13 }}>
              {dropped}
            </strong>{" "}
            dropped
          </span>
        </div>
      </div>

      <div
        style={{
          overflow: "auto",
          border: "1px solid var(--border)",
          borderRadius: 10,
          maxHeight: "min(62vh, 620px)",
        }}
      >
        <svg
          width={Math.max(width, 720)}
          height={height + 8}
          role="img"
          aria-label="Swimlane diagram of raw findings merging into consolidated findings"
          style={{ display: "block", background: "var(--bg)" }}
        >
          <defs>
            <marker id="lane-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto">
              <path d="M0,0 L8,4 L0,8 z" fill="currentColor" opacity="0.55" />
            </marker>
          </defs>

          {/* Column headers */}
          <text x={RAW_X} y={22} fontSize={9.5} fontWeight={700} letterSpacing=".06em" fill="var(--fg-subtle)">
            RAW FINDINGS
          </text>
          <text x={CONSOL_X} y={22} fontSize={9.5} fontWeight={700} letterSpacing=".06em" fill="var(--fg-subtle)">
            CONSOLIDATED FINDINGS
          </text>

          {/* Lanes */}
          {lanes.map((lane, index) => (
            <g key={lane.source}>
              <rect
                x={8}
                y={lane.top}
                width={width - 16}
                height={lane.height}
                rx={8}
                fill={index % 2 === 0 ? "var(--bg-soft)" : "transparent"}
              />
              <text
                x={20}
                y={lane.top + 17}
                fontSize={11.5}
                fontWeight={600}
                fill="var(--fg)"
              >
                {truncate(lane.label, 20)}
              </text>
              <text x={20} y={lane.top + 32} fontSize={10.5} fill="var(--fg-subtle)">
                {lane.raw.length} claim{lane.raw.length === 1 ? "" : "s"}
              </text>
            </g>
          ))}

          {/* Edges */}
          {placedRaw.map((node) => {
            if (!node.consolidatedId) return null;
            const target = placedConsolidated.find(
              (candidate) => String(candidate.finding.id) === node.consolidatedId,
            );
            if (!target) return null;
            const x1 = node.x + RAW_W;
            const y1 = node.y + NODE_H / 2;
            const x2 = target.x;
            const y2 = target.y + NODE_H / 2;
            const midX = (x1 + x2) / 2;
            const highlighted = hovered === node.consolidatedId;
            return (
              <path
                key={`e-${node.finding.id}`}
                d={`M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`}
                fill="none"
                stroke={highlighted ? "var(--primary)" : "var(--border-strong, var(--fg-subtle))"}
                strokeOpacity={hovered && !highlighted ? 0.12 : highlighted ? 0.9 : 0.42}
                strokeWidth={highlighted ? 1.8 : 1.1}
                markerEnd="url(#lane-arrow)"
              />
            );
          })}

          <line
            x1={CONSOL_X - 66}
            y1={CHART_TOP - 14}
            x2={CONSOL_X - 66}
            y2={height - 8}
            stroke="var(--border)"
            strokeDasharray="3 4"
          />

          {/* Raw findings */}
          {placedRaw.map((node) => {
            const dim = isDimmed("raw", String(node.finding.id));
            return (
              <g
                key={`r-${node.finding.id}`}
                opacity={dim ? 0.28 : 1}
                onMouseEnter={() => node.consolidatedId && setHovered(node.consolidatedId)}
                onMouseLeave={() => setHovered(null)}
              >
                <title>
                  {`${node.finding.severity ?? "?"} · ${node.finding.file_path}:${node.finding.line_number ?? "?"}\n${node.finding.title}${node.dropped ? "\n(dropped by consolidation)" : ""}`}
                </title>
                <rect
                  x={node.x}
                  y={node.y}
                  width={RAW_W}
                  height={NODE_H}
                  rx={6}
                  fill={node.dropped ? "transparent" : "var(--bg)"}
                  stroke={node.dropped ? "var(--border)" : "var(--border-strong, var(--border))"}
                  strokeDasharray={node.dropped ? "4 3" : undefined}
                />
                <rect x={node.x} y={node.y} width={3} height={NODE_H} rx={1.5} fill={sevColor(node.finding.severity)} />
                <text x={node.x + 11} y={node.y + NODE_H / 2 + 3.5} fontSize={10.5} fill="var(--fg)">
                  {truncate(node.finding.title, 44)}
                </text>
              </g>
            );
          })}

          {/* Consolidated findings */}
          {placedConsolidated.map((node) => {
            const id = String(node.finding.id);
            const dim = isDimmed("consolidated", id);
            return (
              <g
                key={`c-${id}`}
                opacity={dim ? 0.45 : 1}
                onMouseEnter={() => setHovered(id)}
                onMouseLeave={() => setHovered(null)}
                style={{ cursor: "pointer" }}
              >
                <title>
                  {`${node.finding.severity ?? "?"} · merged from ${node.fromCount}\n${node.finding.title}`}
                </title>
                <rect
                  x={node.x}
                  y={node.y}
                  width={CONSOL_W}
                  height={NODE_H}
                  rx={6}
                  fill="var(--bg)"
                  stroke={hovered === id ? "var(--primary)" : "var(--border-strong, var(--border))"}
                  strokeWidth={hovered === id ? 1.6 : 1}
                />
                <rect x={node.x} y={node.y} width={3} height={NODE_H} rx={1.5} fill={sevColor(node.finding.severity)} />
                <text x={node.x + 11} y={node.y + NODE_H / 2 + 3.5} fontSize={10.5} fill="var(--fg)">
                  {truncate(node.finding.title, 46)}
                </text>
                {node.fromCount > 1 && (
                  <text
                    x={node.x + CONSOL_W - 8}
                    y={node.y + NODE_H / 2 + 3.5}
                    fontSize={9.5}
                    textAnchor="end"
                    fill="var(--fg-subtle)"
                  >
                    ×{node.fromCount}
                  </text>
                )}
              </g>
            );
          })}
        </svg>
      </div>

      {orphaned.length > 0 && (
        <div style={{ fontSize: 11.5, color: "var(--fg-muted)" }}>
          {orphaned.length} consolidated finding
          {orphaned.length === 1 ? "" : "s"} has no recorded raw input (legacy or
          pass-through rows) and is not drawn.
        </div>
      )}
    </section>
  );
};
