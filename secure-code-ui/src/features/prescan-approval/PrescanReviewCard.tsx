// secure-code-ui/src/features/prescan-approval/PrescanReviewCard.tsx
//
// Inline card on the scan-status page that lists deterministic-scanner
// findings already produced by the worker (Bandit / Semgrep / Gitleaks
// / OSV) and asks the operator whether to continue to the LLM phase.
// ADR-009 / G6.
//
// The card itself is dumb: it renders the props and forwards click
// events. The host page (`ScanRunningPage`) owns the API calls and the
// override-modal lifecycle.

import React from "react";
import { Icon } from "../../shared/ui/Icon";
import type { PrescanFindingItem } from "../../shared/types/api";

interface Props {
  findings: PrescanFindingItem[];
  hasCriticalSecret: boolean;
  approving: boolean;
  declining: boolean;
  onContinue: () => void;
  onStop: () => void;
  // When the gate has already closed (terminal block / decline) the
  // card is shown read-only as an audit view.
  readOnly?: boolean;
}

const ENTITIES: Record<string, string> = {
  "&amp;": "&",
  "&lt;": "<",
  "&gt;": ">",
  "&quot;": '"',
  "&#x27;": "'",
  "&#39;": "'",
  "&apos;": "'",
  "&nbsp;": " ",
};

/** Render scanner text as text: decode the entities scanners HTML-escape with. */
function decodeEntities(value?: string | null): string {
  if (!value) return "";
  return value.replace(/&(?:amp|lt|gt|quot|apos|nbsp|#x27|#39);/g, (m) => ENTITIES[m] ?? m);
}

/** Tail of a path, so it stays on one line: `…/src/app/App.tsx`. */
function shortPath(path: string): string {
  const parts = path.split("/");
  if (parts.length <= 3) return path;
  return `…/${parts.slice(-3).join("/")}`;
}

const SEVERITY_ORDER: Record<string, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
  Informational: 4,
};

function severityChipClass(sev?: string | null): string {
  if (sev === "Critical") return "chip chip-critical";
  if (sev === "High") return "chip chip-high";
  if (sev === "Medium") return "chip chip-medium";
  if (sev === "Low") return "chip chip-low";
  return "chip";
}

export const PrescanReviewCard: React.FC<Props> = ({
  findings,
  hasCriticalSecret,
  approving,
  declining,
  onContinue,
  onStop,
  readOnly = false,
}) => {
  const sorted = React.useMemo(() => {
    return [...findings].sort((a, b) => {
      const sa = SEVERITY_ORDER[a.severity || ""] ?? 99;
      const sb = SEVERITY_ORDER[b.severity || ""] ?? 99;
      if (sa !== sb) return sa - sb;
      return a.file_path.localeCompare(b.file_path);
    });
  }, [findings]);

  const counts = React.useMemo(() => {
    const c = new Map<string, number>();
    for (const f of findings) {
      const k = f.severity || "Unknown";
      c.set(k, (c.get(k) ?? 0) + 1);
    }
    return c;
  }, [findings]);

  return (
    <div
      className="sccap-card prescan-review-card"
      style={{
        background: hasCriticalSecret ? "var(--critical-weak)" : "var(--bg-soft)",
        borderColor: "var(--border)",
        borderLeftWidth: 3,
        borderLeftStyle: "solid",
        borderLeftColor: hasCriticalSecret ? "var(--critical)" : "var(--medium)",
      }}
    >
      <div
        className="prescan-review-header"
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 12,
          marginBottom: 12,
        }}
      >
        <div style={{ minWidth: 0 }}>
          <div
            style={{
              fontWeight: 600,
              color: hasCriticalSecret ? "var(--critical)" : "var(--fg)",
              marginBottom: 4,
              display: "flex",
              alignItems: "center",
              gap: 8,
            }}
          >
            {hasCriticalSecret ? <Icon.Alert size={14} /> : <Icon.Shield size={14} />}
            {readOnly
              ? "Pre-LLM scan findings"
              : "Review the pre-LLM scan findings before continuing"}
          </div>
          <div style={{ color: "var(--fg)", fontSize: 13 }}>
            Deterministic scanners found {findings.length} issue
            {findings.length === 1 ? "" : "s"}
            {hasCriticalSecret
              ? ". A Critical-severity secret was detected — continuing will send the affected source to your LLM provider."
              : ". You can continue to the LLM phase or stop the scan here."}
          </div>
          <div
            style={{
              display: "flex",
              gap: 6,
              marginTop: 8,
              flexWrap: "wrap",
            }}
          >
            {Array.from(counts.entries()).map(([sev, n]) => (
              <span key={sev} className={severityChipClass(sev)}>
                {sev} · {n}
              </span>
            ))}
          </div>
        </div>
        {!readOnly && (
          <div
            className="prescan-review-actions"
            style={{ display: "flex", gap: 8, flexShrink: 0 }}
          >
            <button
              className="sccap-btn"
              onClick={onStop}
              disabled={declining || approving}
            >
              {declining ? "Stopping…" : "Stop scan"}
            </button>
            <button
              className={`sccap-btn ${
                hasCriticalSecret ? "sccap-btn-danger" : "sccap-btn-primary"
              }`}
              onClick={onContinue}
              disabled={approving || declining}
            >
              {approving
                ? "Continuing…"
                : hasCriticalSecret
                  ? "Continue anyway…"
                  : "Continue to LLM"}
            </button>
          </div>
        )}
      </div>

      <div
        className="prescan-findings-table"
        style={{
          maxHeight: 280,
          overflowY: "auto",
          overflowX: "hidden",
          background: "var(--bg)",
          border: "1px solid var(--border)",
          borderRadius: 6,
        }}
      >
        <table
          style={{
            width: "100%",
            tableLayout: "fixed",
            borderCollapse: "collapse",
            fontSize: 12.5,
          }}
        >
          <thead>
            <tr style={{ background: "var(--bg-soft)" }}>
              <th style={thStyle}>Severity</th>
              <th style={thStyle}>Source</th>
              <th style={thStyle}>File</th>
              <th style={thStyle}>Line</th>
              <th style={thStyle}>Title</th>
              <th style={thStyle}>CWE / CVE</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((f) => (
              <React.Fragment key={f.id}>
              <tr
                style={{
                  borderTop: "1px solid var(--border)",
                }}
              >
                <td style={tdStyle}>
                  <span className={severityChipClass(f.severity)}>
                    {f.severity || "—"}
                  </span>
                </td>
                <td style={tdStyle}>
                  <code style={{ fontSize: 11 }}>{f.source || "—"}</code>
                </td>
                <td style={{ ...tdStyle, width: "26%" }} title={f.file_path}>
                  <code style={pathStyle}>{shortPath(f.file_path)}</code>
                </td>
                <td style={{ ...tdStyle, fontVariantNumeric: "tabular-nums" }}>
                  {f.line_number ?? "—"}
                </td>
                <td
                  style={{ ...tdStyle, width: "28%", overflowWrap: "anywhere" }}
                  title={f.title}
                >
                  {f.title}
                </td>
                <td style={tdStyle}>
                  <span style={{ display: "block", fontSize: 11 }}>
                    {f.cwe || ""}
                  </span>
                  {f.cve_id && (
                    <span style={{ display: "block", fontSize: 11, color: "var(--fg-muted)" }}>
                      {f.cve_id}
                    </span>
                  )}
                </td>
              </tr>
              {(f.vulnerable_snippet || f.description) && (
                <tr>
                  <td colSpan={6} style={snippetCellStyle}>
                    {f.vulnerable_snippet && (
                      <pre style={snippetStyle}>
                        <span style={lineNumberStyle}>{f.line_number ?? ""}</span>
                        <code>{decodeEntities(f.vulnerable_snippet)}</code>
                      </pre>
                    )}
                    {f.description && (
                      <div style={descriptionStyle}>
                        {decodeEntities(f.description)}
                      </div>
                    )}
                  </td>
                </tr>
              )}
              </React.Fragment>
            ))}
            {sorted.length === 0 && (
              <tr>
                <td colSpan={6} style={{ ...tdStyle, color: "var(--fg-muted)" }}>
                  No findings — the gate is open. (You should not normally see
                  this card with zero findings; if you do, the worker is
                  awaiting cost approval shortly.)
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

const pathStyle: React.CSSProperties = {
  display: "block",
  fontSize: 11,
  whiteSpace: "nowrap",
  overflow: "hidden",
  textOverflow: "ellipsis",
  direction: "rtl",
  textAlign: "left",
  unicodeBidi: "plaintext",
};

const snippetCellStyle: React.CSSProperties = {
  padding: "0 10px 8px 10px",
  background: "var(--bg)",
};

const snippetStyle: React.CSSProperties = {
  display: "flex",
  gap: 10,
  margin: 0,
  padding: "6px 8px",
  borderRadius: 4,
  background: "var(--bg-inset, var(--bg-soft))",
  border: "1px solid var(--border)",
  fontSize: 11.5,
  lineHeight: 1.5,
  whiteSpace: "pre-wrap",
  overflowWrap: "anywhere",
  maxHeight: 160,
  overflowY: "auto",
};

const lineNumberStyle: React.CSSProperties = {
  flex: "0 0 auto",
  color: "var(--fg-subtle)",
  fontVariantNumeric: "tabular-nums",
  userSelect: "none",
};

const descriptionStyle: React.CSSProperties = {
  marginTop: 4,
  fontSize: 11.5,
  lineHeight: 1.5,
  color: "var(--fg-muted)",
  whiteSpace: "pre-wrap",
};

const thStyle: React.CSSProperties = {
  textAlign: "left",
  padding: "8px 10px",
  fontSize: 11,
  fontWeight: 600,
  textTransform: "uppercase",
  letterSpacing: "0.04em",
  color: "var(--fg-muted)",
  position: "sticky",
  top: 0,
  background: "var(--bg-soft)",
  overflowWrap: "anywhere",
};

const tdStyle: React.CSSProperties = {
  padding: "8px 10px",
  verticalAlign: "top",
  overflowWrap: "anywhere",
};

export default PrescanReviewCard;
