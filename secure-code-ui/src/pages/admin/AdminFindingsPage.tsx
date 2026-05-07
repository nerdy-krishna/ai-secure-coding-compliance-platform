// secure-code-ui/src/pages/admin/AdminFindingsPage.tsx
//
// Cross-tenant findings list (sast-prescan-followups Group D1).
// Doubly scoped server-side (current_superuser + visible_user_ids);
// the frontend hides the AdminSubNav entry from non-admins purely as
// UX, never as a security boundary.

import { useQuery } from "@tanstack/react-query";
import React, { useState } from "react";
import { Link } from "react-router-dom";
import type {
  AdminFindingItem,
  AdminFindingSource,
  AdminFindingsResponse,
} from "../../shared/api/adminFindings";
import { listAdminFindings } from "../../shared/api/adminFindings";
const SOURCE_OPTIONS: Array<{ value: AdminFindingSource | ""; label: string }> = [
  { value: "", label: "All" },
  { value: "bandit", label: "Bandit" },
  { value: "semgrep", label: "Semgrep" },
  { value: "gitleaks", label: "Gitleaks" },
  { value: "agent", label: "Agent (legacy LLM)" },
];

const SOURCE_COLORS: Record<string, string> = {
  bandit: "#3b82f6",
  semgrep: "#a855f7",
  gitleaks: "#dc2626",
  agent: "#6b7280",
};

function severityColor(sev: string | null | undefined): string {
  switch ((sev || "").toLowerCase()) {
    case "critical":
      return "#dc2626";
    case "high":
      return "#f97316";
    case "medium":
      return "#eab308";
    case "low":
      return "#3b82f6";
    default:
      return "#6b7280";
  }
}

const PAGE_LIMIT = 50;

const AdminFindingsPage: React.FC = () => {
  const [source, setSource] = useState<AdminFindingSource | "">("");
  const [cursor, setCursor] = useState<number | undefined>(undefined);
  const [pageHistory, setPageHistory] = useState<Array<number | undefined>>([
    undefined,
  ]);

  const { data, isLoading, isError, error } = useQuery<
    AdminFindingsResponse,
    Error
  >({
    queryKey: ["admin-findings", source, cursor],
    queryFn: () =>
      listAdminFindings({
        source: source || undefined,
        limit: PAGE_LIMIT,
        cursor,
      }),
  });

  const onSourceChange = (next: string) => {
    setSource((next as AdminFindingSource) || "");
    setCursor(undefined);
    setPageHistory([undefined]);
  };

  const items: AdminFindingItem[] = data?.items ?? [];
  const nextCursor = data?.next_cursor ?? null;
  const hasPrev = pageHistory.length > 1;

  return (
    <div className="fade-in" style={{ display: "grid", gap: 16 }}>
      <div>
        <h1 style={{ color: "var(--fg)" }}>Findings</h1>
      </div>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 12,
          flexWrap: "wrap",
        }}
      >
        <div style={{ marginLeft: "auto" }}>
          <label style={{ fontSize: 12.5, color: "var(--fg-muted)" }}>
            Source:&nbsp;
            <select
              value={source}
              onChange={(e) => onSourceChange(e.target.value)}
              style={{ padding: "4px 8px", borderRadius: 6 }}
            >
              {SOURCE_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </label>
        </div>
      </div>

      {isLoading && <div>Loading…</div>}
      {isError && (
        <div style={{ color: "var(--danger)" }}>
          Failed to load findings: {error?.message}
        </div>
      )}

      {!isLoading && !isError && (
        <>
          {items.length === 0 ? (
            <div style={{ color: "var(--fg-muted)" }}>No findings match the filter.</div>
          ) : (
            <div
              style={{
                border: "1px solid var(--border)",
                borderRadius: 8,
                overflowX: "auto",
              }}
            >
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ background: "var(--bg-soft)" }}>
                    <Th>Severity</Th>
                    <Th>Source</Th>
                    <Th>File</Th>
                    <Th>CWE</Th>
                    <Th>Title</Th>
                    <Th>Scan</Th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((item) => (
                    <tr key={item.id}>
                      <Td>
                        <span
                          style={{
                            padding: "2px 8px",
                            borderRadius: 6,
                            background: severityColor(item.severity),
                            color: "white",
                            fontSize: 11,
                            fontWeight: 600,
                          }}
                        >
                          {item.severity || "—"}
                        </span>
                      </Td>
                      <Td>
                        <span
                          style={{
                            padding: "2px 8px",
                            borderRadius: 6,
                            background:
                              SOURCE_COLORS[item.source || "agent"] || "#6b7280",
                            color: "white",
                            fontSize: 11,
                            fontWeight: 600,
                          }}
                        >
                          {item.source || "agent"}
                        </span>
                      </Td>
                      <Td>
                        <code style={{ fontSize: 12 }}>
                          {item.file_path}
                          {item.line_number ? `:${item.line_number}` : ""}
                        </code>
                      </Td>
                      <Td>{item.cwe || "—"}</Td>
                      <Td>{item.title}</Td>
                      <Td>
                        <Link
                          to={`/analysis/results/${item.scan_id}`}
                          style={{ fontSize: 12 }}
                        >
                          {item.scan_id.slice(0, 12)}…
                        </Link>
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <div style={{ display: "flex", gap: 8 }}>
            <button
              type="button"
              onClick={() => {
                if (!hasPrev) return;
                const prev = [...pageHistory];
                prev.pop();
                setPageHistory(prev);
                setCursor(prev[prev.length - 1]);
              }}
              disabled={!hasPrev}
              style={{ padding: "4px 12px" }}
            >
              ← Previous
            </button>
            <button
              type="button"
              onClick={() => {
                if (nextCursor === null) return;
                setPageHistory([...pageHistory, nextCursor]);
                setCursor(nextCursor);
              }}
              disabled={nextCursor === null}
              style={{ padding: "4px 12px" }}
            >
              Next →
            </button>
          </div>
        </>
      )}
    </div>
  );
};

const Th: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <th
    style={{
      textAlign: "left",
      padding: "8px 12px",
      fontSize: 12,
      fontWeight: 600,
      color: "var(--fg-muted)",
      borderBottom: "1px solid var(--border)",
    }}
  >
    {children}
  </th>
);

const Td: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <td
    style={{
      padding: "8px 12px",
      fontSize: 13,
      borderBottom: "1px solid var(--border)",
    }}
  >
    {children}
  </td>
);

export default AdminFindingsPage;
