// secure-code-ui/src/pages/account/SubmissionHistoryPage.tsx
//
// SCCAP scan history page. Vertical timeline grouped by day. Replaces
// the Ant-heavy ScanCard list. Data shape and filters are unchanged —
// backend /scans/history pagination still drives the view, but the
// presentation moves into the design bundle's visual language.

import React, { useMemo, useState } from "react";
import { useQuery, keepPreviousData } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { scanService } from "../../shared/api/scanService";
import { useDebounce } from "../../shared/hooks/useDebounce";
import { scanRouteFor } from "../../shared/lib/scanRoute";
import { Icon } from "../../shared/ui/Icon";
import type { ScanHistoryItem } from "../../shared/types/api";

const STATUS_GROUPS = [
  "All",
  "Completed",
  "In Progress",
  "Failed",
  "Pending Approval",
];

function formatDayBucket(iso: string): string {
  const d = new Date(iso);
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const yesterday = new Date(today.getTime() - 24 * 60 * 60 * 1000);
  const dMid = new Date(d.getFullYear(), d.getMonth(), d.getDate());
  if (dMid.getTime() === today.getTime()) return "Today";
  if (dMid.getTime() === yesterday.getTime()) return "Yesterday";
  return d.toLocaleDateString(undefined, {
    weekday: "long",
    month: "short",
    day: "numeric",
    year:
      d.getFullYear() === now.getFullYear() ? undefined : "numeric",
  });
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });
}

function statusTone(s: string): { color: string; label: string } {
  const up = s.toUpperCase();
  if (["COMPLETED", "REMEDIATION_COMPLETED"].includes(up))
    return { color: "var(--success)", label: "Completed" };
  if (up === "FAILED") return { color: "var(--critical)", label: "Failed" };
  if (up === "CANCELLED" || up === "EXPIRED")
    return { color: "var(--fg-subtle)", label: up.toLowerCase() };
  if (up === "PENDING_COST_APPROVAL")
    return { color: "var(--medium)", label: "Pending approval" };
  return { color: "var(--primary)", label: "In progress" };
}

interface DayGroup {
  key: string;
  scans: ScanHistoryItem[];
}

function groupByDay(items: ScanHistoryItem[]): DayGroup[] {
  const buckets = new Map<string, ScanHistoryItem[]>();
  for (const scan of items) {
    const key = formatDayBucket(scan.created_at);
    if (!buckets.has(key)) buckets.set(key, []);
    buckets.get(key)!.push(scan);
  }
  return Array.from(buckets.entries()).map(([key, scans]) => ({ key, scans }));
}

const SubmissionHistoryPage: React.FC = () => {
  const navigate = useNavigate();
  const [page, setPage] = useState(1);
  const [pageSize] = useState(20);
  const [searchTerm, setSearchTerm] = useState("");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");
  const [statusFilter, setStatusFilter] = useState("All");
  const debouncedSearch = useDebounce(searchTerm, 400);

  const { data, isLoading, isError, error } = useQuery({
    queryKey: [
      "scanHistory",
      page,
      pageSize,
      debouncedSearch,
      sortOrder,
      statusFilter,
    ],
    queryFn: () =>
      scanService.getScanHistory(
        page,
        pageSize,
        debouncedSearch,
        sortOrder,
        statusFilter,
      ),
    placeholderData: keepPreviousData,
    refetchInterval: 10_000,
  });

  const groups = useMemo(
    () => (data?.items ? groupByDay(data.items) : []),
    [data],
  );
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <div className="fade-in" style={{ display: "grid", gap: 18 }}>
      <div>
        <h1 style={{ color: "var(--fg)" }}>Submission history</h1>
        <div style={{ color: "var(--fg-muted)", marginTop: 4 }}>
          Every scan you've submitted, newest first.
        </div>
      </div>

      <div
        className="sccap-card"
        style={{
          padding: 14,
          display: "grid",
          gridTemplateColumns: "1fr 180px 180px",
          gap: 10,
        }}
      >
        <div className="input-with-icon">
          <Icon.Search size={14} />
          <input
            className="sccap-input"
            placeholder="Search scans, project, or ID…"
            value={searchTerm}
            onChange={(e) => {
              setPage(1);
              setSearchTerm(e.target.value);
            }}
            style={{ paddingLeft: 32 }}
          />
        </div>
        <select
          className="sccap-input"
          value={statusFilter}
          onChange={(e) => {
            setPage(1);
            setStatusFilter(e.target.value);
          }}
        >
          {STATUS_GROUPS.map((g) => (
            <option key={g} value={g}>
              {g}
            </option>
          ))}
        </select>
        <select
          className="sccap-input"
          value={sortOrder}
          onChange={(e) => setSortOrder(e.target.value as "asc" | "desc")}
        >
          <option value="desc">Newest first</option>
          <option value="asc">Oldest first</option>
        </select>
      </div>

      {isError && (
        <div
          className="sccap-card"
          style={{
            padding: 20,
            color: "var(--critical)",
            background: "var(--critical-weak)",
            borderColor: "var(--critical)",
          }}
        >
          Could not fetch scan history: {error?.message ?? "unknown error"}
        </div>
      )}

      {isLoading ? (
        <div
          className="sccap-card"
          style={{
            padding: 40,
            textAlign: "center",
            color: "var(--fg-muted)",
          }}
        >
          Loading scans…
        </div>
      ) : groups.length === 0 ? (
        <div
          className="sccap-card"
          style={{ padding: 60, textAlign: "center" }}
        >
          <div
            style={{
              color: "var(--fg)",
              fontSize: 16,
              fontWeight: 500,
              marginBottom: 6,
            }}
          >
            No scans found
          </div>
          <div
            style={{
              color: "var(--fg-muted)",
              fontSize: 13,
              marginBottom: 16,
            }}
          >
            Submit code to create your first scan.
          </div>
          <Link to="/submission/submit">
            <button className="sccap-btn sccap-btn-primary">
              <Icon.Plus size={13} /> Start a scan
            </button>
          </Link>
        </div>
      ) : (
        <div style={{ display: "grid", gap: 22 }}>
          {groups.map((group) => (
            <div key={group.key}>
              <div
                style={{
                  fontSize: 11,
                  color: "var(--fg-subtle)",
                  textTransform: "uppercase",
                  letterSpacing: ".08em",
                  marginBottom: 8,
                  fontWeight: 500,
                }}
              >
                {group.key}
              </div>
              <div className="sccap-card" style={{ padding: 0 }}>
                {group.scans.map((scan, idx) => {
                  const tone = statusTone(scan.status);
                  return (
                    <div
                      key={scan.id}
                      onClick={() =>
                        navigate(scanRouteFor(scan.id, scan.status), {
                          state: {
                            fromLabel: "History",
                            fromPath: "/account/history",
                          },
                        })
                      }
                      style={{
                        display: "grid",
                        gridTemplateColumns: "80px 1fr auto",
                        alignItems: "center",
                        gap: 14,
                        padding: "14px 18px",
                        borderBottom:
                          idx < group.scans.length - 1
                            ? "1px solid var(--border)"
                            : "none",
                        cursor: "pointer",
                        transition: "background var(--t)",
                      }}
                      onMouseEnter={(e) =>
                        (e.currentTarget.style.background = "var(--bg-soft)")
                      }
                      onMouseLeave={(e) =>
                        (e.currentTarget.style.background = "transparent")
                      }
                    >
                      <div
                        style={{
                          fontSize: 12,
                          color: "var(--fg-muted)",
                          fontVariantNumeric: "tabular-nums",
                        }}
                      >
                        {formatTime(scan.created_at)}
                      </div>
                      <div>
                        <div
                          style={{
                            fontWeight: 500,
                            color: "var(--fg)",
                            marginBottom: 2,
                          }}
                        >
                          {scan.project_name}
                        </div>
                        <div
                          style={{
                            fontSize: 11.5,
                            color: "var(--fg-subtle)",
                          }}
                        >
                          {scan.scan_type.toUpperCase()} ·{" "}
                          <span style={{ fontFamily: "var(--font-mono)" }}>
                            {scan.id.slice(0, 12)}
                          </span>
                        </div>
                      </div>
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 10,
                        }}
                      >
                        <span
                          className="chip"
                          style={{
                            background: "transparent",
                            borderColor: tone.color,
                            color: tone.color,
                          }}
                        >
                          {tone.label}
                        </span>
                        <Icon.ChevronR size={14} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}

          {totalPages > 1 && (
            <div
              style={{
                display: "flex",
                justifyContent: "center",
                alignItems: "center",
                gap: 12,
                marginTop: 4,
              }}
            >
              <button
                className="sccap-btn sccap-btn-sm"
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                <Icon.ChevronL size={12} /> Prev
              </button>
              <span
                style={{ fontSize: 12, color: "var(--fg-muted)" }}
              >
                Page {page} of {totalPages} · {total} total
              </span>
              <button
                className="sccap-btn sccap-btn-sm"
                disabled={page >= totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              >
                Next <Icon.ChevronR size={12} />
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default SubmissionHistoryPage;
