import React, { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Icon } from "../../shared/ui/Icon";
import { getScannerCoverage, type CoverageEntry } from "../../shared/api/coverageService";

/**
 * What the scanners actually read.
 *
 * The prescan decides, per file, whether it is first-party source, vendored code, a
 * generated artefact, a runtime file, empty or binary — and whether any scanner can
 * read it. This panel turns that decision into something an operator can audit:
 * "scanned 604 of 8,112", a breakdown by reason, and the full file list with the
 * reason each excluded file was skipped. Nothing is hidden.
 */

const REASON_LABELS: Record<string, string> = {
  empty_input: "Empty or whitespace only",
  binary_input: "Binary or compiled",
  low_value_role: "Not first-party code",
  low_value_asset: "Low-value asset",
  unsupported_language: "No scanner for this language",
  unsupported_file_type: "Unsupported file type",
  input_size_limit: "Too large to scan",
  prescan_file_limit: "Beyond the file budget",
};

const ROLE_LABELS: Record<string, string> = {
  first_party_source: "Source",
  unknown: "Unknown",
  first_party_minified_bundle: "Minified bundle",
  generated_asset: "Generated",
  large_static_asset: "Large asset",
  known_third_party_vendor: "Library",
  unknown_third_party_vendor: "Vendored",
  runtime_artifact: "Runtime",
  dependency_lockfile: "Lockfile",
  empty: "Empty",
  binary: "Binary",
};

/** One row per file, folding the per-(scanner, file) entries back together. */
interface FileRow {
  path: string;
  role: string;
  language: string | null;
  scanned: boolean;
  status: string;
  reasonCode: string | null;
  reason: string | null;
  findings: number;
}

function fold(entries: CoverageEntry[]): FileRow[] {
  const byPath = new Map<string, FileRow>();
  for (const entry of entries) {
    const existing = byPath.get(entry.input_path);
    const scanned = ["planned", "completed", "clean", "failed", "timeout"].includes(
      entry.status,
    );
    if (existing === undefined) {
      byPath.set(entry.input_path, {
        path: entry.input_path,
        role: entry.details?.role ?? "unknown",
        language: entry.details?.language ?? null,
        scanned,
        status: entry.status,
        reasonCode: entry.reason_code,
        reason: entry.reason,
        findings: entry.finding_count,
      });
      continue;
    }
    existing.scanned = existing.scanned || scanned;
    existing.findings += entry.finding_count;
    if (!existing.reasonCode && entry.reason_code) {
      existing.reasonCode = entry.reason_code;
      existing.reason = entry.reason;
    }
  }
  return [...byPath.values()].sort((a, b) => a.path.localeCompare(b.path));
}

export const ScanCoveragePanel: React.FC<{ scanId: string }> = ({ scanId }) => {
  const [open, setOpen] = useState(false);
  const [filter, setFilter] = useState<"all" | "scanned" | "excluded">("excluded");
  const query = useQuery({
    queryKey: ["scan-coverage", scanId],
    queryFn: () => getScannerCoverage(scanId),
    staleTime: 60_000,
  });

  const rows = useMemo(() => fold(query.data?.entries ?? []), [query.data]);
  const scanned = rows.filter((row) => row.scanned);
  const excluded = rows.filter((row) => !row.scanned);

  const byReason = useMemo(() => {
    const counts = new Map<string, number>();
    for (const row of excluded) {
      const key = row.reasonCode ?? "unknown";
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
  }, [excluded]);

  if (query.isLoading || query.isError || rows.length === 0) return null;

  const visible = filter === "scanned" ? scanned : filter === "excluded" ? excluded : rows;

  return (
    <section className="sccap-card coverage-panel">
      <div className="coverage-head">
        <h2 style={{ margin: 0 }}>
          File coverage
        </h2>
        <span className="coverage-summary">
          <strong>{scanned.length}</strong> of {rows.length} files scanned
          {excluded.length > 0 && (
            <>
              {" · "}
              <strong>{excluded.length}</strong> excluded
            </>
          )}
        </span>
        <button className="sccap-btn sccap-btn-sm" onClick={() => setOpen((value) => !value)}>
          {open ? "Hide files" : "Show files"}
          <Icon.ChevronD
            size={12}
            style={{ transform: open ? "rotate(0deg)" : "rotate(-90deg)", transition: "transform .15s" }}
          />
        </button>
      </div>

      {byReason.length > 0 && (
        <div className="coverage-reasons">
          {byReason.map(([reason, count]) => (
            <span key={reason} className="coverage-chip">
              {REASON_LABELS[reason] ?? reason.replace(/_/g, " ")}
              <strong>{count}</strong>
            </span>
          ))}
        </div>
      )}

      {open && (
        <>
          <div className="coverage-filters">
            {(["excluded", "scanned", "all"] as const).map((value) => (
              <button
                key={value}
                type="button"
                className={`sccap-btn sccap-btn-sm${filter === value ? " sccap-btn-primary" : ""}`}
                onClick={() => setFilter(value)}
              >
                {value === "excluded"
                  ? `Excluded (${excluded.length})`
                  : value === "scanned"
                    ? `Scanned (${scanned.length})`
                    : `All (${rows.length})`}
              </button>
            ))}
          </div>
          <div className="coverage-table-wrap">
            <table className="coverage-table">
              <thead>
                <tr>
                  <th>File</th>
                  <th>Kind</th>
                  <th>Language</th>
                  <th>Status</th>
                  <th>Why</th>
                </tr>
              </thead>
              <tbody>
                {visible.slice(0, 2000).map((row) => (
                  <tr key={row.path}>
                    <td className="coverage-path" title={row.path}>
                      {row.path}
                    </td>
                    <td>
                      <span className={`coverage-role is-${row.role}`}>
                        {ROLE_LABELS[row.role] ?? row.role}
                      </span>
                    </td>
                    <td className="coverage-lang">{row.language ?? "—"}</td>
                    <td>
                      <span className={`coverage-status is-${row.scanned ? "scanned" : "excluded"}`}>
                        {row.scanned ? "scanned" : "excluded"}
                      </span>
                    </td>
                    <td className="coverage-reason">
                      {row.scanned
                        ? row.findings > 0
                          ? `${row.findings} finding(s)`
                          : "clean"
                        : (REASON_LABELS[row.reasonCode ?? ""] ?? row.reason ?? "—")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {visible.length > 2000 && (
            <p className="coverage-more">
              Showing the first 2,000 of {visible.length} files.
            </p>
          )}
        </>
      )}
    </section>
  );
};
