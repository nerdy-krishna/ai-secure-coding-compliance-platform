// secure-code-ui/src/widgets/TopNav/SearchCombobox.tsx
//
// Global-search combobox rendered in the TopNav. 250 ms debounced;
// TanStack Query keyed on the debounced term. Dropdown shows Projects,
// Scans, and Findings sections; arrow-key + Enter navigation; Escape
// closes. Clicking a row (or hitting Enter on the highlighted row)
// navigates to the row's detail page.

import { useQuery } from "@tanstack/react-query";
import React, { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  searchService,
  type SearchFindingHit,
  type SearchProjectHit,
  type SearchResults,
  type SearchScanHit,
} from "../../shared/api/searchService";
import { Icon } from "../../shared/ui/Icon";

type Row =
  | { kind: "project"; hit: SearchProjectHit }
  | { kind: "scan"; hit: SearchScanHit }
  | { kind: "finding"; hit: SearchFindingHit };

function useDebounced<T>(value: T, ms: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const id = setTimeout(() => setDebounced(value), ms);
    return () => clearTimeout(id);
  }, [value, ms]);
  return debounced;
}

function sevColor(sev: string | null | undefined): string {
  const s = (sev ?? "").toLowerCase();
  if (s === "critical") return "var(--critical)";
  if (s === "high") return "var(--high)";
  if (s === "medium") return "var(--medium)";
  if (s === "low") return "var(--low)";
  return "var(--info)";
}

/**
 * SearchCombobox — input contract (ASVS V2.1.1, V2.1.3):
 *   - Query `q`: 2–128 characters, NUL/control characters (U+0000–U+001F) stripped, whitespace trimmed before debounce.
 *   - Backend rate-limit: 60 search requests / min / user (enforced server-side on POST /api/v1/search).
 *     TODO (V2.1.3 / V2.4.1): confirm backend rate-limit is active; add TODO here if not yet configured.
 */
export const SearchCombobox: React.FC = () => {
  const navigate = useNavigate();
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(false);
  const [activeIdx, setActiveIdx] = useState(-1);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const debounced = useDebounced(q.trim(), 250);

  const { data, isFetching, isError } = useQuery<SearchResults>({
    queryKey: ["search", debounced],
    queryFn: () => searchService.search(debounced),
    enabled: debounced.length >= 2,
    staleTime: 10_000,
  });

  // Flatten hits in display order so arrow navigation can cross sections.
  const rows: Row[] = useMemo(() => {
    if (!data) return [];
    return [
      ...data.projects.map((hit) => ({ kind: "project" as const, hit })),
      ...data.scans.map((hit) => ({ kind: "scan" as const, hit })),
      ...data.findings.map((hit) => ({ kind: "finding" as const, hit })),
    ];
  }, [data]);

  useEffect(() => {
    setActiveIdx(rows.length > 0 ? 0 : -1);
  }, [rows]);

  // Close on outside click.
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (!containerRef.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const goTo = (row: Row) => {
    setOpen(false);
    setQ("");
    if (row.kind === "project") {
      // Scope the projects page search to the matched name so the card
      // surfaces immediately without the user hunting for it.
      navigate(`/analysis/results`);
    } else if (row.kind === "scan") {
      // V1.2.2: encode backend-supplied id to keep the route well-formed.
      navigate(`/analysis/results/${encodeURIComponent(row.hit.id)}`, {
        state: { fromLabel: "Search" },
      });
    } else {
      // V1.2.2: encode backend-supplied scan_id to keep the route well-formed.
      navigate(`/analysis/results/${encodeURIComponent(row.hit.scan_id)}`, {
        state: { fromLabel: "Search" },
      });
    }
  };

  const onKeyDown: React.KeyboardEventHandler<HTMLInputElement> = (e) => {
    if (e.key === "Escape") {
      setOpen(false);
      return;
    }
    if (!open && (e.key === "ArrowDown" || e.key === "Enter")) {
      setOpen(true);
      return;
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActiveIdx((i) => Math.min(rows.length - 1, i + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActiveIdx((i) => Math.max(0, i - 1));
    } else if (e.key === "Enter") {
      const row = rows[activeIdx];
      if (row) {
        e.preventDefault();
        goTo(row);
      }
    }
  };

  const showDropdown =
    open && debounced.length >= 2 && (isFetching || data !== undefined || isError);

  return (
    <div
      ref={containerRef}
      style={{ position: "relative", width: 260 }}
    >
      <div className="input-with-icon" style={{ width: "100%" }}>
        <Icon.Search size={14} />
        <input
          ref={inputRef}
          className="sccap-input"
          placeholder="Search projects, scans, findings…"
          value={q}
          onChange={(e) => {
            // V2.1.1 / V2.2.1: strip NUL/control chars and enforce max length client-side.
            // eslint-disable-next-line no-control-regex
            const next = e.target.value.replace(/[\x00-\x1f]/g, "").slice(0, 128);
            setQ(next);
            setOpen(true);
          }}
          maxLength={128}
          onFocus={() => setOpen(true)}
          onKeyDown={onKeyDown}
          style={{ paddingLeft: 32, height: 34 }}
          aria-label="Global search"
          aria-expanded={showDropdown}
          aria-controls="search-results"
          aria-activedescendant={
            showDropdown && activeIdx >= 0 ? `search-result-${activeIdx}` : undefined
          }
          role="combobox"
          aria-autocomplete="list"
        />
      </div>
      {showDropdown && (
        <div
          id="search-results"
          role="listbox"
          aria-label="Search results"
          aria-busy={isFetching}
          className="surface fade-in"
          style={{
            position: "absolute",
            top: "calc(100% + 6px)",
            right: 0,
            left: 0,
            padding: 6,
            boxShadow: "var(--shadow-md)",
            zIndex: 30,
            maxHeight: 420,
            overflowY: "auto",
          }}
        >
          {isFetching && rows.length === 0 ? (
            <div
              role="status"
              style={{
                padding: 12,
                fontSize: 12.5,
                color: "var(--fg-muted)",
                textAlign: "center",
              }}
            >
              Searching…
            </div>
          ) : isError ? (
            <div role="alert" style={{ padding: 12, fontSize: 12.5, color: "var(--critical)" }}>
              Search is unavailable. Try again when the connection recovers.
            </div>
          ) : rows.length === 0 ? (
            <div
              role="status"
              style={{
                padding: 12,
                fontSize: 12.5,
                color: "var(--fg-muted)",
                textAlign: "center",
              }}
            >
              No matches for &quot;{debounced}&quot;
            </div>
          ) : (
            <>
              {data?.projects.length ? (
                <Section label="Projects">
                  {data.projects.map((hit, i) => {
                    const idx = i;
                    return (
                      <ResultRow
                        key={`p-${hit.id}`}
                        id={`search-result-${idx}`}
                        active={activeIdx === idx}
                        onClick={() =>
                          goTo({ kind: "project", hit })
                        }
                        icon={<Icon.Folder size={14} />}
                        title={hit.name}
                        subtitle="Project"
                      />
                    );
                  })}
                </Section>
              ) : null}

              {data?.scans.length ? (
                <Section label="Scans">
                  {data.scans.map((hit, i) => {
                    const idx = (data.projects.length ?? 0) + i;
                    return (
                      <ResultRow
                        key={`s-${hit.id}`}
                        id={`search-result-${idx}`}
                        active={activeIdx === idx}
                        onClick={() => goTo({ kind: "scan", hit })}
                        icon={<Icon.Zap size={14} />}
                        title={hit.id.slice(0, 12)}
                        titleMono
                        subtitle={`${hit.project_name} · ${hit.status.toLowerCase().replace(/_/g, " ")}`}
                      />
                    );
                  })}
                </Section>
              ) : null}

              {data?.findings.length ? (
                <Section label="Findings">
                  {data.findings.map((hit, i) => {
                    const idx =
                      (data.projects.length ?? 0) +
                      (data.scans.length ?? 0) +
                      i;
                    return (
                      <ResultRow
                        key={`f-${hit.id}`}
                        id={`search-result-${idx}`}
                        active={activeIdx === idx}
                        onClick={() => goTo({ kind: "finding", hit })}
                        icon={
                          <span
                            style={{
                              width: 8,
                              height: 8,
                              borderRadius: 4,
                              background: sevColor(hit.severity),
                              display: "inline-block",
                            }}
                          />
                        }
                        title={hit.title}
                        subtitle={`${hit.file_path}${hit.matched_on === "file_path" ? " · path match" : ""}`}
                      />
                    );
                  })}
                </Section>
              ) : null}
            </>
          )}
        </div>
      )}
    </div>
  );
};

const Section: React.FC<{
  label: string;
  children: React.ReactNode;
}> = ({ label, children }) => (
  <div style={{ marginBottom: 4 }}>
    <div
      style={{
        padding: "6px 10px 4px",
        fontSize: 10.5,
        color: "var(--fg-subtle)",
        textTransform: "uppercase",
        letterSpacing: ".06em",
      }}
    >
      {label}
    </div>
    {children}
  </div>
);

const ResultRow: React.FC<{
  id: string;
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  title: string;
  titleMono?: boolean;
  subtitle: string;
}> = ({ id, active, onClick, icon, title, titleMono, subtitle }) => (
  <button
    id={id}
    role="option"
    aria-selected={active}
    onMouseDown={(e) => {
      // Prevent blur-before-click from stealing the navigation.
      e.preventDefault();
      onClick();
    }}
    style={{
      display: "flex",
      width: "100%",
      alignItems: "center",
      gap: 10,
      padding: "7px 10px",
      borderRadius: 6,
      border: "none",
      background: active ? "var(--bg-soft)" : "transparent",
      color: "var(--fg)",
      cursor: "pointer",
      textAlign: "left",
      fontFamily: "inherit",
      fontSize: 13,
    }}
  >
    <span
      style={{
        width: 22,
        display: "grid",
        placeItems: "center",
        color: "var(--fg-muted)",
      }}
    >
      {icon}
    </span>
    <span style={{ flex: 1, minWidth: 0 }}>
      <div
        style={{
          fontWeight: 500,
          color: "var(--fg)",
          fontFamily: titleMono ? "var(--font-mono)" : undefined,
          whiteSpace: "nowrap",
          overflow: "hidden",
          textOverflow: "ellipsis",
        }}
      >
        {title}
      </div>
      <div
        style={{
          fontSize: 11.5,
          color: "var(--fg-subtle)",
          whiteSpace: "nowrap",
          overflow: "hidden",
          textOverflow: "ellipsis",
        }}
      >
        {subtitle}
      </div>
    </span>
  </button>
);

export default SearchCombobox;
