// secure-code-ui/src/pages/assets/AssetTableWindow.tsx
//
// A fixed-height window over the inventory, for choosing assets and for reading their state.
//
// A flat list of every asset pushed the buttons off the page and turned the choice into
// scrolling. This shows what matters about each asset — where it lives, what it runs, when it
// was last reached and with what result — inside a window whose height does not change, with
// a sticky header and filters over the columns.

import { useMemo, useState } from "react";
import type { Asset } from "../../shared/api/assetsService";
import { Icon } from "../../shared/ui/Icon";

export type SortKey = "name" | "kind" | "environment" | "owner" | "reachable" | "last_probe_at";

export interface AssetFilters {
  query: string;
  kind: string;
  environment: string;
  reach: "" | "up" | "filtered" | "down" | "never";
  owner: string;
  technology: string;
  sort: SortKey;
}

export const EMPTY_FILTERS: AssetFilters = {
  query: "",
  kind: "",
  environment: "",
  reach: "",
  owner: "",
  technology: "",
  sort: "name",
};

export function reachState(asset: Asset): "up" | "filtered" | "down" | "never" {
  if (asset.reachable === true) return "up";
  if (asset.reachable === false) {
    return asset.unreachable_reason === "filtered" ? "filtered" : "down";
  }
  return "never";
}

const STATE_LABEL: Record<ReturnType<typeof reachState>, string> = {
  up: "Reachable",
  filtered: "Filtered",
  down: "Unreachable",
  never: "Not checked",
};

export function when(value: string | null | undefined): string {
  if (!value) return "never";
  const minutes = Math.round((Date.now() - new Date(value).getTime()) / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

export function applyFilters(assets: Asset[], filters: AssetFilters): Asset[] {
  const needle = filters.query.trim().toLowerCase();
  const tech = filters.technology.toLowerCase();
  const rows = assets.filter((asset) => {
    if (filters.kind && asset.kind !== filters.kind) return false;
    if (filters.environment && (asset.environment ?? "") !== filters.environment) return false;
    if (filters.owner && (asset.owner ?? "") !== filters.owner) return false;
    if (filters.reach && reachState(asset) !== filters.reach) return false;
    if (tech && !(asset.technology_names ?? []).some((name) => name.toLowerCase() === tech)) {
      return false;
    }
    if (!needle) return true;
    // Search every aspect the window shows, not only the name.
    return (
      asset.name.toLowerCase().includes(needle) ||
      (asset.owner ?? "").toLowerCase().includes(needle) ||
      asset.kind.toLowerCase().includes(needle) ||
      (asset.environment ?? "").toLowerCase().includes(needle) ||
      (asset.hosts ?? []).some((host) => host.toLowerCase().includes(needle)) ||
      (asset.ports ?? []).some((port) => String(port).includes(needle)) ||
      (asset.technology_names ?? []).some((name) => name.toLowerCase().includes(needle))
    );
  });
  return [...rows].sort((a, b) => {
    if (filters.sort === "reachable") {
      const order = { up: 0, filtered: 1, never: 2, down: 3 };
      return order[reachState(a)] - order[reachState(b)];
    }
    if (filters.sort === "last_probe_at") {
      return (b.last_probe_at ?? "").localeCompare(a.last_probe_at ?? "");
    }
    return String(a[filters.sort] ?? "").localeCompare(String(b[filters.sort] ?? ""));
  });
}

export function AssetFiltersBar({
  assets,
  filters,
  onChange,
  count,
}: {
  assets: Asset[];
  filters: AssetFilters;
  onChange: (next: AssetFilters) => void;
  count?: number;
}) {
  const kinds = useMemo(() => [...new Set(assets.map((a) => a.kind))].sort(), [assets]);
  const environments = useMemo(
    () => [...new Set(assets.map((a) => a.environment).filter(Boolean))].sort() as string[],
    [assets],
  );
  const owners = useMemo(
    () => [...new Set(assets.map((a) => a.owner).filter(Boolean))].sort() as string[],
    [assets],
  );
  const technologies = useMemo(
    () =>
      [...new Set(assets.flatMap((a) => a.technology_names ?? []))]
        .sort()
        .slice(0, 200),
    [assets],
  );

  return (
    <div className="asset-filters">
      <input
        className="asset-filter-input"
        placeholder="Search name, owner, host, port, technology"
        value={filters.query}
        onChange={(event) => onChange({ ...filters, query: event.target.value })}
      />
      <select value={filters.kind} onChange={(e) => onChange({ ...filters, kind: e.target.value })}>
        <option value="">All kinds</option>
        {kinds.map((kind) => (
          <option key={kind} value={kind}>
            {kind}
          </option>
        ))}
      </select>
      <select
        value={filters.environment}
        onChange={(e) => onChange({ ...filters, environment: e.target.value })}
      >
        <option value="">All environments</option>
        {environments.map((env) => (
          <option key={env} value={env}>
            {env}
          </option>
        ))}
      </select>
      <select
        value={filters.reach}
        onChange={(e) =>
          onChange({ ...filters, reach: e.target.value as AssetFilters["reach"] })
        }
      >
        <option value="">Any reachability</option>
        <option value="up">Reachable</option>
        <option value="filtered">Filtered</option>
        <option value="down">Unreachable</option>
        <option value="never">Not checked</option>
      </select>
      {owners.length > 0 && (
        <select value={filters.owner} onChange={(e) => onChange({ ...filters, owner: e.target.value })}>
          <option value="">Any owner</option>
          {owners.map((owner) => (
            <option key={owner} value={owner}>
              {owner}
            </option>
          ))}
        </select>
      )}
      {technologies.length > 0 && (
        <select
          value={filters.technology}
          onChange={(e) => onChange({ ...filters, technology: e.target.value })}
        >
          <option value="">Any technology</option>
          {technologies.map((tech) => (
            <option key={tech} value={tech}>
              {tech}
            </option>
          ))}
        </select>
      )}
      <select
        value={filters.sort}
        onChange={(e) => onChange({ ...filters, sort: e.target.value as SortKey })}
      >
        <option value="name">Sort: name</option>
        <option value="owner">Sort: owner</option>
        <option value="kind">Sort: kind</option>
        <option value="environment">Sort: environment</option>
        <option value="reachable">Sort: reachability</option>
        <option value="last_probe_at">Sort: recently scanned</option>
      </select>
      {count !== undefined && (
        <span className="asset-muted" style={{ marginLeft: "auto" }}>
          {count} of {assets.length}
        </span>
      )}
    </div>
  );
}

export function AssetStatus({ asset }: { asset: Asset }) {
  const state = reachState(asset);
  return (
    <span className={`asset-state is-${state}`} title={asset.last_probe_evidence ?? undefined}>
      {STATE_LABEL[state]}
      {asset.last_probe_level ? ` · L${asset.last_probe_level}` : ""}
    </span>
  );
}

export default function AssetTableWindow({
  assets,
  selected,
  onToggle,
  onSelectVisible,
  height = 380,
}: {
  assets: Asset[];
  selected?: Set<string>;
  onToggle?: (assetId: string) => void;
  onSelectVisible?: (assets: Asset[], selected: boolean) => void;
  height?: number;
}) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const selectable = Boolean(onToggle);

  if (assets.length === 0) {
    return (
      <div className="asset-window" style={{ height }}>
        <p className="asset-empty" style={{ padding: 16 }}>
          No asset matches these filters.
        </p>
      </div>
    );
  }

  return (
    <div className="asset-window" style={{ height }}>
      <table>
        <thead>
          <tr>
            {selectable && (
              <th style={{ width: 34 }}>
                <input
                  type="checkbox"
                  title="Select these rows"
                  checked={assets.length > 0 && assets.every((a) => selected?.has(a.id))}
                  onChange={(event) => onSelectVisible?.(assets, event.target.checked)}
                />
              </th>
            )}
            <th>Asset</th>
            <th>Kind</th>
            <th>Environment</th>
            <th>Hosts / ports</th>
            <th>Technologies</th>
            <th>Last scanned</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {assets.map((asset) => (
              <>
                <tr
                  key={asset.id}
                  className={selected?.has(asset.id) ? "is-selected" : ""}
                  onClick={() => setExpanded(expanded === asset.id ? null : asset.id)}
                >
                  {selectable && (
                    <td onClick={(event) => event.stopPropagation()}>
                      <input
                        type="checkbox"
                        checked={selected?.has(asset.id) ?? false}
                        onChange={() => onToggle?.(asset.id)}
                      />
                    </td>
                  )}
                  <td>
                    <strong>{asset.name}</strong>
                    {asset.owner && <div className="asset-muted">{asset.owner}</div>}
                  </td>
                  <td>{asset.kind}</td>
                  <td>{asset.environment ?? "—"}</td>
                  <td>
                    {(asset.hosts ?? []).length > 0 ? (
                      <>
                        <div>{(asset.hosts ?? []).slice(0, 2).join(", ")}</div>
                        <div className="asset-muted">
                          {(asset.ports ?? []).length
                            ? `ports ${(asset.ports ?? []).join(", ")}`
                            : "no port recorded"}
                        </div>
                      </>
                    ) : (
                      <span className="asset-muted">no host recorded</span>
                    )}
                  </td>
                  <td title={(asset.technology_names ?? []).join(", ")}>
                    {(asset.technology_names ?? []).length ? (
                      (asset.technology_names ?? []).slice(0, 3).join(", ")
                    ) : (
                      <span className="asset-muted">—</span>
                    )}
                  </td>
                  <td>{when(asset.last_probe_at)}</td>
                  <td>
                    <AssetStatus asset={asset} />
                  </td>
                </tr>
                {expanded === asset.id && (
                  <tr key={`${asset.id}-detail`}>
                    <td colSpan={selectable ? 8 : 7} className="asset-muted">
                      <div style={{ display: "grid", gap: 3 }}>
                        <span>
                          <strong>Why:</strong> {asset.last_probe_evidence ?? "never checked"}
                        </span>
                        <span>
                          <strong>Endpoints:</strong> {asset.services ?? 0} ·{" "}
                          <strong>technologies:</strong> {asset.technologies ?? 0} ·{" "}
                          <strong>packages:</strong> {asset.dependencies ?? 0}
                        </span>
                        <span>
                          <strong>Scope:</strong>{" "}
                          {asset.authorization_basis ?? "no authorisation basis recorded"}
                        </span>
                        {asset.last_probe_seconds != null && (
                          <span>
                            <strong>Check took:</strong> {asset.last_probe_seconds}s
                          </span>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </>
            ))}
        </tbody>
      </table>
    </div>
  );
}

export { Icon };
