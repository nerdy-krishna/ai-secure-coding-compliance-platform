// secure-code-ui/src/pages/assets/CveCheckTab.tsx
//
// Page 1: pick CVEs, pick assets, read what the CVE actually is, then test.
//
// The pause in the middle is the point: research is cheap and reversible, testing against
// production assets is not. The operator sees the mechanism, the affected products, any
// known exploit and the detection check before anything is sent.

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  browseCves,
  checkCves,
  listAssets,
  researchCves,
  type Asset,
  type CveResearchItem,
} from "../../shared/api/assetsService";
import { Icon } from "../../shared/ui/Icon";
import { useToast } from "../../shared/ui/Toast";

type Stage = "select" | "research" | "testing";

type SortKey = "name" | "kind" | "environment" | "reachable" | "last_probe_at";

function reachLabel(asset: Asset): string {
  if (asset.reachable === true) return "reachable";
  if (asset.reachable === false) return `unreachable (${asset.unreachable_reason ?? "unknown"})`;
  return "never checked";
}

export default function CveCheckTab({ onTesting, verify }: { onTesting: () => void; verify: boolean }) {
  const toast = useToast();
  const queryClient = useQueryClient();

  const [stage, setStage] = useState<Stage>("select");
  const [selectedCves, setSelectedCves] = useState<string[]>([]);
  const [cveSearch, setCveSearch] = useState("");
  const [selectedAssets, setSelectedAssets] = useState<Set<string>>(new Set());
  const [assetFilter, setAssetFilter] = useState("");
  const [kindFilter, setKindFilter] = useState("");
  const [envFilter, setEnvFilter] = useState("");
  const [sortBy, setSortBy] = useState<SortKey>("name");
  const [research, setResearch] = useState<CveResearchItem[] | null>(null);

  const assetsQ = useQuery({ queryKey: ["assets"], queryFn: listAssets });
  const assets = assetsQ.data?.items ?? [];
  const browseQ = useQuery({
    queryKey: ["cve", "browse", cveSearch],
    queryFn: () => browseCves({ query: cveSearch || undefined, limit: 25 }),
    enabled: stage === "select",
  });
  const suggestions = browseQ.data?.items ?? [];

  const environments = useMemo(
    () => [...new Set(assets.map((a) => a.environment).filter(Boolean))].sort() as string[],
    [assets],
  );

  const filteredAssets = useMemo(() => {
    const needle = assetFilter.trim().toLowerCase();
    const rows = assets.filter((asset) => {
      if (kindFilter && asset.kind !== kindFilter) return false;
      if (envFilter && (asset.environment ?? "") !== envFilter) return false;
      if (!needle) return true;
      return (
        asset.name.toLowerCase().includes(needle) ||
        (asset.owner ?? "").toLowerCase().includes(needle)
      );
    });
    return [...rows].sort((a, b) => {
      if (sortBy === "reachable") return Number(b.reachable ?? -1) - Number(a.reachable ?? -1);
      if (sortBy === "last_probe_at") {
        return (b.last_probe_at ?? "").localeCompare(a.last_probe_at ?? "");
      }
      return String(a[sortBy] ?? "").localeCompare(String(b[sortBy] ?? ""));
    });
  }, [assets, assetFilter, kindFilter, envFilter, sortBy]);

  const addCves = (raw: string) => {
    const found = raw
      .split(/[\s,;]+/)
      .map((token) => token.trim().toUpperCase())
      .filter((token) => /^CVE-\d{4}-\d{4,}$/.test(token));
    if (!found.length) return;
    setSelectedCves((current) => [...new Set([...current, ...found])]);
  };

  const researchMutation = useMutation({
    mutationFn: () => researchCves(selectedCves),
    onSuccess: (items) => {
      setResearch(items);
      setStage("research");
    },
    onError: () => toast.error("Could not research these CVEs"),
  });

  const testMutation = useMutation({
    mutationFn: () =>
      checkCves({
        cve_ids: selectedCves,
        asset_ids: selectedAssets.size ? [...selectedAssets] : null,
        verify,
        scan: true,
      }),
    onMutate: () => {
      setStage("testing");
      onTesting();
    },
    onSuccess: (result) => {
      toast.success(
        `${result.matched} candidate(s) · ${result.applicable} applicable · ${result.undetermined} need a test`,
      );
      queryClient.invalidateQueries({ queryKey: ["assets"] });
      setStage("select");
    },
    onError: () => {
      toast.error("The check failed");
      setStage("research");
    },
  });

  return (
    <div className="asset-card sccap-card">
      <div className="asset-toolbar">
        <div>
          <strong>Check CVEs against assets</strong>
          <span className="asset-muted">
            Pick the CVEs and the assets. Research comes first — nothing is sent to an asset
            until you read what would be tested.
          </span>
        </div>
        {stage !== "select" && (
          <button
            className="sccap-btn sccap-btn-sm"
            onClick={() => {
              setStage("select");
              setResearch(null);
            }}
          >
            Back
          </button>
        )}
      </div>

      {stage === "select" && (
        <>
          <div className="asset-cve-picker">
            <label className="asset-field">
              <span>CVE ids</span>
              <input
                list="cve-suggestions"
                placeholder="CVE-2021-44228 — type, or choose from the corpus"
                value={cveSearch}
                onChange={(event) => setCveSearch(event.target.value)}
                onBlur={() => {
                  if (cveSearch.trim()) {
                    addCves(cveSearch);
                    setCveSearch("");
                  }
                }}
                onKeyDown={(event) => {
                  if (event.key === "Enter") {
                    addCves(cveSearch);
                    setCveSearch("");
                  }
                }}
              />
              <datalist id="cve-suggestions">
                {suggestions.map((item) => (
                  <option key={item.cve_id} value={item.cve_id}>
                    {item.severity ?? "unrated"} · {item.description.slice(0, 80)}
                  </option>
                ))}
              </datalist>
              <span className="asset-muted">
                {browseQ.data?.total ?? 0} CVE(s) in the local corpus — imported feeds only.
              </span>
            </label>
            <label className="asset-field">
              <span>Or paste a list</span>
              <textarea
                className="asset-textarea"
                rows={3}
                placeholder="One per line, or comma separated"
                onBlur={(event) => {
                  addCves(event.target.value);
                  event.target.value = "";
                }}
              />
            </label>
          </div>

          {selectedCves.length > 0 && (
            <div className="asset-inline-form">
              {selectedCves.map((cve) => (
                <button
                  key={cve}
                  className="asset-chip is-removable"
                  onClick={() =>
                    setSelectedCves((current) => current.filter((item) => item !== cve))
                  }
                >
                  {cve} <Icon.X size={10} />
                </button>
              ))}
              <button className="sccap-btn sccap-btn-sm" onClick={() => setSelectedCves([])}>
                Clear
              </button>
            </div>
          )}

          <div className="asset-toolbar">
            <div>
              <strong>Assets ({selectedAssets.size} selected)</strong>
              <span className="asset-muted">
                Nothing selected means the whole inventory.
              </span>
            </div>
            <div className="asset-inline-form">
              <button
                className="sccap-btn sccap-btn-sm"
                onClick={() => setSelectedAssets(new Set(filteredAssets.map((a) => a.id)))}
              >
                Select all
              </button>
              <button
                className="sccap-btn sccap-btn-sm"
                onClick={() => setSelectedAssets(new Set())}
              >
                Select none
              </button>
            </div>
          </div>

          <div className="asset-filters">
            <input
              className="asset-filter-input"
              placeholder="Filter assets by name or owner"
              value={assetFilter}
              onChange={(event) => setAssetFilter(event.target.value)}
            />
            <select value={kindFilter} onChange={(event) => setKindFilter(event.target.value)}>
              <option value="">All kinds</option>
              {[...new Set(assets.map((a) => a.kind))].sort().map((kind) => (
                <option key={kind} value={kind}>
                  {kind}
                </option>
              ))}
            </select>
            <select value={envFilter} onChange={(event) => setEnvFilter(event.target.value)}>
              <option value="">All environments</option>
              {environments.map((env) => (
                <option key={env} value={env}>
                  {env}
                </option>
              ))}
            </select>
            <select
              value={sortBy}
              onChange={(event) => setSortBy(event.target.value as SortKey)}
            >
              <option value="name">Sort: name</option>
              <option value="kind">Sort: kind</option>
              <option value="environment">Sort: environment</option>
              <option value="reachable">Sort: reachable first</option>
              <option value="last_probe_at">Sort: recently scanned</option>
            </select>
          </div>

          <div className="asset-pick-list">
            {filteredAssets.length === 0 ? (
              <p className="asset-muted">No assets match these filters.</p>
            ) : (
              filteredAssets.map((asset) => (
                <label key={asset.id} className="asset-pick-row">
                  <input
                    type="checkbox"
                    checked={selectedAssets.has(asset.id)}
                    onChange={(event) =>
                      setSelectedAssets((current) => {
                        const next = new Set(current);
                        if (event.target.checked) next.add(asset.id);
                        else next.delete(asset.id);
                        return next;
                      })
                    }
                  />
                  <strong>{asset.name}</strong>
                  <span className="asset-muted">{asset.kind}</span>
                  <span className="asset-muted">{asset.environment ?? "—"}</span>
                  <span
                    className={`asset-reach is-${
                      asset.reachable === true ? "ok" : asset.reachable === false ? "bad" : "unknown"
                    }`}
                  >
                    {reachLabel(asset)}
                  </span>
                </label>
              ))
            )}
          </div>

          <div className="asset-toolbar">
            <span className="asset-muted">
              {selectedCves.length} CVE(s) · {selectedAssets.size || "all"} asset(s)
            </span>
            <button
              className="sccap-btn sccap-btn-primary"
              disabled={!selectedCves.length || researchMutation.isPending}
              onClick={() => researchMutation.mutate()}
            >
              <Icon.Search size={13} />
              {researchMutation.isPending ? "Researching…" : "Research CVEs"}
            </button>
          </div>
        </>
      )}

      {stage !== "select" && research && (
        <div className="asset-research">
          {research.map((item) => (
            <div key={item.cve_id} className="asset-research-card">
              <div className="asset-research-head">
                <strong>{item.cve_id}</strong>
                <span className={`asset-sev is-${item.severity ?? "unknown"}`}>
                  {item.severity ?? "unrated"}
                </span>
                {item.cvss_score != null && <span className="asset-muted">CVSS {item.cvss_score}</span>}
                {item.kev && <span className="asset-chip is-kev">known exploited</span>}
                {item.cwe && <span className="asset-muted">{item.cwe}</span>}
              </div>
              {item.error ? (
                <p className="asset-muted">{item.error}</p>
              ) : (
                <>
                  <p className="asset-research-text">{item.description ?? "no description stored"}</p>
                  {item.affected_products.length > 0 && (
                    <p className="asset-muted">
                      Affects: {item.affected_products.slice(0, 8).join(", ")}
                      {item.affected_products.length > 8 ? ` …+${item.affected_products.length - 8}` : ""}
                    </p>
                  )}
                  {item.research_error && (
                    <p className="asset-muted">
                      Research unavailable — the model could not be reached
                      ({item.research_error.slice(0, 120)}). The corpus facts above are what is
                      stored; no check was designed.
                    </p>
                  )}
                  {item.research && (
                    <div className="asset-research-block">
                      <strong>Mechanism</strong>
                      <p className="asset-research-text">{item.research.mechanism}</p>
                      {item.research.detection_signals.length > 0 && (
                        <ul className="asset-research-list">
                          {item.research.detection_signals.slice(0, 5).map((signal) => (
                            <li key={signal}>{signal}</li>
                          ))}
                        </ul>
                      )}
                      {item.research.patched_version && (
                        <p className="asset-muted">Fixed in {item.research.patched_version}</p>
                      )}
                    </div>
                  )}
                  <div className="asset-research-block">
                    <strong>
                      {item.template_present ? "Detection check (ready)" : "No detection check built"}
                    </strong>
                    {item.template && <pre className="asset-yaml">{item.template.slice(0, 1200)}</pre>}
                    {!item.template_present && (
                      <p className="asset-muted">
                        {item.ranges_known === false
                          ? "No affected version range is stored for this CVE, so there is nothing a detection check could test; the verdict will come from the inventory instead."
                          : item.research_error
                            ? "The check could not be designed because the model was unavailable."
                            : "A check is designed on first use."}
                      </p>
                    )}
                  </div>
                  <div className="asset-research-block">
                    <strong>
                      Exploits ({item.exploit_references.length} reference
                      {item.exploit_references.length === 1 ? "" : "s"})
                    </strong>
                    {item.exploit_references.length === 0 ? (
                      <p className="asset-muted">
                        No exploit reference stored. The check above is what would run.
                      </p>
                    ) : (
                      <ul className="asset-research-list">
                        {item.exploit_references.slice(0, 5).map((reference) => (
                          <li key={reference.url}>
                            <a href={reference.url} target="_blank" rel="noreferrer">
                              {reference.url}
                            </a>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                </>
              )}
            </div>
          ))}

          <div className="asset-toolbar">
            <span className="asset-muted">
              {testMutation.isPending
                ? "Testing — progress appears in the activity console."
                : `Proceed will test ${selectedCves.length} CVE(s) against ${
                    selectedAssets.size || "the whole inventory"
                  }.`}
            </span>
            <div style={{ display: "flex", gap: 8 }}>
              <button
                className="sccap-btn"
                onClick={() => {
                  setStage("select");
                  setResearch(null);
                }}
              >
                Cancel
              </button>
              <button
                className="sccap-btn sccap-btn-primary"
                disabled={testMutation.isPending}
                onClick={() => testMutation.mutate()}
              >
                <Icon.Play size={13} />
                {testMutation.isPending ? "Testing…" : "Proceed to test"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
