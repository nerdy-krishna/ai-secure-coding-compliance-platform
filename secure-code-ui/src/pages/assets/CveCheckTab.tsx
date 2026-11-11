// secure-code-ui/src/pages/assets/CveCheckTab.tsx
//
// Page 1: pick CVEs, pick assets, read what the CVE actually is, then test.
//
// The pause in the middle is the point: research is cheap and reversible, testing against
// production assets is not. The operator sees the mechanism, the affected products, any known
// exploit and the detection check before anything is sent.
//
// Layout note: the buttons and the activity window sit at the *top*, above the choices. A scan
// started from the bottom of a long list used to leave the operator looking at a page that
// appeared to do nothing.

import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  browseCves,
  checkCves,
  listAssets,
  researchCves,
  stopCveCheck,
  type Asset,
  type CveResearchItem,
} from "../../shared/api/assetsService";
import { Icon } from "../../shared/ui/Icon";
import TerminalConsole from "../../shared/ui/TerminalConsole";
import { useToast } from "../../shared/ui/Toast";
import AssetTableWindow, {
  AssetFiltersBar,
  EMPTY_FILTERS,
  applyFilters,
  type AssetFilters,
} from "./AssetTableWindow";
import useScanActivity from "./useScanActivity";

type Stage = "select" | "research" | "testing";

export default function CveCheckTab({ verify }: { verify: boolean }) {
  const toast = useToast();
  const queryClient = useQueryClient();
  const activity = useScanActivity();

  const [stage, setStage] = useState<Stage>("select");
  const [cveText, setCveText] = useState("");
  const [selectedCves, setSelectedCves] = useState<string[]>([]);
  const [cveSearch, setCveSearch] = useState("");
  const [selectedAssets, setSelectedAssets] = useState<Set<string>>(new Set());
  const [filters, setFilters] = useState<AssetFilters>(EMPTY_FILTERS);
  const [research, setResearch] = useState<CveResearchItem[] | null>(null);

  const assetsQ = useQuery({ queryKey: ["assets"], queryFn: listAssets });
  const assets: Asset[] = assetsQ.data?.items ?? [];
  const browseQ = useQuery({
    queryKey: ["cve", "browse", cveSearch],
    queryFn: () => browseCves({ query: cveSearch || undefined, limit: 25 }),
    enabled: stage === "select",
  });
  const suggestions = browseQ.data?.items ?? [];
  const visible = useMemo(() => applyFilters(assets, filters), [assets, filters]);

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
      activity.finish("completed", "Research complete");
    },
    onError: () => {
      activity.finish("error", "Research failed");
      toast.error("Could not research these CVEs");
    },
  });

  const testMutation = useMutation({
    mutationFn: () =>
      checkCves({
        cve_ids: selectedCves,
        asset_ids: selectedAssets.size ? [...selectedAssets] : null,
        verify,
        scan: true,
      }),
    onMutate: () => setStage("testing"),
    onSuccess: (result) => {
      if (result.stopped) {
        activity.finish("cancelled", "Stopped by operator");
        toast.info("The check was stopped; nothing further was tested");
        setStage("select");
        return;
      }
      activity.finish("completed", "Check complete");
      toast.success(
        `${result.matched} candidate(s) · ${result.applicable} applicable · ${result.undetermined} need a test`,
      );
      queryClient.invalidateQueries({ queryKey: ["assets"] });
      setStage("select");
    },
    onError: () => {
      activity.finish("error", "Check failed");
      toast.error("The check failed");
      setStage("research");
    },
  });

  const startResearch = async () => {
    await activity.start("Researching CVEs");
    researchMutation.mutate();
  };

  const startTest = async () => {
    await activity.start("Testing assets");
    testMutation.mutate();
  };

  // A stopped run returns to the research view, so the operator can act on what was learned.
  useEffect(() => {
    if (activity.phase === "cancelled" && stage === "testing") setStage("research");
  }, [activity.phase, stage]);

  const busy = activity.phase === "running";

  return (
    <>
      <section className="sccap-card asset-card">
        <div className="asset-toolbar">
          <div>
            <strong>Check CVEs against assets</strong>
            <span className="asset-muted">
              {selectedCves.length} CVE(s) · {selectedAssets.size || "all"} asset(s) — research
              first, then test.
            </span>
          </div>
          <div className="asset-inline-form">
            {stage === "research" && (
              <>
                <button
                  className="sccap-btn"
                  disabled={busy}
                  onClick={() => {
                    setStage("select");
                    setResearch(null);
                  }}
                >
                  Cancel
                </button>
                <button
                  className="sccap-btn sccap-btn-primary"
                  disabled={busy}
                  onClick={() => void startTest()}
                >
                  <Icon.Play size={13} /> Proceed to test
                </button>
              </>
            )}
            {stage !== "research" && (
              <button
                className="sccap-btn sccap-btn-primary"
                disabled={!selectedCves.length || busy}
                onClick={() => void startResearch()}
              >
                <Icon.Search size={13} /> Research {selectedCves.length || ""} CVE
                {selectedCves.length === 1 ? "" : "s"}
              </button>
            )}
          </div>
        </div>

        <TerminalConsole
          title="this check"
          order="newest-first"
          lines={activity.lines}
          phase={{ phase: activity.phase, label: activity.label, detail: `${activity.elapsed}s` }}
          live={busy}
          maxHeight={300}
          emptyHint="Start a check: each CVE lookup, asset probe, match and detection test appears here, newest first."
          downloadName="cve-check"
          onClear={activity.clear}
          actions={
            <>
              <button
                className="is-primary"
                disabled={!selectedCves.length || busy}
                onClick={() => void startResearch()}
              >
                <Icon.Search size={11} /> Research
              </button>
              <button
                disabled={stage !== "research" || busy}
                onClick={() => void startTest()}
              >
                <Icon.Play size={11} /> Test
              </button>
              <button
                className="is-danger"
                disabled={!busy}
                onClick={async () => {
                  activity.finish("cancelled", "Stopping at the next step");
                  try {
                    await stopCveCheck();
                    toast.info("Stop requested — the check ends after the current step");
                  } catch {
                    toast.error("Could not reach the server to stop the check");
                  }
                }}
              >
                <Icon.X size={11} /> Stop
              </button>
              <button onClick={activity.clear}>Clear</button>
            </>
          }
        />
      </section>

      {stage === "research" && research && (
        <section className="sccap-card asset-card">
          <div className="asset-toolbar">
            <div>
              <strong>What would be tested</strong>
              <span className="asset-muted">
                Read this before proceeding — nothing has been sent to an asset yet.
              </span>
            </div>
            <button
              className="sccap-btn sccap-btn-primary"
              disabled={busy}
              onClick={() => void startTest()}
            >
              <Icon.Play size={13} /> Proceed to test
            </button>
          </div>
          <div className="asset-research">
            {research.map((item) => (
              <div key={item.cve_id} className="asset-research-card">
                <div className="asset-research-head">
                  <strong>{item.cve_id}</strong>
                  <span className={`asset-sev is-${item.severity ?? "unknown"}`}>
                    {item.severity ?? "unrated"}
                  </span>
                  {item.cvss_score != null && (
                    <span className="asset-muted">CVSS {item.cvss_score}</span>
                  )}
                  {item.kev && <span className="asset-chip is-kev">known exploited</span>}
                  {item.cwe && <span className="asset-muted">{item.cwe}</span>}
                </div>
                {item.error ? (
                  <p className="asset-muted">{item.error}</p>
                ) : (
                  <>
                    <p className="asset-research-text">
                      {item.description ?? "no description stored"}
                    </p>
                    {item.affected_products.length > 0 && (
                      <p className="asset-muted">
                        Affects: {item.affected_products.slice(0, 8).join(", ")}
                        {item.affected_products.length > 8
                          ? ` …+${item.affected_products.length - 8}`
                          : ""}
                      </p>
                    )}
                    {item.research_error && (
                      <p className="asset-muted">
                        Research unavailable — the model could not be reached (
                        {item.research_error.slice(0, 120)}). The corpus facts above are what is
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
                      {item.template && (
                        <pre className="asset-yaml">{item.template.slice(0, 1200)}</pre>
                      )}
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
                      <strong>Exploits ({item.exploit_references.length} references)</strong>
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
          </div>
        </section>
      )}

      <section className="sccap-card asset-card">
        <div className="asset-toolbar">
          <div>
            <strong>1 · CVEs</strong>
            <span className="asset-muted">
              Type an id, choose one from the corpus, or paste a list.
            </span>
          </div>
        </div>
        <div className="asset-cve-picker">
          <label className="asset-field">
            <span>CVE id</span>
            <input
              list="cve-suggestions"
              placeholder="CVE-2021-44228"
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
            <span className="asset-muted">{browseQ.data?.total ?? 0} CVE(s) in the local corpus.</span>
          </label>
          <label className="asset-field">
            <span>Or paste a list</span>
            <textarea
              className="asset-textarea"
              rows={3}
              placeholder="One per line, or comma separated"
              value={cveText}
              onChange={(event) => setCveText(event.target.value)}
              onBlur={() => {
                if (cveText.trim()) {
                  addCves(cveText);
                  setCveText("");
                }
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
                onClick={() => setSelectedCves((current) => current.filter((item) => item !== cve))}
              >
                {cve} <Icon.X size={10} />
              </button>
            ))}
            <button className="sccap-btn sccap-btn-sm" onClick={() => setSelectedCves([])}>
              Clear
            </button>
          </div>
        )}
      </section>

      <section className="sccap-card asset-card">
        <div className="asset-toolbar">
          <div>
            <strong>2 · Assets ({selectedAssets.size} selected)</strong>
            <span className="asset-muted">
              Nothing selected means the whole inventory. Click a row for detail.
            </span>
          </div>
          <div className="asset-inline-form">
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={() => setSelectedAssets(new Set(visible.map((a) => a.id)))}
            >
              Select all
            </button>
            <button className="sccap-btn sccap-btn-sm" onClick={() => setSelectedAssets(new Set())}>
              Select none
            </button>
          </div>
        </div>

        <AssetFiltersBar
          assets={assets}
          filters={filters}
          onChange={setFilters}
          count={visible.length}
        />

        <AssetTableWindow
          assets={visible}
          selected={selectedAssets}
          onToggle={(assetId) =>
            setSelectedAssets((current) => {
              const next = new Set(current);
              if (next.has(assetId)) next.delete(assetId);
              else next.add(assetId);
              return next;
            })
          }
          onSelectVisible={(rows, select) =>
            setSelectedAssets((current) => {
              const next = new Set(current);
              for (const asset of rows) {
                if (select) next.add(asset.id);
                else next.delete(asset.id);
              }
              return next;
            })
          }
        />
      </section>
    </>
  );
}
