// secure-code-ui/src/pages/assets/AssetsPage.tsx
//
// Asset inventory and CVE applicability.
//
// The page exists to answer one question honestly: does this CVE affect us? So it
// never shows a bare "yes" — every verdict carries its basis (declared version,
// observed banner, or a probe that was actually run) and its confidence, and an
// unverified candidate says so.

import { Fragment, useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { PageHeader } from "../../shared/ui/PageHeader";
import { Modal } from "../../shared/ui/Modal";
import TerminalConsole, { type ConsoleLine } from "../../shared/ui/TerminalConsole";
import { Icon } from "../../shared/ui/Icon";
import { useToast } from "../../shared/ui/Toast";
import {
  addDependencies,
  addService,
  addTechnology,
  probeInventory,
  checkCves,
  createAsset,
  assetsTemplateUrl,
  cancelProbe,
  getCveCheck,
  getProbeStatus,
  importAssets,
  updateAsset,
  listAssetEvents,
  putCveCheck,
  deleteAsset,
  getAsset,
  importCorpus,
  listAssets,
  listVerdicts,
  verifyVerdict,
  type Asset,
  type AssetImportSummary,
  type AssetKind,
  type CveVerdict,
  type Verdict,
} from "../../shared/api/assetsService";
import "./assets.css";

const KIND_LABEL: Record<AssetKind, string> = {
  web_app: "Web app",
  api: "API",
  host: "Host",
  service: "Service",
  repo: "Repository",
  vm: "VM / server",
  container: "Container image",
  k8s: "Kubernetes cluster",
  database: "Database",
  firewall: "Firewall / appliance",
  network: "Network device",
  cloud: "Cloud account / service",
};

const TECH_CATEGORIES = [
  "os",
  "database",
  "web",
  "container",
  "orchestrator",
  "network",
  "library",
  "other",
] as const;

const VERDICT_LABEL: Record<Verdict, string> = {
  applicable: "Applicable",
  not_applicable: "Not applicable",
  undetermined: "Needs a test",
};

const BASIS_HINT: Record<string, string> = {
  declared: "A dependency version from a scan — exact.",
  observed: "A version from a banner — a hypothesis.",
  probe: "A check was designed and run against the asset.",
};

type Tab = "assets" | "cves" | "corpus";

function splitCves(value: string): string[] {
  return value
    .split(/[\s,;]+/)
    .map((token) => token.trim().toUpperCase())
    .filter((token) => /^CVE-\d{4}-\d{4,}$/.test(token));
}

function VerdictChip({ verdict }: { verdict: Verdict }) {
  return <span className={`asset-verdict is-${verdict}`}>{VERDICT_LABEL[verdict]}</span>;
}

export default function AssetsPage() {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<Tab>("assets");
  const [openAssetId, setOpenAssetId] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [importSummary, setImportSummary] = useState<AssetImportSummary | null>(null);
  // Filters and paging: an inventory is read, not scrolled.
  const [query, setQuery] = useState("");
  const [kindFilter, setKindFilter] = useState("");
  const [envFilter, setEnvFilter] = useState("");
  const [techFilter, setTechFilter] = useState("");
  const [pageSize, setPageSize] = useState(20);
  // Selection is shared by "probe these" and "check CVEs against these".
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [limitToSelected, setLimitToSelected] = useState(false);
  const [page, setPage] = useState(1);
  const [importing, setImporting] = useState(false);
  const [cveQuery, setCveQuery] = useState("");
  const [verify, setVerify] = useState(false);
  const [checkFor, setCheckFor] = useState<string | null>(null);
  const [checkYaml, setCheckYaml] = useState<string>("");
  const [checkBusy, setCheckBusy] = useState(false);

  const [events, setEvents] = useState<ConsoleLine[]>([]);
  const [lastEventId, setLastEventId] = useState(0);
  const [busy, setBusy] = useState(false);
  const [busySince, setBusySince] = useState<string | null>(null);

  const eventsQ = useQuery({
    queryKey: ["assets", "events", lastEventId],
    queryFn: () => listAssetEvents(lastEventId),
    // Fast while work is running, relaxed otherwise: this is a live console, not a
    // status page.
    refetchInterval: busy ? 1200 : 6000,
  });

  useEffect(() => {
    const batch = eventsQ.data;
    if (!batch?.items?.length) return;
    setEvents((current) =>
      [
        ...current,
        ...batch.items.map((event) => ({
          id: event.id,
          at: event.at,
          level: event.level,
          kind: event.kind,
          message: event.message,
          detail: event.payload ?? undefined,
        })),
      ].slice(-600),
    );
    setLastEventId(batch.last_id);
  }, [eventsQ.data]);

  const statusQ = useQuery({
    queryKey: ["assets", "probe-status"],
    queryFn: getProbeStatus,
    refetchInterval: (q) => (q.state.data?.active ? 3000 : 15000),
  });
  const probeStatus = statusQ.data;

  const assetsQ = useQuery({ queryKey: ["assets"], queryFn: listAssets });
  const assets: Asset[] = assetsQ.data?.items ?? [];

  const environments = useMemo(
    () =>
      [...new Set(assets.map((asset) => asset.environment).filter(Boolean))].sort() as string[],
    [assets],
  );
  const technologies = useMemo(
    () =>
      [...new Set(assets.flatMap((asset) => asset.technology_names ?? []))].sort() as string[],
    [assets],
  );
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return assets.filter((asset) => {
      if (kindFilter && asset.kind !== kindFilter) return false;
      if (envFilter && (asset.environment ?? "") !== envFilter) return false;
      if (techFilter && !(asset.technology_names ?? []).includes(techFilter)) return false;
      if (!needle) return true;
      return (
        asset.name.toLowerCase().includes(needle) ||
        (asset.owner ?? "").toLowerCase().includes(needle) ||
        (asset.authorization_basis ?? "").toLowerCase().includes(needle)
      );
    });
  }, [assets, query, kindFilter, envFilter, techFilter]);
  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const visible = useMemo(
    () => filtered.slice((currentPage - 1) * pageSize, currentPage * pageSize),
    [filtered, currentPage, pageSize],
  );
  const corpus = assetsQ.data?.corpus;

  const verdictsQ = useQuery({
    queryKey: ["assets", "verdicts"],
    queryFn: () => listVerdicts({}),
    enabled: tab === "cves",
  });

  const detailQ = useQuery({
    queryKey: ["assets", openAssetId],
    queryFn: () => getAsset(openAssetId as string),
    enabled: Boolean(openAssetId),
  });

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ["assets"] });
  };

  const check = useMutation({
    onMutate: () => {
      setBusy(true);
      setBusySince(new Date().toISOString());
    },
    onSettled: () => {
      setBusy(false);
      setBusySince(null);
    },
    mutationFn: async () => {
      const ids = splitCves(cveQuery);
      // `scan` is what makes a check mean something for an asset that has never
      // been fingerprinted: it probes first, then matches.
      return checkCves({
        cve_ids: ids.length ? ids : null,
        verify,
        scan: true,
        asset_ids: limitToSelected && selectedIds.size ? [...selectedIds] : null,
      });
    },
    onSuccess: (result) => {
      const probed = result.assets_probed
        ? `${result.assets_probed} asset(s), ${result.endpoints_probed ?? 0} endpoint(s) probed, ` +
          `${result.fingerprints_found ?? 0} fingerprinted`
        : "";
      const parts = [
        probed,
        `${result.matched} candidate${result.matched === 1 ? "" : "s"}`,
        `${result.undetermined} need a test`,
        `${result.applicable} applicable`,
      ].filter(Boolean);
      if (result.verified) parts.push(`${result.verified} tested`);
      const fetched = result.enriched ?? [];
      if (fetched.length) {
        const unverified = result.unverified_cves ?? [];
        const trusted = fetched.filter(
          (item: { cve_id: string; source: string }) => !unverified.includes(item.cve_id),
        );
        if (trusted.length) {
          toast.info(
            `Fetched ${trusted.length} CVE(s) not in the corpus: ` +
              trusted
                .map((item: { cve_id: string; source: string }) => `${item.cve_id} (${item.source})`)
                .join(", "),
          );
        }
        if (unverified.length) {
          toast.error(
            `No advisory feed was reachable, so ${unverified.join(", ")} was reconstructed ` +
              "by the model — treat the verdict as unverified.",
          );
        }
      }
      if (result.unknown_cves?.length) {
        // Nothing anywhere could resolve these: that is genuinely unknown, not clean.
        toast.error(
          `Could not resolve ${result.unknown_cves.join(", ")} — not in the corpus, and ` +
            "no NVD/OSV fetch succeeded. Import a feed or check egress from the app container.",
        );
        return;
      }
      toast.success(parts.join(" · "));
      refresh();
      queryClient.invalidateQueries({ queryKey: ["assets", "verdicts"] });
    },
    onError: () => toast.error("Could not run the check"),
  });

  const probe = useMutation({
    onMutate: () => {
      setBusy(true);
      setBusySince(new Date().toISOString());
    },
    onSettled: () => {
      setBusy(false);
      setBusySince(null);
    },
    mutationFn: (input: { rescan: boolean; withNuclei?: boolean }) =>
      probeInventory({
        asset_ids: selectedIds.size ? [...selectedIds] : null,
        rescan: input.rescan,
        tools: input.withNuclei ? ["nmap", "whatweb", "nuclei"] : ["nmap", "whatweb"],
      }),
    onSuccess: (result) => {
      toast.success(
        result.note ??
          `${result.assets_probed} asset(s) probed · ${result.fingerprints_found} fingerprint(s)` +
            (result.products.length ? ` · ${result.products.join(", ")}` : ""),
      );
      refresh();
    },
    onError: () => toast.error("Could not probe the inventory"),
  });

  const openCheck = async (cveId: string) => {
    setCheckFor(cveId);
    setCheckBusy(true);
    setCheckYaml("");
    try {
      const existing = await getCveCheck(cveId);
      if (existing) {
        setCheckYaml(existing.template);
      } else {
        await putCveCheck(cveId);
        const created = await getCveCheck(cveId);
        setCheckYaml(created?.template ?? "");
        if (!created) toast.error("A check could not be designed for this CVE yet");
      }
    } catch {
      toast.error("Could not load the check");
    } finally {
      setCheckBusy(false);
    }
  };

  const verifyOne = useMutation({
    mutationFn: (verdictId: string) => verifyVerdict(verdictId),
    onSuccess: (result) => {
      toast.success(`${result.verdict.replace("_", " ")} · ${result.confidence} confidence`);
      queryClient.invalidateQueries({ queryKey: ["assets", "verdicts"] });
    },
    onError: () => toast.error("Could not verify this candidate"),
  });

  const verdicts: CveVerdict[] = verdictsQ.data ?? [];
  const grouped = useMemo(() => {
    const byVerdict: Record<Verdict, CveVerdict[]> = {
      applicable: [],
      undetermined: [],
      not_applicable: [],
    };
    for (const verdict of verdicts) byVerdict[verdict.verdict].push(verdict);
    return byVerdict;
  }, [verdicts]);

  return (
    <div className="c13-page assets-page fade-in">
      <PageHeader
        crumbs={[{ label: "Dashboard", to: "/account/dashboard" }, { label: "Asset inventory" }]}
        title="Asset inventory"
        subtitle="What you own, and which CVEs actually affect it. Adding an asset authorises testing its recorded hosts."
        actions={
          <button className="sccap-btn sccap-btn-primary" onClick={() => setCreateOpen(true)}>
            <Icon.Plus size={14} /> Add asset
          </button>
        }
      />

      <div className="asset-tabs" role="tablist">
        {(
          [
            ["assets", `Assets (${assets.length})`],
            ["cves", `CVE checks (${verdicts.length})`],
            ["corpus", `Corpus (${corpus?.cves ?? 0})`],
          ] as Array<[Tab, string]>
        ).map(([key, label]) => (
          <button
            key={key}
            role="tab"
            aria-selected={tab === key}
            className={`asset-tab${tab === key ? " is-active" : ""}`}
            onClick={() => setTab(key)}
          >
            {label}
          </button>
        ))}
      </div>

      <section className="sccap-card asset-card">
        <TerminalConsole
          title="inventory activity"
          lines={
            busy && busySince
              ? [
                  ...events,
                  {
                    id: "live",
                    at: busySince,
                    level: "info",
                    kind: "running",
                    message: "working — probing, matching and testing; entries appear below as each step finishes",
                    status: "running",
                    startedAt: busySince,
                  },
                ]
              : events
          }
          live={busy}
          emptyHint="Run a CVE check or probe the inventory: probing, fingerprinting, CVE lookups, matches and tests appear here as they happen."
          downloadName="inventory-activity"
          maxHeight={320}
          // Clears what is on screen. The events stay in the database as the log;
          // keeping the cursor means they do not reappear on the next poll.
          onClear={() => setEvents([])}
        />
      </section>

      {tab === "assets" && (
        <section className="sccap-card asset-card">
          <div className="asset-toolbar">
            <div>
              <strong>{assets.length} asset{assets.length === 1 ? "" : "s"}</strong>
              <span className="asset-muted">
                {corpus?.services ?? 0} endpoint(s) · {corpus?.dependencies ?? 0} package version(s)
              </span>
            </div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <label className="asset-upload" title="Create many assets from a CSV file">
                <Icon.Download size={13} />
                {importing ? "Importing…" : "Import CSV"}
                <input
                  type="file"
                  accept=".csv,text/csv"
                  disabled={importing}
                  onChange={async (event) => {
                    const file = event.target.files?.[0];
                    event.target.value = "";
                    if (!file) return;
                    setImporting(true);
                    try {
                      const summary = await importAssets(file);
                      setImportSummary(summary);
                      refresh();
                    } catch (err) {
                      const detail = (err as { response?: { data?: { detail?: string } } })
                        ?.response?.data?.detail;
                      toast.error(detail || "Could not import the file");
                    } finally {
                      setImporting(false);
                    }
                  }}
                />
              </label>
              <a className="sccap-btn" href={assetsTemplateUrl()} download>
                <Icon.Download size={13} /> Template
              </a>
              {probeStatus?.active && (
                <button
                  className="sccap-btn"
                  onClick={async () => {
                    try {
                      const result = await cancelProbe();
                      toast.info(
                        `Probe stop requested: ${result.cancelled} cancelled, ${result.stopping} stopping`,
                      );
                      statusQ.refetch();
                    } catch {
                      toast.error("Could not stop the probe");
                    }
                  }}
                >
                  <Icon.X size={13} /> Stop probe
                </button>
              )}
              <button
                className={`sccap-btn${probeStatus?.active ? " is-busy" : ""}`}
                disabled={probe.isPending || probeStatus?.active || assets.length === 0}
                onClick={() => probe.mutate({ rescan: true })}
                title="Scan every asset and store the technology and version it runs"
              >
                {probeStatus?.active ? (
                  <>
                    <span className="asset-pulse" /> Probing
                    {probeStatus.host ? ` ${probeStatus.host}` : ""}
                    {probeStatus.queued ? ` (+${probeStatus.queued} queued)` : ""}
                  </>
                ) : (
                  <>
                    <Icon.Shield size={13} />
                    {probe.isPending ? "Probing…" : "Probe inventory"}
                  </>
                )}
              </button>
            </div>
          </div>

          {assets.length > 0 && (
            <div className="asset-filters">
              <input
                className="asset-filter-input"
                placeholder="Filter by name, host or owner"
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setPage(1);
                }}
              />
              <select
                value={kindFilter}
                onChange={(e) => {
                  setKindFilter(e.target.value);
                  setPage(1);
                }}
              >
                <option value="">All kinds</option>
                {Object.entries(KIND_LABEL).map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </select>
              <select
                value={envFilter}
                onChange={(e) => {
                  setEnvFilter(e.target.value);
                  setPage(1);
                }}
              >
                <option value="">All environments</option>
                {environments.map((env) => (
                  <option key={env} value={env}>
                    {env}
                  </option>
                ))}
              </select>
              <select
                value={techFilter}
                onChange={(e) => {
                  setTechFilter(e.target.value);
                  setPage(1);
                }}
              >
                <option value="">All technologies</option>
                {technologies.map((tech) => (
                  <option key={tech} value={tech}>
                    {tech}
                  </option>
                ))}
              </select>
              {(query || kindFilter || envFilter || techFilter) && (
                <button
                  className="sccap-btn sccap-btn-sm"
                  onClick={() => {
                    setQuery("");
                    setKindFilter("");
                    setEnvFilter("");
                    setTechFilter("");
                    setPage(1);
                  }}
                >
                  Clear filters
                </button>
              )}
              {selectedIds.size > 0 && (
                <>
                  <span className="asset-chip">{selectedIds.size} selected</span>
                  <button
                    className="sccap-btn sccap-btn-sm"
                    disabled={probe.isPending || probeStatus?.active}
                    onClick={() => probe.mutate({ rescan: true })}
                  >
                    Probe selected
                  </button>
                  <button
                    className="sccap-btn sccap-btn-sm"
                    onClick={() => setSelectedIds(new Set())}
                  >
                    Clear selection
                  </button>
                  <label className="asset-check-inline">
                    <input
                      type="checkbox"
                      checked={limitToSelected}
                      onChange={(e) => setLimitToSelected(e.target.checked)}
                    />
                    also limit CVE checks to these
                  </label>
                </>
              )}
              <span className="asset-muted" style={{ marginLeft: "auto" }}>
                {filtered.length} of {assets.length} asset(s)
              </span>
            </div>
          )}

          {assets.length === 0 ? (
            <p className="asset-empty">
              No assets yet. Add the systems you are responsible for — that is what makes a
              CVE list answerable.
            </p>
          ) : filtered.length === 0 ? (
            <p className="asset-empty">No asset matches these filters.</p>
          ) : (
            <>
              <div className="asset-table-wrap">
                <table className="asset-table">
                  <thead>
                    <tr>
                      <th style={{ width: 32 }}>
                        <input
                          type="checkbox"
                          checked={visible.length > 0 && visible.every((a) => selectedIds.has(a.id))}
                          onChange={(e) => {
                            setSelectedIds((current) => {
                              const next = new Set(current);
                              for (const asset of visible) {
                                if (e.target.checked) next.add(asset.id);
                                else next.delete(asset.id);
                              }
                              return next;
                            });
                          }}
                          title="Select every asset on this page"
                        />
                      </th>
                      <th>Asset</th>
                      <th>Kind</th>
                      <th>Environment</th>
                      <th>Endpoints</th>
                      <th>Technologies</th>
                      <th>Packages</th>
                      <th>Authorisation</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {visible.map((asset) => (
                      <Fragment key={asset.id}>
                        <tr
                          className={openAssetId === asset.id ? "is-open" : ""}
                          onClick={() => setOpenAssetId(asset.id === openAssetId ? null : asset.id)}
                        >
                          <td onClick={(event) => event.stopPropagation()}>
                            <input
                              type="checkbox"
                              checked={selectedIds.has(asset.id)}
                              onChange={(e) => {
                                setSelectedIds((current) => {
                                  const next = new Set(current);
                                  if (e.target.checked) next.add(asset.id);
                                  else next.delete(asset.id);
                                  return next;
                                });
                              }}
                            />
                          </td>
                          <td>
                            <strong>{asset.name}</strong>
                            {asset.owner && <span className="asset-muted">{asset.owner}</span>}
                          </td>
                          <td>{KIND_LABEL[asset.kind] ?? asset.kind}</td>
                          <td>{asset.environment ?? "—"}</td>
                          <td>{asset.services ?? 0}</td>
                          <td title={(asset.technology_names ?? []).join(", ")}>
                            {asset.technologies ?? 0}
                          </td>
                          <td>{asset.dependencies ?? 0}</td>
                          <td className="asset-muted">{asset.authorization_basis ?? "—"}</td>
                          <td>
                            {!asset.in_scope && <span className="asset-chip">out of scope</span>}
                          </td>
                        </tr>
                        {openAssetId === asset.id && (
                          <tr className="asset-row-detail">
                            <td colSpan={9}>
                              {detailQ.isLoading ? (
                                <p className="asset-muted">Loading details…</p>
                              ) : detailQ.data ? (
                                <AssetDetailPanel
                                  detail={detailQ.data}
                                  onChanged={() => {
                                    queryClient.invalidateQueries({ queryKey: ["assets"] });
                                    queryClient.invalidateQueries({
                                      queryKey: ["assets", openAssetId],
                                    });
                                  }}
                                  onDeleted={() => {
                                    setOpenAssetId(null);
                                    refresh();
                                  }}
                                />
                              ) : null}
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="asset-pager">
                <span className="asset-muted">
                  Showing {(page - 1) * pageSize + 1}–
                  {Math.min(page * pageSize, filtered.length)} of {filtered.length}
                </span>
                <label className="asset-muted">
                  Rows
                  <select
                    value={pageSize}
                    onChange={(e) => {
                      setPageSize(Number(e.target.value));
                      setPage(1);
                    }}
                  >
                    {[20, 50, 100].map((size) => (
                      <option key={size} value={size}>
                        {size}
                      </option>
                    ))}
                  </select>
                </label>
                <div className="asset-pager-buttons">
                  <button
                    className="sccap-btn sccap-btn-sm"
                    disabled={page <= 1}
                    onClick={() => setPage((value) => Math.max(1, value - 1))}
                  >
                    Previous
                  </button>
                  <span className="asset-muted">
                    Page {page} of {totalPages}
                  </span>
                  <button
                    className="sccap-btn sccap-btn-sm"
                    disabled={page >= totalPages}
                    onClick={() => setPage((value) => Math.min(totalPages, value + 1))}
                  >
                    Next
                  </button>
                </div>
              </div>
            </>
          )}

        </section>
      )}

      {tab === "cves" && (
        <>
          <section className="sccap-card asset-card">
            <div className="asset-toolbar">
              <div>
                <strong>Check a CVE list</strong>
                <span className="asset-muted">
                  Paste CVEs, or leave empty to apply the whole local corpus.
                </span>
              </div>
            </div>
            <textarea
              className="asset-textarea"
              rows={3}
              value={cveQuery}
              onChange={(event) => setCveQuery(event.target.value)}
              placeholder="CVE-2021-23017, CVE-2021-23337 …"
            />
            <div className="asset-inline-form">
              <label className="asset-upload">
                <Icon.Download size={13} /> Upload a list (.txt / .csv)
                <input
                  type="file"
                  accept=".txt,.csv,.json,text/plain"
                  onChange={async (event) => {
                    const file = event.target.files?.[0];
                    if (!file) return;
                    const text = await file.text();
                    const ids = splitCves(text);
                    if (!ids.length) {
                      toast.error("No CVE ids found in that file");
                    } else {
                      setCveQuery(ids.join("\n"));
                      toast.info(`${ids.length} CVE id(s) loaded from ${file.name}`);
                    }
                    event.target.value = "";
                  }}
                />
              </label>
              <span className="asset-muted">
                One per line, or comma separated; anything that is not a CVE id is ignored.
              </span>
            </div>
            <div className="asset-toolbar asset-toolbar-actions">
              <label className="asset-check">
                <input
                  type="checkbox"
                  checked={verify}
                  onChange={(event) => setVerify(event.target.checked)}
                />
                Test the uncertain candidates
                <span className="asset-muted">
                  The model designs a read-only check, runs it, and a verdict without
                  evidence is downgraded to “needs a test”.
                </span>
              </label>
              <button className="sccap-btn sccap-btn-primary" disabled={check.isPending} onClick={() => check.mutate()}>
                <Icon.Play size={13} /> {check.isPending ? "Checking…" : "Check"}
              </button>
            </div>
          </section>

          <section className="sccap-card asset-card">
            {verdicts.length === 0 ? (
              <p className="asset-empty">No verdicts yet. Run a check to see what applies.</p>
            ) : (
              (["applicable", "undetermined", "not_applicable"] as Verdict[]).map((key) =>
                grouped[key].length === 0 ? null : (
                  <div key={key} className="asset-verdict-group">
                    <h3>
                      <VerdictChip verdict={key} /> {grouped[key].length}
                    </h3>
                    <div className="asset-table-wrap">
                      <table className="asset-table">
                        <thead>
                          <tr>
                            <th>CVE</th>
                            <th>Asset</th>
                            <th>Severity</th>
                            <th>Basis</th>
                            <th>Confidence</th>
                            <th>Why</th>
                            <th />
                          </tr>
                        </thead>
                        <tbody>
                          {grouped[key].map((verdict) => (
                            <tr key={verdict.id}>
                              <td>
                                <strong>{verdict.cve_id}</strong>
                                {verdict.kev && <span className="asset-chip is-kev">KEV</span>}
                                <span className="asset-muted">{verdict.title}</span>
                              </td>
                              <td>{verdict.asset_name}</td>
                              <td>
                                {verdict.severity ?? "—"}
                                {verdict.cvss_score != null ? ` · ${verdict.cvss_score.toFixed(1)}` : ""}
                              </td>
                              <td title={BASIS_HINT[verdict.basis]}>{verdict.basis}</td>
                              <td>{verdict.confidence}</td>
                              <td className="asset-reason">{verdict.reason ?? "—"}</td>
                              <td>
                                <button
                                  className="sccap-btn sccap-btn-sm"
                                  onClick={() => void openCheck(verdict.cve_id)}
                                  title="The stored Nuclei-style check that decides this CVE"
                                >
                                  <Icon.Code size={12} /> Check
                                </button>
                                {verdict.verdict === "undetermined" && verdict.basis === "observed" && (
                                  <button
                                    className="sccap-btn sccap-btn-sm"
                                    disabled={verifyOne.isPending}
                                    onClick={() => verifyOne.mutate(verdict.id)}
                                  >
                                    <Icon.Shield size={12} /> Test
                                  </button>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                ),
              )
            )}
          </section>
        </>
      )}

      {tab === "corpus" && (
        <section className="sccap-card asset-card">
          <div className="asset-toolbar">
            <div>
              <strong>Local CVE corpus</strong>
              <span className="asset-muted">
                Offline feeds only: a verdict that depends on a live API cannot be reproduced.
              </span>
            </div>
          </div>
          <div className="asset-stats">
            <div>
              <span>{corpus?.cves ?? 0}</span>
              <label>CVEs</label>
            </div>
            <div>
              <span>{corpus?.kev ?? 0}</span>
              <label>known exploited</label>
            </div>
            <div>
              <span>{corpus?.affected_ranges ?? 0}</span>
              <label>affected ranges</label>
            </div>
            <div>
              <span>{corpus?.dependencies ?? 0}</span>
              <label>declared versions</label>
            </div>
          </div>
          <div className="asset-imports">
            {(
              [
                ["nvd", "NVD 2.0 page (JSON)", "api.nvd.nist.gov/rest/json/cves/2.0"],
                ["osv", "OSV record or zip export", "osv.dev / a zip of ecosystem advisories"],
                ["kev", "CISA KEV catalogue", "cisa.gov known_exploited_vulnerabilities.json"],
              ] as Array<["nvd" | "osv" | "kev", string, string]>
            ).map(([kind, label, source]) => (
              <label key={kind} className="asset-import">
                <strong>{label}</strong>
                <span className="asset-muted">{source}</span>
                <input
                  type="file"
                  accept={kind === "osv" ? ".json,.zip" : ".json"}
                  onChange={async (event) => {
                    const file = event.target.files?.[0];
                    if (!file) return;
                    try {
                      const result = await importCorpus(kind, file);
                      toast.success(
                        `${kind.toUpperCase()} imported · ` +
                          Object.entries(result)
                            .map(([key, value]) => `${value} ${key}`)
                            .join(" · "),
                      );
                      refresh();
                    } catch {
                      toast.error(`Could not import ${kind.toUpperCase()} feed`);
                    } finally {
                      event.target.value = "";
                    }
                  }}
                />
              </label>
            ))}
          </div>
        </section>
      )}

      <Modal
        open={checkFor !== null}
        onClose={() => setCheckFor(null)}
        title={`Detection check · ${checkFor ?? ""}`}
        width={760}
        footer={
          <>
            <button className="sccap-btn" onClick={() => setCheckFor(null)}>
              Close
            </button>
            <button
              className="sccap-btn"
              disabled={!checkYaml.trim() || checkBusy}
              onClick={async () => {
                if (!checkFor) return;
                try {
                  await putCveCheck(checkFor, checkYaml);
                  toast.success("Check saved; the next verification uses it");
                } catch {
                  toast.error("The check was rejected (read-only requests and matchers only)");
                }
              }}
            >
              Save check
            </button>
          </>
        }
      >
        <p className="asset-muted">
          One check per CVE, replayed against every asset. Read-only requests only
          (GET/HEAD/OPTIONS), no request body, matchers over header or body — the same
          shape Nuclei uses, so it can be exported and run by hand.
        </p>
        <textarea
          className="asset-textarea asset-yaml"
          rows={18}
          value={checkBusy ? "Designing a check…" : checkYaml}
          onChange={(event) => setCheckYaml(event.target.value)}
          spellCheck={false}
        />
      </Modal>

      <Modal
        open={importSummary !== null}
        onClose={() => setImportSummary(null)}
        title="Import summary"
        width={720}
        footer={
          <button className="sccap-btn" onClick={() => setImportSummary(null)}>
            Close
          </button>
        }
      >
        {importSummary && (
          <div className="asset-import-summary">
            <p className="asset-muted">
              {importSummary.total} row(s) read: <strong>{importSummary.created} created</strong>,{" "}
              {importSummary.duplicates} duplicate(s) skipped, {importSummary.rejected} rejected.
            </p>

            {importSummary.created_assets.length > 0 && (
              <div>
                <h4>Created</h4>
                <ul className="asset-list asset-list-compact">
                  {importSummary.created_assets.map((asset) => (
                    <li key={asset.id}>
                      <strong>{asset.name}</strong>
                      <span>{asset.kind}</span>
                      {asset.host && <span className="asset-muted">{asset.host}</span>}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {importSummary.duplicate_names.length > 0 && (
              <div>
                <h4>Already in the inventory (skipped)</h4>
                <p className="asset-muted">
                  {importSummary.duplicate_names.join(", ")} — existing assets are never
                  overwritten by an import.
                </p>
              </div>
            )}

            {importSummary.rejected_rows.length > 0 && (
              <div>
                <h4>Rejected</h4>
                <ul className="asset-list asset-list-compact">
                  {importSummary.rejected_rows.map((row) => (
                    <li key={`${row.line}-${row.name}`}>
                      <span>line {row.line}</span>
                      <strong>{row.name ?? "(no name)"}</strong>
                      <span className="asset-muted">{row.reason}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </Modal>

      <CreateAssetModal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        onCreated={() => {
          setCreateOpen(false);
          refresh();
        }}
      />
    </div>
  );
}

function AssetDetailPanel({
  detail,
  onChanged,
  onDeleted,
}: {
  detail: {
    id: string;
    name: string;
    authorization_basis: string | null;
    services: Array<{
      id: string;
      host: string;
      port: number | null;
      protocol: string;
      product: string | null;
      version: string | null;
      source: string;
      confidence: string;
    }>;
    dependencies: Array<{ id: string; ecosystem: string; package: string; version: string | null }>;
    technologies: Array<{
      id: string;
      product: string;
      version: string | null;
      category: string;
      source: string;
    }>;
  };
  onChanged: () => void;
  onDeleted: () => void;
}) {
  const toast = useToast();
  const [techProduct, setTechProduct] = useState("");
  const [techVersion, setTechVersion] = useState("");
  const [techCategory, setTechCategory] = useState<(typeof TECH_CATEGORIES)[number]>("other");
  const [host, setHost] = useState("");
  const [port, setPort] = useState("");
  const [product, setProduct] = useState("");
  const [version, setVersion] = useState("");
  const [packages, setPackages] = useState("");

  const addTech = useMutation({
    mutationFn: () =>
      addTechnology(detail.id, {
        product: techProduct.trim(),
        version: techVersion.trim() || null,
        category: techCategory,
        confidence: techVersion.trim() ? "exact" : "heuristic",
      }),
    onSuccess: () => {
      setTechProduct("");
      setTechVersion("");
      toast.success("Technology recorded");
      onChanged();
    },
    onError: () => toast.error("Could not record the technology"),
  });

  const add = useMutation({
    mutationFn: () =>
      addService(detail.id, {
        host: host.trim(),
        port: port ? Number(port) : null,
        protocol: "https",
        product: product.trim() || null,
        version: version.trim() || null,
        source: "manual",
        confidence: version.trim() ? "exact" : "heuristic",
      }),
    onSuccess: () => {
      setHost("");
      setPort("");
      setProduct("");
      setVersion("");
      toast.success("Endpoint added");
      onChanged();
    },
    onError: () => toast.error("Could not add the endpoint"),
  });

  const importPackages = useMutation({
    mutationFn: () => {
      // Accepts "ecosystem/package@version" per line, or a JSON list.
      const raw = packages.trim();
      if (!raw) return Promise.resolve({ stored: 0 });
      let list: Array<{ ecosystem: string; package: string; version?: string }> = [];
      if (raw.startsWith("[") || raw.startsWith("{")) {
        const parsed = JSON.parse(raw);
        const items = Array.isArray(parsed) ? parsed : parsed.packages ?? [];
        list = items.map((item: Record<string, string>) => ({
          ecosystem: item.ecosystem ?? "unknown",
          package: item.package ?? item.name ?? "",
          version: item.version,
        }));
      } else {
        list = raw
          .split("\n")
          .map((line) => line.trim())
          .filter(Boolean)
          .map((line) => {
            const match = line.match(/^([^/]+)\/(.+)@(.+)$/);
            if (match) return { ecosystem: match[1], package: match[2], version: match[3] };
            const simple = line.match(/^(.+)@(.+)$/);
            return simple
              ? { ecosystem: "unknown", package: simple[1], version: simple[2] }
              : { ecosystem: "unknown", package: line };
          });
      }
      return addDependencies(detail.id, list);
    },
    onSuccess: (result) => {
      setPackages("");
      toast.success(`${result.stored} package version(s) imported`);
      onChanged();
    },
    onError: () => toast.error("Could not import the packages"),
  });

  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState({
    name: detail.name,
    kind: (detail as { kind?: string }).kind ?? "web_app",
    owner: (detail as { owner?: string | null }).owner ?? "",
    environment: (detail as { environment?: string | null }).environment ?? "",
    authorization_basis: (detail as { authorization_basis?: string | null }).authorization_basis ?? "",
  });

  const save = useMutation({
    mutationFn: () =>
      updateAsset(detail.id, {
        name: draft.name.trim(),
        kind: draft.kind as never,
        owner: draft.owner.trim() || null,
        environment: draft.environment.trim() || null,
        authorization_basis: draft.authorization_basis.trim() || null,
      }),
    onSuccess: () => {
      setEditing(false);
      toast.success("Asset updated");
      onChanged();
    },
    onError: () => toast.error("Could not update the asset"),
  });

  const remove = useMutation({
    mutationFn: () => deleteAsset(detail.id),
    onSuccess: () => {
      toast.success("Asset removed");
      onDeleted();
    },
    onError: () => toast.error("Could not remove the asset"),
  });

  return (
    <div className="asset-detail">
      <div className="asset-toolbar">
        <div>
          <strong>{detail.name}</strong>
          <span className="asset-muted">
            Authorisation: {detail.authorization_basis ?? "not recorded"}
          </span>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button className="sccap-btn sccap-btn-sm" onClick={() => setEditing((v) => !v)}>
            <Icon.Settings size={12} /> {editing ? "Cancel" : "Edit asset"}
          </button>
          <button className="sccap-btn sccap-btn-ghost" onClick={() => remove.mutate()}>
            <Icon.X size={13} /> Remove asset
          </button>
        </div>
      </div>

      {editing && (
        <div className="asset-inline-form asset-edit-form">
          <input
            value={draft.name}
            onChange={(e) => setDraft({ ...draft, name: e.target.value })}
            placeholder="name"
          />
          <select
            value={draft.kind}
            onChange={(e) => setDraft({ ...draft, kind: e.target.value })}
          >
            {Object.entries(KIND_LABEL).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
          <input
            value={draft.owner}
            onChange={(e) => setDraft({ ...draft, owner: e.target.value })}
            placeholder="owner"
          />
          <input
            value={draft.environment}
            onChange={(e) => setDraft({ ...draft, environment: e.target.value })}
            placeholder="environment"
          />
          <input
            value={draft.authorization_basis}
            onChange={(e) => setDraft({ ...draft, authorization_basis: e.target.value })}
            placeholder="authorisation basis"
            style={{ minWidth: 220 }}
          />
          <button
            className="sccap-btn sccap-btn-sm sccap-btn-primary"
            disabled={!draft.name.trim() || save.isPending}
            onClick={() => save.mutate()}
          >
            {save.isPending ? "Saving…" : "Save"}
          </button>
        </div>
      )}

      <div className="asset-detail-grid">
        <div>
          <h4>Technologies ({detail.technologies.length})</h4>
          <p className="asset-muted">
            What the asset runs. A database, appliance or cluster can be recorded here
            without a URL — that is what makes it checkable against a CVE list.
          </p>
          {detail.technologies.length > 0 && (
            <ul className="asset-list asset-list-compact">
              {detail.technologies.map((technology) => (
                <li key={technology.id}>
                  <strong>{technology.product}</strong>
                  <span>{technology.version ?? "version unknown"}</span>
                  <span className="asset-muted">
                    {technology.category} · {technology.source}
                  </span>
                </li>
              ))}
            </ul>
          )}
          <div className="asset-inline-form">
            <input
              placeholder="product (postgresql)"
              value={techProduct}
              onChange={(e) => setTechProduct(e.target.value)}
              style={{ width: 150 }}
            />
            <input
              placeholder="version"
              value={techVersion}
              onChange={(e) => setTechVersion(e.target.value)}
              style={{ width: 90 }}
            />
            <select
              value={techCategory}
              onChange={(e) => setTechCategory(e.target.value as (typeof TECH_CATEGORIES)[number])}
            >
              {TECH_CATEGORIES.map((category) => (
                <option key={category} value={category}>
                  {category}
                </option>
              ))}
            </select>
            <button
              className="sccap-btn sccap-btn-sm"
              disabled={!techProduct.trim() || addTech.isPending}
              onClick={() => addTech.mutate()}
            >
              Add technology
            </button>
          </div>
        </div>

        <div>
          <h4>Endpoints ({detail.services.length})</h4>
          {detail.services.length === 0 ? (
            <p className="asset-muted">No endpoints recorded. Add the host and port this asset serves.</p>
          ) : (
            <ul className="asset-list">
              {detail.services.map((service) => (
                <li key={service.id}>
                  <code>
                    {service.protocol}://{service.host}
                    {service.port && service.port !== 443 ? `:${service.port}` : ""}
                  </code>
                  <span>
                    {service.product ?? "unknown product"} {service.version ?? ""}
                  </span>
                  <span className="asset-muted">
                    {service.source} · {service.confidence}
                  </span>
                </li>
              ))}
            </ul>
          )}
          <div className="asset-inline-form">
            <input placeholder="host (app.example.com)" value={host} onChange={(e) => setHost(e.target.value)} />
            <input placeholder="port" value={port} onChange={(e) => setPort(e.target.value)} style={{ width: 80 }} />
            <input placeholder="product" value={product} onChange={(e) => setProduct(e.target.value)} style={{ width: 120 }} />
            <input placeholder="version" value={version} onChange={(e) => setVersion(e.target.value)} style={{ width: 100 }} />
            <button className="sccap-btn sccap-btn-sm" disabled={!host.trim() || add.isPending} onClick={() => add.mutate()}>
              Add endpoint
            </button>
          </div>
        </div>

        <div>
          <h4>Declared packages ({detail.dependencies.length})</h4>
          <p className="asset-muted">
            Versions the build actually resolved. This is the exact half of the matcher.
          </p>
          <textarea
            className="asset-textarea"
            rows={4}
            value={packages}
            onChange={(event) => setPackages(event.target.value)}
            placeholder={"npm/lodash@4.17.20\npypi/requests@2.31.0"}
          />
          <button
            className="sccap-btn sccap-btn-sm"
            disabled={!packages.trim() || importPackages.isPending}
            onClick={() => importPackages.mutate()}
          >
            Import packages
          </button>
          {detail.dependencies.length > 0 && (
            <ul className="asset-list asset-list-compact">
              {detail.dependencies.slice(0, 40).map((dependency) => (
                <li key={dependency.id}>
                  <code>
                    {dependency.ecosystem}/{dependency.package}
                  </code>
                  <span>{dependency.version ?? "unknown version"}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}

function CreateAssetModal({
  open,
  onClose,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  onCreated: () => void;
}) {
  const toast = useToast();
  const [name, setName] = useState("");
  const [kind, setKind] = useState<AssetKind>("web_app");
  const [owner, setOwner] = useState("");
  const [environment, setEnvironment] = useState("production");
  const [basis, setBasis] = useState("");
  const [host, setHost] = useState("");

  const create = useMutation({
    mutationFn: async () => {
      const asset = await createAsset({
        name: name.trim(),
        kind,
        owner: owner.trim() || null,
        environment: environment.trim() || null,
        in_scope: true,
        authorization_basis: basis.trim() || "added to the asset inventory",
      });
      if (host.trim()) {
        await addService(asset.id, { host: host.trim(), source: "manual", confidence: "heuristic" });
      }
      return asset;
    },
    onSuccess: () => {
      setName("");
      setOwner("");
      setBasis("");
      setHost("");
      toast.success("Asset added and authorised");
      onCreated();
    },
    onError: () => toast.error("Could not add the asset"),
  });

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Add an asset"
      footer={
        <>
          <button className="sccap-btn" onClick={onClose}>
            Cancel
          </button>
          <button
            className="sccap-btn sccap-btn-primary"
            disabled={!name.trim() || create.isPending}
            onClick={() => create.mutate()}
          >
            {create.isPending ? "Adding…" : "Add and authorise"}
          </button>
        </>
      }
    >
      <div className="asset-form">
        <label>
          <span>Name</span>
          <input value={name} onChange={(event) => setName(event.target.value)} placeholder="Customer portal" />
        </label>
        <label>
          <span>Kind</span>
          <select value={kind} onChange={(event) => setKind(event.target.value as AssetKind)}>
            {Object.entries(KIND_LABEL).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>Owner</span>
          <input value={owner} onChange={(event) => setOwner(event.target.value)} placeholder="team-payments" />
        </label>
        <label>
          <span>Environment</span>
          <input value={environment} onChange={(event) => setEnvironment(event.target.value)} />
        </label>
        <label>
          <span>Host</span>
          <input value={host} onChange={(event) => setHost(event.target.value)} placeholder="portal.example.com" />
        </label>
        <label>
          <span>Authorisation basis</span>
          <input
            value={basis}
            onChange={(event) => setBasis(event.target.value)}
            placeholder="Owned by us; engagement ref"
          />
          <small className="asset-muted">
            Adding an asset authorises fingerprinting its recorded hosts. Recording why makes
            that auditable.
          </small>
        </label>
      </div>
    </Modal>
  );
}
