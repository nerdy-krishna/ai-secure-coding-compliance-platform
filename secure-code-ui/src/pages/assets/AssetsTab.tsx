// secure-code-ui/src/pages/assets/AssetsTab.tsx
//
// Page 2: the inventory itself.
//
// Every row says when it was last scanned and whether it answered, because "0 services
// found" means something different on a host that never responded. Scanning is started from
// here, over all assets or a chosen few.

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  assetsTemplateUrl,
  createAsset,
  getAsset,
  importAssets,
  listAssets,
  probeInventory,
  type Asset,
  type AssetImportSummary,
  type AssetKind,
} from "../../shared/api/assetsService";
import { Icon } from "../../shared/ui/Icon";
import { Modal } from "../../shared/ui/Modal";
import { useToast } from "../../shared/ui/Toast";
import AssetDetailPanel from "./AssetDetailPanel";

const KIND_LABEL: Record<string, string> = {
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

function when(value: string | null | undefined): string {
  if (!value) return "never";
  const then = new Date(value).getTime();
  const minutes = Math.round((Date.now() - then) / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

type SortKey = "name" | "kind" | "environment" | "reachable" | "last_probe_at";

export default function AssetsTab({ probeActive }: { probeActive: boolean }) {
  const toast = useToast();
  const queryClient = useQueryClient();

  const [query, setQuery] = useState("");
  const [kindFilter, setKindFilter] = useState("");
  const [envFilter, setEnvFilter] = useState("");
  const [reachFilter, setReachFilter] = useState("");
  const [sortBy, setSortBy] = useState<SortKey>("name");
  const [pageSize, setPageSize] = useState(20);
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [openId, setOpenId] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [scanOpen, setScanOpen] = useState(false);
  const [importSummary, setImportSummary] = useState<AssetImportSummary | null>(null);
  const [importing, setImporting] = useState(false);

  const assetsQ = useQuery({ queryKey: ["assets"], queryFn: listAssets });
  const assets: Asset[] = assetsQ.data?.items ?? [];

  const detailQ = useQuery({
    queryKey: ["assets", openId],
    queryFn: () => getAsset(openId as string),
    enabled: Boolean(openId),
  });

  const environments = useMemo(
    () => [...new Set(assets.map((a) => a.environment).filter(Boolean))].sort() as string[],
    [assets],
  );

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const rows = assets.filter((asset) => {
      if (kindFilter && asset.kind !== kindFilter) return false;
      if (envFilter && (asset.environment ?? "") !== envFilter) return false;
      if (reachFilter === "up" && asset.reachable !== true) return false;
      if (reachFilter === "down" && asset.reachable !== false) return false;
      if (reachFilter === "never" && asset.reachable != null) return false;
      if (!needle) return true;
      return (
        asset.name.toLowerCase().includes(needle) ||
        (asset.owner ?? "").toLowerCase().includes(needle) ||
        (asset.technology_names ?? []).some((tech) => tech.toLowerCase().includes(needle))
      );
    });
    return [...rows].sort((a, b) => {
      if (sortBy === "reachable") return Number(b.reachable ?? -1) - Number(a.reachable ?? -1);
      if (sortBy === "last_probe_at") {
        return (b.last_probe_at ?? "").localeCompare(a.last_probe_at ?? "");
      }
      return String(a[sortBy] ?? "").localeCompare(String(b[sortBy] ?? ""));
    });
  }, [assets, query, kindFilter, envFilter, reachFilter, sortBy]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const visible = filtered.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const probe = useMutation({
    mutationFn: (assetIds: string[] | null) =>
      probeInventory({ asset_ids: assetIds, rescan: true, tools: ["nmap", "whatweb"] }),
    onSuccess: (result) => {
      setScanOpen(false);
      toast.success(
        result.queued
          ? `Queued ${result.queued} asset(s) for the pentest engine`
          : `${result.fingerprints_found} fingerprint(s) from ${result.endpoints_probed} endpoint(s)`,
      );
      queryClient.invalidateQueries({ queryKey: ["assets"] });
    },
    onError: () => toast.error("Could not start the scan"),
  });

  return (
    <>
      <section className="sccap-card asset-card">
        <div className="asset-toolbar">
          <div>
            <strong>
              {assets.length} asset{assets.length === 1 ? "" : "s"}
            </strong>
            <span className="asset-muted">
              {assets.filter((a) => a.reachable === false).length} unreachable on last check ·{" "}
              {assets.filter((a) => a.reachable == null).length} never checked
            </span>
          </div>
          <div className="asset-inline-form">
            <button className="sccap-btn" disabled={!assets.length || probeActive} onClick={() => setScanOpen(true)}>
              <Icon.Shield size={13} /> Scan assets
            </button>
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
                    queryClient.invalidateQueries({ queryKey: ["assets"] });
                  } catch (err) {
                    const detail = (err as { response?: { data?: { detail?: string } } })?.response
                      ?.data?.detail;
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
            <button className="sccap-btn sccap-btn-primary" onClick={() => setCreateOpen(true)}>
              <Icon.Plus size={14} /> Add asset
            </button>
          </div>
        </div>

        {assets.length > 0 && (
          <div className="asset-filters">
            <input
              className="asset-filter-input"
              placeholder="Filter by name, owner or technology"
              value={query}
              onChange={(event) => {
                setQuery(event.target.value);
                setPage(1);
              }}
            />
            <select value={kindFilter} onChange={(event) => setKindFilter(event.target.value)}>
              <option value="">All kinds</option>
              {[...new Set(assets.map((a) => a.kind))].sort().map((kind) => (
                <option key={kind} value={kind}>
                  {KIND_LABEL[kind] ?? kind}
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
            <select value={reachFilter} onChange={(event) => setReachFilter(event.target.value)}>
              <option value="">Any reachability</option>
              <option value="up">Reachable</option>
              <option value="down">Unreachable</option>
              <option value="never">Never checked</option>
            </select>
            <select value={sortBy} onChange={(event) => setSortBy(event.target.value as SortKey)}>
              <option value="name">Sort: name</option>
              <option value="kind">Sort: kind</option>
              <option value="environment">Sort: environment</option>
              <option value="reachable">Sort: reachable first</option>
              <option value="last_probe_at">Sort: recently scanned</option>
            </select>
            <span className="asset-muted" style={{ marginLeft: "auto" }}>
              {filtered.length} of {assets.length}
            </span>
          </div>
        )}

        {assets.length === 0 ? (
          <p className="asset-empty">
            No assets yet. Add the systems you are responsible for — that is what makes a CVE
            list answerable.
          </p>
        ) : (
          <>
            <div className="asset-table-wrap">
              <table className="asset-table">
                <thead>
                  <tr>
                    <th style={{ width: 32 }}>
                      <input
                        type="checkbox"
                        checked={visible.length > 0 && visible.every((a) => selected.has(a.id))}
                        onChange={(event) =>
                          setSelected((current) => {
                            const next = new Set(current);
                            for (const asset of visible) {
                              if (event.target.checked) next.add(asset.id);
                              else next.delete(asset.id);
                            }
                            return next;
                          })
                        }
                        title="Select this page"
                      />
                    </th>
                    <th>Asset</th>
                    <th>Kind</th>
                    <th>Environment</th>
                    <th>Last scanned</th>
                    <th>Reachability</th>
                    <th>Endpoints</th>
                    <th>Technologies</th>
                    <th>Packages</th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map((asset) => (
                    <>
                      <tr
                        key={asset.id}
                        className={openId === asset.id ? "is-open" : ""}
                        onClick={() => setOpenId(asset.id === openId ? null : asset.id)}
                      >
                        <td onClick={(event) => event.stopPropagation()}>
                          <input
                            type="checkbox"
                            checked={selected.has(asset.id)}
                            onChange={(event) =>
                              setSelected((current) => {
                                const next = new Set(current);
                                if (event.target.checked) next.add(asset.id);
                                else next.delete(asset.id);
                                return next;
                              })
                            }
                          />
                        </td>
                        <td>
                          <strong>{asset.name}</strong>
                          {asset.owner && <span className="asset-muted">{asset.owner}</span>}
                        </td>
                        <td>{KIND_LABEL[asset.kind] ?? asset.kind}</td>
                        <td>{asset.environment ?? "—"}</td>
                        <td title={asset.last_probe_at ?? "never scanned"}>
                          {when(asset.last_probe_at)}
                        </td>
                        <td>
                          <span
                            className={`asset-reach is-${
                              asset.reachable === true
                                ? "ok"
                                : asset.reachable === false
                                  ? "bad"
                                  : "unknown"
                            }`}
                          >
                            {asset.reachable === true
                              ? "reachable"
                              : asset.reachable === false
                                ? `unreachable (${asset.unreachable_reason ?? "?"})`
                                : "unknown"}
                          </span>
                        </td>
                        <td>{asset.services ?? 0}</td>
                        <td title={(asset.technology_names ?? []).join(", ")}>
                          {asset.technologies ?? 0}
                        </td>
                        <td>{asset.dependencies ?? 0}</td>
                      </tr>
                      {openId === asset.id && (
                        <tr key={`${asset.id}-detail`} className="asset-row-detail">
                          <td colSpan={9}>
                            {detailQ.isLoading ? (
                              <p className="asset-muted">Loading details…</p>
                            ) : detailQ.data ? (
                              <AssetDetailPanel
                                detail={detailQ.data}
                                onChanged={() => {
                                  queryClient.invalidateQueries({ queryKey: ["assets"] });
                                  queryClient.invalidateQueries({ queryKey: ["assets", openId] });
                                }}
                                onDeleted={() => {
                                  setOpenId(null);
                                  queryClient.invalidateQueries({ queryKey: ["assets"] });
                                }}
                              />
                            ) : null}
                          </td>
                        </tr>
                      )}
                    </>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="asset-pager">
              <span className="asset-muted">
                Showing {(currentPage - 1) * pageSize + 1}–{Math.min(currentPage * pageSize, filtered.length)}{" "}
                of {filtered.length}
              </span>
              <label className="asset-muted">
                Rows
                <select
                  value={pageSize}
                  onChange={(event) => {
                    setPageSize(Number(event.target.value));
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
                  disabled={currentPage <= 1}
                  onClick={() => setPage((value) => Math.max(1, value - 1))}
                >
                  Previous
                </button>
                <span className="asset-muted">
                  Page {currentPage} of {totalPages}
                </span>
                <button
                  className="sccap-btn sccap-btn-sm"
                  disabled={currentPage >= totalPages}
                  onClick={() => setPage((value) => Math.min(totalPages, value + 1))}
                >
                  Next
                </button>
              </div>
            </div>
          </>
        )}
      </section>

      <Modal
        open={scanOpen}
        onClose={() => setScanOpen(false)}
        title="Scan asset information"
        width={640}
        footer={
          <>
            <button className="sccap-btn" onClick={() => setScanOpen(false)}>
              Cancel
            </button>
            <button
              className="sccap-btn sccap-btn-primary"
              disabled={probe.isPending}
              onClick={() => probe.mutate(selected.size ? [...selected] : null)}
            >
              {probe.isPending
                ? "Starting…"
                : `Scan ${selected.size || assets.length} asset(s)`}
            </button>
          </>
        }
      >
        <p className="asset-muted">
          Each asset is checked for reachability first — a host that will not answer is marked
          and skipped, so the scan is not spent on it — then nmap and whatweb identify what it
          runs.
        </p>
        <div className="asset-inline-form" style={{ marginBottom: 8 }}>
          <button
            className="sccap-btn sccap-btn-sm"
            onClick={() => setSelected(new Set(assets.map((a) => a.id)))}
          >
            Select all
          </button>
          <button className="sccap-btn sccap-btn-sm" onClick={() => setSelected(new Set())}>
            Select none
          </button>
          <span className="asset-muted">{selected.size} selected</span>
        </div>
        <div className="asset-pick-list">
          {assets.map((asset) => (
            <label key={asset.id} className="asset-pick-row">
              <input
                type="checkbox"
                checked={selected.has(asset.id)}
                onChange={(event) =>
                  setSelected((current) => {
                    const next = new Set(current);
                    if (event.target.checked) next.add(asset.id);
                    else next.delete(asset.id);
                    return next;
                  })
                }
              />
              <strong>{asset.name}</strong>
              <span className="asset-muted">{KIND_LABEL[asset.kind] ?? asset.kind}</span>
              <span
                className={`asset-reach is-${
                  asset.reachable === true ? "ok" : asset.reachable === false ? "bad" : "unknown"
                }`}
              >
                {asset.reachable === true
                  ? "reachable"
                  : asset.reachable === false
                    ? "unreachable"
                    : "never checked"}
              </span>
            </label>
          ))}
        </div>
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
              <ul className="asset-list asset-list-compact">
                {importSummary.created_assets.map((asset) => (
                  <li key={asset.id}>
                    <strong>{asset.name}</strong>
                    <span>{asset.kind}</span>
                    {asset.host && <span className="asset-muted">{asset.host}</span>}
                  </li>
                ))}
              </ul>
            )}
            {importSummary.duplicate_names.length > 0 && (
              <p className="asset-muted">
                Already in the inventory: {importSummary.duplicate_names.join(", ")}
              </p>
            )}
            {importSummary.rejected_rows.map((row) => (
              <p key={`${row.line}-${row.name}`} className="asset-muted">
                line {row.line} · {row.name ?? "(no name)"} — {row.reason}
              </p>
            ))}
          </div>
        )}
      </Modal>

      <CreateAssetModal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        onCreated={() => {
          setCreateOpen(false);
          queryClient.invalidateQueries({ queryKey: ["assets"] });
        }}
      />
    </>
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
      const { addService } = await import("../../shared/api/assetsService");
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
          <input value={basis} onChange={(event) => setBasis(event.target.value)} placeholder="Owned by us" />
        </label>
      </div>
    </Modal>
  );
}


