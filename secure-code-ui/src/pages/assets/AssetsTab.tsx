// secure-code-ui/src/pages/assets/AssetsTab.tsx
//
// Page 2: the inventory itself.
//
// Every row says when it was last scanned and whether it answered, because "0 services found"
// means something different on a host that never responded.
//
// The scan controls and the activity window sit at the top, and a scan starts where it is
// pressed: selecting rows and pressing "Scan selected" scans those rows. There is no dialog
// between the button and the work — that dialog was the thing that made a selection look
// ignored.

import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  assetsTemplateUrl,
  cancelProbe,
  checkReachability,
  createAsset,
  getAsset,
  getProbeStatus,
  importAssets,
  listAssets,
  probeInventory,
  type Asset,
  type AssetImportSummary,
  type AssetKind,
} from "../../shared/api/assetsService";
import { Icon } from "../../shared/ui/Icon";
import { Modal } from "../../shared/ui/Modal";
import TerminalConsole from "../../shared/ui/TerminalConsole";
import { useToast } from "../../shared/ui/Toast";
import CollapsibleCard from "../../shared/ui/CollapsibleCard";
import AssetDetailPanel from "./AssetDetailPanel";
import {
  AssetFiltersBar,
  AssetStatus,
  EMPTY_FILTERS,
  applyFilters,
  when,
  type AssetFilters,
} from "./AssetTableWindow";
import useScanActivity from "./useScanActivity";

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

export default function AssetsTab() {
  const toast = useToast();
  const queryClient = useQueryClient();
  const activity = useScanActivity();

  const [filters, setFilters] = useState<AssetFilters>(EMPTY_FILTERS);
  const [pageSize, setPageSize] = useState(20);
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [openId, setOpenId] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [importSummary, setImportSummary] = useState<AssetImportSummary | null>(null);
  const [importing, setImporting] = useState(false);
  // Which kind of work is running: only an engine scan is watched by probe status, so a
  // reachability check must not be declared "complete" while it is still going.
  const engineScan = useRef(false);

  const assetsQ = useQuery({ queryKey: ["assets"], queryFn: listAssets });
  const assets: Asset[] = assetsQ.data?.items ?? [];
  const detailQ = useQuery({
    queryKey: ["assets", openId],
    queryFn: () => getAsset(openId as string),
    enabled: Boolean(openId),
  });

  const filtered = useMemo(() => applyFilters(assets, filters), [assets, filters]);
  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const visible = filtered.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  // The engine reports the truth about whether anything is still running.
  const statusQ = useQuery({
    queryKey: ["assets", "probe-status"],
    queryFn: getProbeStatus,
    refetchInterval: activity.phase === "running" ? 2500 : 20000,
  });
  const probing = Boolean(statusQ.data?.active);

  // A scan that started is finished when the engine says nothing is active any more.
  // Depend on the phase, not on the hook object: that object is new every render, so an
  // effect keyed on it would clear its own timer forever and the badge would stay "running".
  const { phase: activityPhase, hasRun, finish: finishActivity } = activity;
  useEffect(() => {
    if (activityPhase !== "running" || !hasRun || !engineScan.current || probing) return undefined;
    const timer = window.setTimeout(() => {
      finishActivity("completed", "Scan complete");
      queryClient.invalidateQueries({ queryKey: ["assets"] });
    }, 2500);
    return () => window.clearTimeout(timer);
  }, [activityPhase, hasRun, probing, finishActivity, queryClient]);

  const probe = useMutation({
    mutationFn: (assetIds: string[] | null) =>
      probeInventory({ asset_ids: assetIds, rescan: true, tools: ["nmap", "whatweb"] }),
    onSuccess: (result) => {
      toast.success(
        result.queued
          ? `Queued ${result.queued} asset(s) for the pentest engine`
          : `${result.fingerprints_found} fingerprint(s) from ${result.endpoints_probed} endpoint(s)`,
      );
      statusQ.refetch();
      queryClient.invalidateQueries({ queryKey: ["assets"] });
    },
    onError: () => {
      activity.finish("error", "Scan failed");
      toast.error("Could not start the scan");
    },
  });

  const reach = useMutation({
    mutationFn: (assetIds: string[] | null) => checkReachability(assetIds),
    onSuccess: (result) => {
      activity.finish("completed", "Reachability checked");
      toast.success(`${result.up} up · ${result.filtered} filtered · ${result.down} down`);
      queryClient.invalidateQueries({ queryKey: ["assets"] });
    },
    onError: () => {
      activity.finish("error", "Reachability check failed");
      toast.error("Could not check reachability");
    },
  });

  const startScan = async (assetIds: string[] | null, count: number) => {
    engineScan.current = true;
    await activity.start(`Scanning ${count} asset(s)`);
    probe.mutate(assetIds);
  };

  const startReachability = async () => {
    engineScan.current = false;
    await activity.start(`Checking reachability of ${selected.size || assets.length} asset(s)`);
    reach.mutate(selected.size ? [...selected] : null);
  };

  const busy = activity.phase === "running" || probing;

  return (
    <>
      <CollapsibleCard
        title={`${assets.length} asset${assets.length === 1 ? "" : "s"}`}
        subtitle={assets.length ? `${assets.filter((a) => a.reachable !== null).length} checked` : undefined}
        storageKey="inventory-actions"
        className="asset-card"
      >
        <div className="asset-toolbar">
          <div>
            <strong>
              Scan, import and check reachability
            </strong>
            <span className="asset-muted">
              {assets.filter((a) => a.reachable === true).length} reachable ·{" "}
              {
                assets.filter(
                  (a) => a.reachable === false && a.unreachable_reason === "filtered",
                ).length
              }{" "}
              filtered ·{" "}
              {
                assets.filter(
                  (a) => a.reachable === false && a.unreachable_reason !== "filtered",
                ).length
              }{" "}
              unreachable · {assets.filter((a) => a.reachable == null).length} not checked
            </span>
          </div>
        </div>

        <TerminalConsole
          title="asset scan"
          order="newest-first"
          lines={activity.lines}
          phase={{ phase: activity.phase, label: activity.label, detail: `${activity.elapsed}s` }}
          live={busy}
          maxHeight={300}
          emptyHint="Press Scan: reachability, fingerprints, CVE lookups and matches appear here, newest first."
          downloadName="asset-scan"
          onClear={activity.clear}
          actions={
            <>
              <button
                className="is-primary"
                disabled={!assets.length || busy}
                onClick={() => void startScan(selected.size ? [...selected] : null, selected.size || assets.length)}
              >
                <Icon.Play size={11} /> Scan {selected.size ? `selected (${selected.size})` : `all (${assets.length})`}
              </button>
              <button
                disabled={!assets.length || busy}
                title="Climb the reachability ladder only — no fingerprinting"
                onClick={() => void startReachability()}
              >
                <Icon.Search size={11} /> Reachability
              </button>
              <button
                className="is-danger"
                disabled={!busy}
                onClick={async () => {
                  activity.finish("cancelled", "Cancelled by operator");
                  try {
                    const result = await cancelProbe();
                    toast.info(
                      `Stopped: ${result.cancelled} cancelled, ${result.stopping} stopping`,
                    );
                    statusQ.refetch();
                  } catch {
                    toast.error("Could not stop the scan");
                  }
                }}
              >
                <Icon.X size={11} /> Stop
              </button>
              <button onClick={activity.clear}>Clear</button>
            </>
          }
        />

        <div className="asset-inline-form" style={{ marginTop: 10 }}>
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
          <span className="asset-muted" style={{ marginLeft: "auto" }}>
            {selected.size ? `${selected.size} selected` : "select rows to scan a subset"}
          </span>
        </div>
      </CollapsibleCard>

      <CollapsibleCard
        title="Inventory"
        subtitle={filtered.length ? `${filtered.length} shown` : undefined}
        storageKey="inventory-table"
        className="asset-card"
      >
        <AssetFiltersBar
          assets={assets}
          filters={filters}
          onChange={(next) => {
            setFilters(next);
            setPage(1);
          }}
          count={filtered.length}
        />

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
                    <th style={{ width: 34 }}>
                      <input
                        type="checkbox"
                        checked={visible.length > 0 && visible.every((a) => selected.has(a.id))}
                        title="Select this page"
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
                      />
                    </th>
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
                          {(asset.technology_names ?? []).length
                            ? (asset.technology_names ?? []).slice(0, 3).join(", ")
                            : "—"}
                        </td>
                        <td title={asset.last_probe_at ?? "never scanned"}>
                          {when(asset.last_probe_at)}
                        </td>
                        <td>
                          <AssetStatus asset={asset} />
                        </td>
                      </tr>
                      {openId === asset.id && (
                        <tr key={`${asset.id}-detail`} className="asset-row-detail">
                          <td colSpan={8}>
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
                Showing {(currentPage - 1) * pageSize + 1}–
                {Math.min(currentPage * pageSize, filtered.length)} of {filtered.length}
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
      </CollapsibleCard>

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
