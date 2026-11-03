// secure-code-ui/src/pages/assets/AssetsPage.tsx
//
// Asset inventory and CVE applicability.
//
// The page exists to answer one question honestly: does this CVE affect us? So it
// never shows a bare "yes" — every verdict carries its basis (declared version,
// observed banner, or a probe that was actually run) and its confidence, and an
// unverified candidate says so.

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { PageHeader } from "../../shared/ui/PageHeader";
import { Modal } from "../../shared/ui/Modal";
import { Icon } from "../../shared/ui/Icon";
import { useToast } from "../../shared/ui/Toast";
import {
  addDependencies,
  addService,
  checkCves,
  createAsset,
  deleteAsset,
  getAsset,
  importCorpus,
  listAssets,
  listVerdicts,
  sweepInventory,
  verifyVerdict,
  type Asset,
  type AssetKind,
  type CveVerdict,
  type Verdict,
} from "../../shared/api/assetsService";
import "./assets.css";

const KIND_LABEL: Record<AssetKind, string> = {
  web_app: "Web app",
  api: "API",
  host: "Host",
  repo: "Repository",
  service: "Service",
};

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
  const [cveQuery, setCveQuery] = useState("");
  const [verify, setVerify] = useState(false);

  const assetsQ = useQuery({ queryKey: ["assets"], queryFn: listAssets });
  const assets: Asset[] = assetsQ.data?.items ?? [];
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
    mutationFn: async () => {
      const ids = splitCves(cveQuery);
      return checkCves({ cve_ids: ids.length ? ids : null, verify });
    },
    onSuccess: (result) => {
      const parts = [
        `${result.matched} candidate${result.matched === 1 ? "" : "s"}`,
        `${result.undetermined} need a test`,
        `${result.applicable} applicable`,
      ];
      if (result.verified) parts.push(`${result.verified} tested`);
      toast.success(parts.join(" · "));
      refresh();
      queryClient.invalidateQueries({ queryKey: ["assets", "verdicts"] });
    },
    onError: () => toast.error("Could not run the check"),
  });

  const sweep = useMutation({
    mutationFn: () => sweepInventory({ verify }),
    onSuccess: (result) => {
      toast.success(
        `${result.endpoints_fingerprinted} endpoint(s) refreshed · ${result.matched} candidate(s) · ` +
          `${result.applicable} applicable`,
      );
      refresh();
    },
    onError: () => toast.error("Could not sweep the inventory"),
  });

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

      {tab === "assets" && (
        <section className="sccap-card asset-card">
          <div className="asset-toolbar">
            <div>
              <strong>{assets.length} asset{assets.length === 1 ? "" : "s"}</strong>
              <span className="asset-muted">
                {corpus?.services ?? 0} endpoint(s) · {corpus?.dependencies ?? 0} package version(s)
              </span>
            </div>
            <button
              className="sccap-btn"
              disabled={sweep.isPending || assets.length === 0}
              onClick={() => sweep.mutate()}
              title="Re-fingerprint every in-scope endpoint, then apply the CVE list"
            >
              <Icon.Refresh size={13} />
              {sweep.isPending ? "Sweeping…" : "Sweep inventory"}
            </button>
          </div>

          {assets.length === 0 ? (
            <p className="asset-empty">
              No assets yet. Add the systems you are responsible for — that is what makes a
              CVE list answerable.
            </p>
          ) : (
            <div className="asset-table-wrap">
              <table className="asset-table">
                <thead>
                  <tr>
                    <th>Asset</th>
                    <th>Kind</th>
                    <th>Environment</th>
                    <th>Endpoints</th>
                    <th>Packages</th>
                    <th>Authorisation</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {assets.map((asset) => (
                    <tr
                      key={asset.id}
                      className={openAssetId === asset.id ? "is-open" : ""}
                      onClick={() => setOpenAssetId(asset.id === openAssetId ? null : asset.id)}
                    >
                      <td>
                        <strong>{asset.name}</strong>
                        {asset.owner && <span className="asset-muted">{asset.owner}</span>}
                      </td>
                      <td>{KIND_LABEL[asset.kind] ?? asset.kind}</td>
                      <td>{asset.environment ?? "—"}</td>
                      <td>{asset.services ?? 0}</td>
                      <td>{asset.dependencies ?? 0}</td>
                      <td className="asset-muted">{asset.authorization_basis ?? "—"}</td>
                      <td>
                        {!asset.in_scope && <span className="asset-chip">out of scope</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {openAssetId && detailQ.data && (
            <AssetDetailPanel
              detail={detailQ.data}
              onChanged={() => {
                queryClient.invalidateQueries({ queryKey: ["assets"] });
                queryClient.invalidateQueries({ queryKey: ["assets", openAssetId] });
              }}
              onDeleted={() => {
                setOpenAssetId(null);
                refresh();
              }}
            />
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
  };
  onChanged: () => void;
  onDeleted: () => void;
}) {
  const toast = useToast();
  const [host, setHost] = useState("");
  const [port, setPort] = useState("");
  const [product, setProduct] = useState("");
  const [version, setVersion] = useState("");
  const [packages, setPackages] = useState("");

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
        <button className="sccap-btn sccap-btn-ghost" onClick={() => remove.mutate()}>
          <Icon.X size={13} /> Remove asset
        </button>
      </div>

      <div className="asset-detail-grid">
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
