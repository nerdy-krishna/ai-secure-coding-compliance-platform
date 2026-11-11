// secure-code-ui/src/pages/assets/AssetDetailPanel.tsx
//
// The expanded row: what the asset runs, the endpoints it serves, the packages it declares,
// and an inline edit form. Moved out of the page so the tab that shows it stays readable.

import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import {
  addDependencies,
  addService,
  addTechnology,
  deleteAsset,
  updateAsset,
} from "../../shared/api/assetsService";
import { Icon } from "../../shared/ui/Icon";
import { useToast } from "../../shared/ui/Toast";

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

export default AssetDetailPanel;
