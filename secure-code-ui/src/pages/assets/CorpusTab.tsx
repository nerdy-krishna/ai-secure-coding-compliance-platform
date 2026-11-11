// secure-code-ui/src/pages/assets/CorpusTab.tsx
//
// Page 3: the CVE corpus — what is loaded, how to load more, and how to find a CVE.
//
// The browse list is not decoration: it is how an operator picks a CVE on page 1 without
// knowing its id by heart, so the same filter box is available here.

import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { browseCves, importCorpus, listAssets } from "../../shared/api/assetsService";
import { Icon } from "../../shared/ui/Icon";
import { useToast } from "../../shared/ui/Toast";

const PAGE_SIZE = 25;

export default function CorpusTab() {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("");
  const [kevOnly, setKevOnly] = useState(false);
  const [offset, setOffset] = useState(0);

  const assetsQ = useQuery({ queryKey: ["assets"], queryFn: listAssets });
  const corpus = assetsQ.data?.corpus;
  const browseQ = useQuery({
    queryKey: ["cve", "browse", query, severity, kevOnly, offset],
    queryFn: () =>
      browseCves({
        query: query || undefined,
        severity: severity || undefined,
        kev: kevOnly,
        limit: PAGE_SIZE,
        offset,
      }),
  });
  const rows = browseQ.data?.items ?? [];
  const total = browseQ.data?.total ?? 0;

  return (
    <>
      <section className="sccap-card asset-card">
        <div className="asset-toolbar">
          <div>
            <strong>Local CVE corpus</strong>
            <span className="asset-muted">
              Offline feeds only: a verdict that depends on a live API cannot be reproduced.
              Browsing here is how you pick a CVE on the check page.
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
                    queryClient.invalidateQueries({ queryKey: ["assets"] });
                    queryClient.invalidateQueries({ queryKey: ["cve"] });
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

      <section className="sccap-card asset-card">
        <div className="asset-toolbar">
          <div>
            <strong>Browse the corpus</strong>
            <span className="asset-muted">{total} record(s) match.</span>
          </div>
        </div>

        <div className="asset-filters">
          <input
            className="asset-filter-input"
            placeholder="Search by CVE id or description"
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              setOffset(0);
            }}
          />
          <select
            value={severity}
            onChange={(event) => {
              setSeverity(event.target.value);
              setOffset(0);
            }}
          >
            <option value="">Any severity</option>
            {["critical", "high", "medium", "low"].map((level) => (
              <option key={level} value={level}>
                {level}
              </option>
            ))}
          </select>
          <label className="asset-check-inline">
            <input
              type="checkbox"
              checked={kevOnly}
              onChange={(event) => {
                setKevOnly(event.target.checked);
                setOffset(0);
              }}
            />
            known exploited only
          </label>
        </div>

        {rows.length === 0 ? (
          <p className="asset-empty">
            No CVE matches. Import an NVD or OSV feed above — the corpus starts empty.
          </p>
        ) : (
          <div className="asset-table-wrap">
            <table className="asset-table">
              <thead>
                <tr>
                  <th>CVE</th>
                  <th>Severity</th>
                  <th>CVSS</th>
                  <th>Description</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.cve_id}>
                    <td>
                      <strong>{row.cve_id}</strong>
                      {row.kev && <span className="asset-chip is-kev">KEV</span>}
                    </td>
                    <td>
                      <span className={`asset-sev is-${row.severity ?? "unknown"}`}>
                        {row.severity ?? "unrated"}
                      </span>
                    </td>
                    <td>{row.cvss_score ?? "—"}</td>
                    <td className="asset-reason">{row.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="asset-pager">
          <span className="asset-muted">
            Showing {total === 0 ? 0 : offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total}
          </span>
          <div className="asset-pager-buttons">
            <button
              className="sccap-btn sccap-btn-sm"
              disabled={offset === 0}
              onClick={() => setOffset((value) => Math.max(0, value - PAGE_SIZE))}
            >
              <Icon.ChevronD size={12} /> Previous
            </button>
            <button
              className="sccap-btn sccap-btn-sm"
              disabled={offset + PAGE_SIZE >= total}
              onClick={() => setOffset((value) => value + PAGE_SIZE)}
            >
              Next <Icon.ChevronD size={12} />
            </button>
          </div>
        </div>
      </section>
    </>
  );
}
