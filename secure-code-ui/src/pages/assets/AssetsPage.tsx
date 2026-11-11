// secure-code-ui/src/pages/assets/AssetsPage.tsx
//
// The inventory, in three pages:
//
//   1. CVE check — pick CVEs and assets, read the research, then test.
//   2. Assets    — the inventory itself: add, import, edit, scan.
//   3. Corpus    — the offline CVE feeds and a searchable browser.
//
// Each page owns its activity window. A single console shared by all three replayed the
// history of every earlier scan and showed work started on a page you were not looking at;
// the window now belongs to the scan you started, and says what that scan is doing.

import { useState } from "react";
import { PageHeader } from "../../shared/ui/PageHeader";
import AssetsTab from "./AssetsTab";
import CorpusTab from "./CorpusTab";
import CveCheckTab from "./CveCheckTab";
import "./assets.css";

type Tab = "check" | "assets" | "corpus";

export default function AssetsPage() {
  const [tab, setTab] = useState<Tab>("check");
  const [verify, setVerify] = useState(true);

  return (
    <div className="c13-page assets-page fade-in">
      <PageHeader
        crumbs={[{ label: "Dashboard", to: "/account/dashboard" }, { label: "Asset inventory" }]}
        title="Asset inventory"
        subtitle="What you own, what it runs, and which CVEs actually affect it. Adding an asset authorises testing its recorded hosts."
      />

      <div className="asset-tabs" role="tablist">
        {(
          [
            ["check", "1 · CVE check"],
            ["assets", "2 · Assets"],
            ["corpus", "3 · CVE corpus"],
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
        {tab === "check" && (
          <label className="asset-check-inline" style={{ marginLeft: "auto" }}>
            <input
              type="checkbox"
              checked={verify}
              onChange={(event) => setVerify(event.target.checked)}
            />
            test the uncertain candidates
          </label>
        )}
      </div>

      {tab === "check" && <CveCheckTab verify={verify} />}
      {tab === "assets" && <AssetsTab />}
      {tab === "corpus" && <CorpusTab />}
    </div>
  );
}
