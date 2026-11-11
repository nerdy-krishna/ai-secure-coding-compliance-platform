// secure-code-ui/src/pages/assets/AssetsPage.tsx
//
// The inventory, in three pages:
//
//   1. CVE check — pick CVEs and assets, read the research, then test.
//   2. Assets    — the inventory itself: add, import, edit, scan.
//   3. Corpus    — the offline CVE feeds and a searchable browser.
//
// The activity console and the probe state sit above the tabs because both pages need
// them: a scan started on either page reports there, and the stop control applies to both.

import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { PageHeader } from "../../shared/ui/PageHeader";
import { useToast } from "../../shared/ui/Toast";
import TerminalConsole, { type ConsoleLine } from "../../shared/ui/TerminalConsole";
import {
  cancelProbe,
  clearAssetEvents,
  getProbeStatus,
  listAssetEvents,
} from "../../shared/api/assetsService";
import AssetsTab from "./AssetsTab";
import CorpusTab from "./CorpusTab";
import CveCheckTab from "./CveCheckTab";
import "./assets.css";

type Tab = "check" | "assets" | "corpus";

export default function AssetsPage() {
  const toast = useToast();
  const [tab, setTab] = useState<Tab>("check");
  const [verify, setVerify] = useState(true);
  const [events, setEvents] = useState<ConsoleLine[]>([]);
  const [lastEventId, setLastEventId] = useState(0);
  const [busy, setBusy] = useState(false);
  const [busySince, setBusySince] = useState<string | null>(null);

  const statusQ = useQuery({
    queryKey: ["assets", "probe-status"],
    queryFn: getProbeStatus,
    refetchInterval: (query) => (query.state.data?.active ? 3000 : 15000),
  });
  const probeStatus = statusQ.data;
  const active = Boolean(probeStatus?.active) || busy;

  const eventsQ = useQuery({
    queryKey: ["assets", "events", lastEventId],
    queryFn: () => listAssetEvents(lastEventId),
    refetchInterval: active ? 1200 : 6000,
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

  const beginWork = () => {
    setBusy(true);
    setBusySince(new Date().toISOString());
    window.setTimeout(() => setBusy(false), 1500);
  };

  return (
    <div className="c13-page assets-page fade-in">
      <PageHeader
        crumbs={[{ label: "Dashboard", to: "/account/dashboard" }, { label: "Asset inventory" }]}
        title="Asset inventory"
        subtitle="What you own, what it runs, and which CVEs actually affect it. Adding an asset authorises testing its recorded hosts."
        actions={
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            {active && (
              <span className="asset-running">
                <span className="asset-pulse" />
                {probeStatus?.running
                  ? `scanning ${probeStatus.host ?? "assets"}`
                  : "working"}
                {probeStatus?.queued ? ` · ${probeStatus.queued} queued` : ""}
              </span>
            )}
            {active && (
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
                Stop probe
              </button>
            )}
          </div>
        }
      />

      <section className="sccap-card asset-card">
        <TerminalConsole
          title="inventory activity"
          lines={
            active && busySince
              ? [
                  ...events,
                  {
                    id: "live",
                    at: busySince,
                    level: "info",
                    kind: "running",
                    message: "working — progress appears below as each step finishes",
                    status: "running",
                    startedAt: busySince,
                  },
                ]
              : events
          }
          live={active}
          emptyHint="Run a CVE check or an asset scan: probing, reachability, fingerprints, CVE lookups, matches and tests appear here as they happen."
          downloadName="inventory-activity"
          maxHeight={260}
          onClear={async () => {
            // Hides the log from the view and records where it was hidden, so a reload does
            // not bring it back. The events stay in the database.
            setEvents([]);
            try {
              await clearAssetEvents();
              setLastEventId(0);
            } catch {
              toast.error("Could not clear the activity view");
            }
          }}
        />
      </section>

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

      {tab === "check" && <CveCheckTab verify={verify} onTesting={beginWork} />}
      {tab === "assets" && <AssetsTab probeActive={active} />}
      {tab === "corpus" && <CorpusTab />}
    </div>
  );
}
