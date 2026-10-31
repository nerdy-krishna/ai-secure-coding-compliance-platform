import React from "react";
import { Link } from "react-router-dom";
import { PageHeader } from "../../shared/ui/PageHeader";
import SemgrepRulesTab from "../../features/semgrep/SemgrepRulesTab";

/**
 * Semgrep rule sources.
 *
 * Deliberately its own page: rule sources are deterministic detectors that decide
 * *what* a scan can find, independent of the standard → policies → agents → prompts
 * → framework-mapping pipeline that decides how findings are interpreted.
 */
const SemgrepRulesPage: React.FC = () => (
  <div className="c13-page fade-in">
    <PageHeader
      crumbs={[
        { label: "Dashboard", to: "/account/dashboard" },
        { label: "Administration", to: "/admin/system" },
        { label: "Semgrep rules" },
      ]}
      title="Semgrep rules"
      subtitle="The deterministic detectors scans run. A scan executes only the rules ingested here — there is no bundled fallback pack, and a language with no enabled source produces no findings."
    />
    <section className="analysis-step">
      <div className="analysis-step-head">
        <strong>Before your first scan</strong>
        <span className="analysis-step-requires">not part of the analysis pipeline</span>
      </div>
      <p className="analysis-step-body">
        Enable the sources that cover the languages you scan and sync them. Each source
        pulls a rule set from a git repository; the rule count and last sync status tell
        you whether coverage is current. Rules feed findings, while security standards,
        agents and prompts interpret them — configure those under{" "}
        <Link to="/admin/analysis">Analysis configuration</Link>.
      </p>
    </section>
    <SemgrepRulesTab />
  </div>
);

export default SemgrepRulesPage;
