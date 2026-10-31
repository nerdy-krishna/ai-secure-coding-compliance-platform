import React, { useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { PageHeader } from "../../shared/ui/PageHeader";
import { Icon } from "../../shared/ui/Icon";
import { useAuth } from "../../shared/hooks/useAuth";
import { Permission, hasPermission } from "../../shared/lib/permissions";
import SemgrepRulesTab from "../../features/semgrep/SemgrepRulesTab";
import CompliancePage from "../compliance/CompliancePage";
import FrameworkManagementPage from "./FrameworkManagementPage";
import AgentManagementPage from "./AgentManagementPage";
import PromptManagementPage from "./PromptManagementPage";

/**
 * The analysis configuration surface.
 *
 * Standards feed rules, rules feed framework mappings, mappings pick the agents,
 * and the agents run prompts — so these five screens are one workflow presented as
 * ordered tabs instead of five unrelated menu items. Each tab keeps its own content
 * component; `embedded` tells those pages to drop their own title, so the tab
 * header is the only heading on screen.
 */

type TabKey = "standards" | "semgrep" | "mappings" | "agents" | "prompts";

interface TabDef {
  key: TabKey;
  label: string;
  icon: React.ReactNode;
  description: string;
  /** Admin-only tab (authoring surfaces). */
  adminOnly?: boolean;
}

const TABS: TabDef[] = [
  {
    key: "standards",
    label: "Security standards",
    icon: <Icon.BookOpen size={13} />,
    description:
      "The knowledge corpus: which standards are ingested, how many documents back each one, and the posture each is reporting.",
  },
  {
    key: "semgrep",
    label: "Semgrep rules",
    icon: <Icon.Code size={13} />,
    description:
      "Deterministic detection sources. Scans run only the rules ingested here — no bundled pack.",
    adminOnly: true,
  },
  {
    key: "mappings",
    label: "Framework mappings",
    icon: <Icon.Layers size={13} />,
    description:
      "Framework records and which agents analyse findings against each one.",
    adminOnly: true,
  },
  {
    key: "agents",
    label: "Agents",
    icon: <Icon.Sparkle size={13} />,
    description:
      "Specialised analysis agents and the retrieval query each sends to the corpus.",
    adminOnly: true,
  },
  {
    key: "prompts",
    label: "Prompts",
    icon: <Icon.File size={13} />,
    description:
      "Per-agent prompt templates, with provider-tuned variants and automatic fallback.",
    adminOnly: true,
  },
];

const AnalysisConfigPage: React.FC<{ only?: TabKey }> = ({ only }) => {
  const { user } = useAuth();
  const isAdmin = hasPermission(user?.permissions, Permission.platformConfigManage);
  const [params, setParams] = useSearchParams();

  const tabs = useMemo(
    () => TABS.filter((tab) => (!only || tab.key === only) && (!tab.adminOnly || isAdmin)),
    [only, isAdmin],
  );

  const requested = params.get("tab") as TabKey | null;
  const active = tabs.find((tab) => tab.key === requested) ?? tabs[0];

  const select = (key: TabKey) => {
    const next = new URLSearchParams(params);
    next.set("tab", key);
    setParams(next, { replace: true });
  };

  return (
    <div className="c13-page analysis-config fade-in">
      <PageHeader
        crumbs={[
          { label: "Dashboard", to: "/account/dashboard" },
          ...(only ? [{ label: "Analysis config" }] : [{ label: "Administration", to: "/admin/system" }, { label: "Analysis config" }]),
        ]}
        title={only ? "Security standards" : "Analysis configuration"}
        subtitle={
          only
            ? "The standards your scans and advisor measure against."
            : "One pipeline, in order: standards supply the knowledge, rules supply the detectors, mappings bind them to frameworks, agents run the analysis, prompts shape the output."
        }
      />

      {!only && (
        <nav className="analysis-tabs" aria-label="Analysis configuration sections">
          {tabs.map((tab, index) => (
            <button
              key={tab.key}
              type="button"
              className={`analysis-tab${active?.key === tab.key ? " is-active" : ""}`}
              aria-current={active?.key === tab.key ? "page" : undefined}
              onClick={() => select(tab.key)}
            >
              <span className="analysis-tab-step">{index + 1}</span>
              {tab.icon}
              <span className="analysis-tab-label">{tab.label}</span>
            </button>
          ))}
        </nav>
      )}

      {active && (
        <p className="analysis-tab-description">{active.description}</p>
      )}

      <div className="analysis-tab-panel">
        {active?.key === "standards" && <CompliancePage embedded />}
        {active?.key === "semgrep" && <SemgrepRulesTab />}
        {active?.key === "mappings" && <FrameworkManagementPage embedded />}
        {active?.key === "agents" && <AgentManagementPage embedded />}
        {active?.key === "prompts" && <PromptManagementPage embedded />}
      </div>
    </div>
  );
};

export default AnalysisConfigPage;
