import React, { useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { PageHeader } from "../../shared/ui/PageHeader";
import { Icon } from "../../shared/ui/Icon";
import { useAuth } from "../../shared/hooks/useAuth";
import { Permission, hasPermission } from "../../shared/lib/permissions";
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

type TabKey = "standards" | "agents" | "prompts" | "mappings";

interface TabDef {
  key: TabKey;
  label: string;
  icon: React.ReactNode;
  /** What the operator does on this tab. */
  description: string;
  /** What must exist before this step is useful. */
  requires?: string;
  /** Admin-only tab (authoring surfaces). */
  adminOnly?: boolean;
}

const TABS: TabDef[] = [
  {
    key: "standards",
    label: "Security standards",
    icon: <Icon.BookOpen size={13} />,
    description:
      "Create the standard and upload its policies. Those policies are chunked and embedded into the cybersecurity RAG corpus — everything downstream reasons over them, so nothing else can be configured until a standard exists.",
  },
  {
    key: "agents",
    label: "Agents",
    icon: <Icon.Sparkle size={13} />,
    description:
      "Create the agents that analyse findings for a standard, and give each one the RAG query it uses to retrieve the relevant policies from the corpus.",
    requires: "a security standard with policies ingested (step 1)",
    adminOnly: true,
  },
  {
    key: "prompts",
    label: "Prompts",
    icon: <Icon.File size={13} />,
    description:
      "Write the prompt each agent sends to the model, with provider-tuned variants that fall back automatically. A prompt inherits its agent's retrieved policies.",
    requires: "at least one agent (step 2)",
    adminOnly: true,
  },
  {
    key: "mappings",
    label: "Framework mappings",
    icon: <Icon.Layers size={13} />,
    description:
      "Finally, assign those agents to the frameworks they should analyse. A scan or advisor question is routed to the agents mapped to the frameworks it references.",
    requires: "agents with prompts (steps 2 and 3)",
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
        title={only ? "Security Standards" : "Framework Configuration"}
        subtitle={
          only
            ? "The standards your scans and advisor measure against."
            : "One workflow, in order: create a security standard and upload its policies (the RAG corpus), build the agents that query those policies, write their prompts, then map the agents to the frameworks they analyse. Semgrep rules have their own page — they are deterministic detectors, not part of this pipeline."
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
        <section className="analysis-step">
          <div className="analysis-step-head">
            <span className="analysis-step-number">
              Step {tabs.findIndex((tab) => tab.key === active.key) + 1}
            </span>
            <strong>{active.label}</strong>
            {active.requires && (
              <span className="analysis-step-requires">Requires {active.requires}</span>
            )}
          </div>
          <p className="analysis-step-body">{active.description}</p>
        </section>
      )}

      <div className="analysis-tab-panel">
        {active?.key === "standards" && <CompliancePage embedded />}
        {active?.key === "mappings" && <FrameworkManagementPage embedded />}
        {active?.key === "agents" && <AgentManagementPage embedded />}
        {active?.key === "prompts" && <PromptManagementPage embedded />}
      </div>
    </div>
  );
};

export default AnalysisConfigPage;
