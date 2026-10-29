// secure-code-ui/src/features/semgrep/SemgrepReadinessBanner.tsx
//
// Dashboard-level readiness gate for Semgrep rule ingestion.
//
// Semgrep runs exclusively on rules ingested from the public rule sources
// (Admin → Frameworks → Semgrep Rules). On a fresh deployment nothing is
// enabled yet, so a scan completes "successfully" with zero findings — which
// reads as a broken scanner. This banner surfaces that before the operator
// starts their first scan and links straight to the sync page.
//
// Admin-only: the underlying `/admin/rule-sources/` endpoint is superuser-gated,
// and only a superuser can enable/sync sources.

import React from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { ruleSourcesService } from "../../shared/api/ruleSourcesService";
import { useAuth } from "../../shared/hooks/useAuth";
import type { RuleSourceRead } from "../../shared/types/api";
import { Icon } from "../../shared/ui/Icon";

const SEMGREP_RULES_PATH = "/admin/frameworks?tab=semgrep";

const SemgrepReadinessBanner: React.FC = () => {
  const { user } = useAuth();
  const isAdmin = Boolean(user?.is_superuser);

  const { data: sources } = useQuery<RuleSourceRead[]>({
    queryKey: ["rule-sources"],
    queryFn: ruleSourcesService.listSources,
    enabled: isAdmin,
    // Reads are cheap and the banner must clear as soon as a sync finishes.
    staleTime: 30_000,
  });

  if (!isAdmin || !sources) return null;

  const enabled = sources.filter((s) => s.enabled);
  const totalRules = enabled.reduce((sum, s) => sum + s.rule_count, 0);
  const failed = enabled.filter((s) => s.last_sync_status === "failed");
  const never = enabled.filter((s) => s.last_sync_status === "never");
  const nothingSynced = totalRules === 0;

  // Healthy: at least one enabled source with rules and nothing failing.
  if (nothingSynced === false && failed.length === 0 && never.length === 0) {
    return null;
  }

  const tone = nothingSynced ? "var(--critical)" : "var(--warning)";
  const toneWeak = nothingSynced ? "var(--critical-weak)" : "rgba(245,158,66,0.12)";

  const headline = nothingSynced
    ? "Semgrep has no enabled rules yet — scans will complete with zero findings"
    : failed.length > 0
      ? `${failed.length} Semgrep rule source${failed.length === 1 ? "" : "s"} failed to sync`
      : `${never.length} Semgrep rule source${never.length === 1 ? "" : "s"} never synced`;

  const detail = nothingSynced
    ? sources.length === 0
      ? "No rule sources are installed. Load the built-in sources, enable at least one, then sync."
      : "Load the built-in sources, enable the ones you want, and sync before starting a scan."
    : `${failed.length + never.length} of ${enabled.length} enabled source(s) need attention · ${totalRules.toLocaleString()} rules currently available.`;

  const problemNames = [...failed, ...never]
    .slice(0, 4)
    .map((s) => s.display_name);

  return (
    <div
      className="sccap-card"
      role="status"
      data-testid="semgrep-readiness-banner"
      style={{
        display: "grid",
        gap: 10,
        padding: 16,
        marginBottom: 20,
        borderColor: tone,
        background: toneWeak,
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          fontSize: 14,
          fontWeight: 600,
          color: tone,
        }}
      >
        <Icon.Shield size={15} />
        {headline}
      </div>
      <div style={{ fontSize: 13, color: "var(--fg-muted)", lineHeight: 1.55 }}>
        {detail}
        {problemNames.length > 0 && (
          <>
            {" "}
            Failed or pending: <b>{problemNames.join(", ")}</b>
            {failed.length + never.length > problemNames.length ? " …" : ""}.
          </>
        )}
      </div>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        <Link className="sccap-btn sccap-btn-primary" to={SEMGREP_RULES_PATH}>
          <Icon.Settings size={14} /> Open Semgrep rules
        </Link>
        <Link className="sccap-btn" to="/admin/frameworks?tab=semgrep">
          <Icon.Refresh size={14} /> Load built-in sources &amp; sync
        </Link>
      </div>
    </div>
  );
};

export default SemgrepReadinessBanner;
