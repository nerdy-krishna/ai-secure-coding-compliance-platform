import React, { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { debugService } from "../../shared/api/debugService";
import { scanService } from "../../shared/api/scanService";
import type { Finding } from "../../shared/lib/scanContract";
import type { PatchPlanArtifact } from "../../shared/lib/scanContract";
import { CopyButton } from "../../shared/ui/CopyButton";
import { Icon } from "../../shared/ui/Icon";

type PatchRequirement = PatchPlanArtifact["files"][number]["requirements"][number];

const requirementKinds: Array<{
  label: string;
  key: string;
  values: (requirement: PatchRequirement) => string[];
}> = [
  { label: "Imports", key: "required_imports", values: (item) => item.required_imports },
  { label: "Dependencies", key: "required_dependencies", values: (item) => item.required_dependencies },
  { label: "Configuration", key: "configuration_changes", values: (item) => item.configuration_changes },
  { label: "Migrations", key: "migration_changes", values: (item) => item.migration_changes },
  { label: "Commands", key: "required_commands", values: (item) => item.required_commands },
  { label: "Manual steps", key: "manual_steps", values: (item) => item.manual_steps },
];

function candidateBadges(candidate: {
  disposition: string;
  validation_status: string;
  applicability_status: string;
  is_applied: boolean;
  resolved_range?: unknown;
}): string[] {
  const badges = ["proposed"];
  if (candidate.resolved_range) badges.push("anchor-validated");
  if (candidate.validation_status === "passed") {
    badges.push("syntax/build/test validated", "security-verified");
  }
  if (candidate.is_applied) badges.push("applied");
  if (candidate.disposition === "duplicate") badges.push("duplicate");
  if (candidate.disposition === "conflict") badges.push("conflicted");
  if (candidate.disposition === "rejected") badges.push("rejected");
  if (["validation_unavailable", "ambiguous", "conflict"].includes(candidate.applicability_status)) {
    badges.push("manual-review");
  }
  return badges;
}

export const ActionableRemediationPanel: React.FC<{
  scanId: string;
  scanType: string;
  finding: Finding;
  patchPlan?: PatchPlanArtifact | null;
}> = ({ scanId, scanType, finding, patchPlan }) => {
  const mode = scanType.toUpperCase();
  const { data: lineage } = useQuery({
    queryKey: ["actionable-fix-lineage", scanId],
    queryFn: () => debugService.getFindingLineage(scanId, [], null, 250),
    enabled: mode !== "AUDIT" && !!patchPlan,
  });
  const candidates = useMemo(
    () => (lineage?.fix_candidates ?? []).filter(
      (item) => item.canonical_finding_id === finding.canonical_finding_id,
    ),
    [finding.canonical_finding_id, lineage?.fix_candidates],
  );
  const candidateIds = new Set(candidates.map((item) => item.candidate_id));
  const files = (patchPlan?.files ?? []).filter((file) => candidateIds.size === 0
    ? file.file_path === finding.file_path
    : file.hunks.some((hunk) => hunk.candidate_ids.some((id) => candidateIds.has(id)))
      || file.requirements.some((item) => candidateIds.has(item.candidate_id)),
  );
  const plannedFileCount = files.filter((file) => file.status === "planned").length;
  const manualFileCount = files.filter((file) => file.status === "manual_review_required").length;
  const heading = files.length === 0
    ? "No actionable patch was persisted"
    : mode === "SUGGEST"
    ? plannedFileCount === 0
      ? "Manual review required · no validated patch"
      : manualFileCount > 0
        ? "Partially validated suggestion · not applied"
        : "Validated suggestion · not applied"
    : plannedFileCount === 0 && manualFileCount > 0
      ? "Remediation not applied · manual review required"
      : manualFileCount > 0
        ? "Partial remediation · review remaining files"
        : "Persisted remediation evidence";

  if (mode === "AUDIT") {
    return (
      <div className="sccap-card" data-testid="audit-guidance-only">
        <strong>Audit evidence and remediation guidance</strong>
        <div style={{ color: "var(--fg-muted)", fontSize: 12.5, marginTop: 5 }}>
          This scan did not generate, validate, or apply a source patch.
        </div>
      </div>
    );
  }
  if (!patchPlan) {
    return (
      <div className="sccap-card" data-testid="legacy-fix-evidence">
        <strong>Legacy suggestion · validation evidence unavailable</strong>
        <div style={{ color: "var(--fg-muted)", fontSize: 12.5, marginTop: 5 }}>
          No persisted patch artifact exists. Any displayed range is approximate and the source is not marked applied.
        </div>
      </div>
    );
  }

  return (
    <section className="sccap-card" data-testid="actionable-remediation" style={{ display: "grid", gap: 12 }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 8, flexWrap: "wrap" }}>
        <div>
          <strong>{heading}</strong>
          <div style={{ color: "var(--fg-muted)", fontSize: 12 }}>
            Ranges, diffs, requirements, and instructions come from patch artifact v{patchPlan.schema_version}.
          </div>
        </div>
        <div style={{ display: "flex", gap: 6 }}>
          <button className="sccap-btn sccap-btn-sm" onClick={() => scanService.downloadPatchPlan(scanId, "patch")}>
            <Icon.Download size={12} /> Patch
          </button>
          <button className="sccap-btn sccap-btn-sm" onClick={() => scanService.downloadPatchPlan(scanId, "json")}>
            <Icon.Download size={12} /> JSON
          </button>
        </div>
      </div>

      {manualFileCount > 0 && (
        <div role="alert" className="surface" style={{ padding: 10 }}>
          {manualFileCount} file{manualFileCount === 1 ? "" : "s"} remain review-only because validation failed, was unavailable, or a conflict requires operator action.
        </div>
      )}

      {candidates.map((candidate) => (
        <details key={candidate.candidate_id} open>
          <summary style={{ cursor: "pointer", fontWeight: 600 }}>
            Candidate {candidate.candidate_id.slice(0, 8)}
          </summary>
          <div style={{ display: "flex", gap: 5, flexWrap: "wrap", marginTop: 8 }}>
            {candidateBadges(candidate).map((badge) => (
              <span className="chip" key={badge} data-candidate-state={badge}>{badge}</span>
            ))}
          </div>
          <div style={{ fontSize: 12, color: "var(--fg-muted)", marginTop: 6 }}>
            {candidate.decision_reason || "No decision explanation recorded."}
          </div>
        </details>
      ))}

      {files.map((file) => (
        <div key={file.file_path} style={{ display: "grid", gap: 10 }}>
          <div><strong className="mono">{file.file_path}</strong> · {file.status}</div>
          {file.hunks.filter((h) => candidateIds.size === 0 || h.candidate_ids.some((id) => candidateIds.has(id))).map((hunk) => (
            <div key={hunk.patch_hunk_id} className="surface" style={{ padding: 10 }}>
              <div style={{ fontSize: 11, color: "var(--fg-muted)" }}>
                Exact resolved range {hunk.resolved_range.start_line}:{hunk.resolved_range.start_column}–{hunk.resolved_range.end_line}:{hunk.resolved_range.end_column}
              </div>
              <pre style={{ whiteSpace: "pre-wrap", marginBottom: 0 }}>{hunk.original_text}</pre>
              <pre style={{ whiteSpace: "pre-wrap", marginBottom: 0 }}>{hunk.replacement_text}</pre>
            </div>
          ))}
          {file.requirements.filter((r) => candidateIds.size === 0 || candidateIds.has(r.candidate_id)).map((requirement) => (
            <div key={requirement.candidate_id} style={{ display: "grid", gap: 5 }}>
              {requirementKinds.map(({ label, key, values }) => {
                const items = values(requirement);
                return items.length > 0 && (
                  <div key={key}>
                    <b>{label}:</b> {items.map((value) => <code key={value} style={{ marginLeft: 6 }}>{value}</code>)}
                  </div>
                );
              })}
            </div>
          ))}
          <details>
            <summary style={{ cursor: "pointer", fontWeight: 600 }}>Exact validation evidence</summary>
            <div style={{ display: "grid", gap: 6, marginTop: 8 }}>
              {file.validation_checks.map((check, index) => (
                <div key={`${check.stage}-${index}`} className="surface" style={{ padding: 8, fontSize: 12 }}>
                  <b>{check.status}</b> · {check.profile || check.stage} · {check.tool || "tool not recorded"} · {check.tool_version || "version not recorded"} · {check.completed_at || "timestamp not recorded"}
                  <div>{check.detail}</div>
                  {check.output && <pre style={{ whiteSpace: "pre-wrap" }}>{check.output}</pre>}
                </div>
              ))}
            </div>
          </details>
          {file.unified_diff && (
            <div>
              <div style={{ display: "flex", justifyContent: "space-between" }}>
                <strong>
                  {file.status === "planned"
                    ? "Validated apply-ready unified diff"
                    : "Review-only diff · not apply-ready"}
                </strong>
                <CopyButton
                  value={file.unified_diff}
                  title={file.status === "planned"
                    ? "Copy the validated persisted unified diff"
                    : "Copy the review-only persisted diff"}
                />
              </div>
              <pre style={{ whiteSpace: "pre-wrap", overflowX: "auto" }}>{file.unified_diff}</pre>
              {file.status === "planned"
                ? <code>git apply --check scan-{scanId}.patch &amp;&amp; git apply scan-{scanId}.patch</code>
                : <div role="alert">Do not apply automatically. Resolve the recorded conflict or failed/unavailable validation first.</div>}
            </div>
          )}
        </div>
      ))}
    </section>
  );
};
