import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AxiosError } from "axios";
import React, { useState } from "react";

import { ruleSourcesService } from "../../shared/api/ruleSourcesService";
import { hasPermission, Permission } from "../../shared/lib/permissions";
import type {
  RuleFoundryCandidate,
  RuleFoundryCandidateCreate,
  RuleFoundryFixturePack,
  RuleFoundryPredicate,
} from "../../shared/types/api";
import { Modal } from "../../shared/ui/Modal";
import { useToast } from "../../shared/ui/Toast";

const EMPTY_FIXTURES: RuleFoundryFixturePack = {
  vulnerable: [], fixed: [], negative: [], performance: [], churn: [],
};

const statusColor: Record<string, string> = {
  promoted: "var(--success)", shadow: "var(--info)", approved: "var(--info)",
  rejected: "var(--error)", expired: "var(--fg-subtle)",
  review_required: "var(--warning)", ai_dataflow: "var(--fg-muted)",
};

function errorText(error: unknown): string {
  const detail = error instanceof AxiosError
    ? (error.response?.data as { detail?: unknown })?.detail
    : undefined;
  return typeof detail === "string" && detail.length <= 240
    ? detail
    : "Rule Foundry action failed.";
}

export interface RuleFoundryPanelProps {
  permissions?: readonly string[];
}

export const RuleFoundryPanel: React.FC<RuleFoundryPanelProps> = ({ permissions }) => {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [findingId, setFindingId] = useState("");
  const [predicate, setPredicate] = useState<RuleFoundryPredicate>("semantic_runtime");
  const [ruleJson, setRuleJson] = useState("");
  const [fixturesJson, setFixturesJson] = useState("");
  const canCreate = hasPermission(permissions, Permission.ruleCandidateCreate);
  const canReview = hasPermission(permissions, Permission.ruleCandidateReview);
  const canPromote = hasPermission(permissions, Permission.rulePromote);

  const candidates = useQuery({
    queryKey: ["rule-foundry", page, statusFilter],
    queryFn: () => ruleSourcesService.listFoundryCandidates(page, 12, statusFilter || undefined),
  });
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["rule-foundry"] });
  const transition = useMutation({
    mutationFn: ({ candidate, action }: {
      candidate: RuleFoundryCandidate;
      action: "shadow" | "promote" | "rollback" | "approve" | "reject";
    }) => {
      const reason = window.prompt("Audit reason (required)", `Rule Foundry ${action} review`);
      if (!reason) return Promise.reject(new Error("Action cancelled"));
      if (action === "approve" || action === "reject") {
        return ruleSourcesService.reviewFoundryCandidate(candidate.id, action === "approve", reason);
      }
      return ruleSourcesService.transitionFoundryCandidate(candidate.id, action, reason);
    },
    onSuccess: () => { toast.success("Rule Foundry state updated."); void refresh(); },
    onError: (error) => {
      if (error instanceof Error && error.message === "Action cancelled") return;
      toast.error(errorText(error));
    },
  });
  const create = useMutation({
    mutationFn: async () => {
      const staticCandidate = predicate !== "semantic_runtime";
      const payload: RuleFoundryCandidateCreate = {
        finding_id: Number(findingId),
        predicate_kind: predicate,
        bounded: staticCandidate,
        uses_project_specific_names: false,
        requires_hidden_runtime_state: !staticCandidate,
      };
      if (staticCandidate) {
        payload.proposed_rule = JSON.parse(ruleJson) as RuleFoundryCandidateCreate["proposed_rule"];
        payload.fixtures = JSON.parse(fixturesJson) as RuleFoundryFixturePack;
      }
      return ruleSourcesService.createFoundryCandidate(payload);
    },
    onSuccess: () => {
      toast.success("Candidate created."); setCreateOpen(false); setFindingId("");
      setRuleJson(""); setFixturesJson(""); void refresh();
    },
    onError: (error) => toast.error(error instanceof SyntaxError ? "Rule or fixture JSON is invalid." : errorText(error)),
  });

  return (
    <section className="sccap-card" style={{ padding: 16, display: "grid", gap: 14 }}>
      <header style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
        <div style={{ flex: 1, minWidth: 220 }}>
          <h3 style={{ margin: 0, fontSize: 15 }}>Governed AI rule foundry</h3>
          <p style={{ margin: "4px 0 0", color: "var(--fg-muted)", fontSize: 12 }}>
            Tenant-only candidates · server-measured quality · KMS-signed rollout
          </p>
        </div>
        <select className="sccap-input" aria-label="Candidate status" value={statusFilter}
          onChange={(event) => { setStatusFilter(event.target.value); setPage(1); }}>
          <option value="">All states</option><option value="pending_review">Pending review</option>
          <option value="shadow">Shadow</option><option value="promoted">Promoted</option>
          <option value="review_required">Review required</option><option value="ai_dataflow">AI/data-flow</option>
        </select>
        {canCreate && <button className="sccap-btn sccap-btn-primary sccap-btn-sm" onClick={() => setCreateOpen(true)}>New candidate</button>}
      </header>

      {candidates.isLoading ? <p>Loading candidates…</p> : candidates.isError ? (
        <p style={{ color: "var(--error)" }}>Candidate registry unavailable.</p>
      ) : candidates.data?.items.length === 0 ? (
        <p style={{ color: "var(--fg-muted)", margin: 0 }}>No candidates in this state.</p>
      ) : (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 320px), 1fr))", gap: 10 }}>
          {candidates.data?.items.map((candidate) => {
            const deployment = candidate.active_deployment;
            const unexpectedRate = deployment && deployment.eligible_files > 0
              ? (deployment.unexpected_matches / deployment.eligible_files * 100).toFixed(2)
              : "—";
            return <article key={candidate.id} style={{ border: "1px solid var(--border)", borderRadius: 10, padding: 12, display: "grid", gap: 8 }}>
              <div style={{ display: "flex", gap: 8, justifyContent: "space-between" }}>
                <strong>{candidate.registry_kind === "ai_dataflow" ? "AI/data-flow check" : `${candidate.registry_kind} candidate`}</strong>
                <span style={{ color: statusColor[candidate.status] ?? "var(--fg-muted)", fontSize: 11, fontWeight: 700 }}>{candidate.status.replace(/_/g, " ")}</span>
              </div>
              <div style={{ fontSize: 12, color: "var(--fg-muted)" }}>
                Finding {candidate.source_finding_id ?? "retained lineage"} · {candidate.cwe ?? "No CWE"} · {candidate.severity}
              </div>
              {candidate.non_representable_reason && <div style={{ fontSize: 12 }}>Static rule withheld: {candidate.non_representable_reason}</div>}
              {candidate.latest_version && <div style={{ fontSize: 11, fontFamily: "monospace" }}>v{candidate.latest_version.version} · signed {candidate.latest_version.payload_sha256.slice(0, 12)}…</div>}
              {deployment && <div style={{ fontSize: 11, color: "var(--fg-muted)" }}>
                Shadow observations: {deployment.eligible_files} eligible units (minimum 100) · {unexpectedRate}% unexpected matches · review {deployment.review_due_at ? new Date(deployment.review_due_at).toLocaleDateString() : "not scheduled"}
              </div>}
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {canReview && ["pending_review", "review_required", "rolled_back"].includes(candidate.status) && <>
                  <button className="sccap-btn sccap-btn-sm" onClick={() => transition.mutate({ candidate, action: "approve" })}>Approve & sign</button>
                  <button className="sccap-btn sccap-btn-sm" onClick={() => transition.mutate({ candidate, action: "reject" })}>Reject</button>
                </>}
                {canPromote && candidate.status === "approved" && <button className="sccap-btn sccap-btn-sm" onClick={() => transition.mutate({ candidate, action: "shadow" })}>Start shadow</button>}
                {canPromote && candidate.status === "shadow" && <button className="sccap-btn sccap-btn-primary sccap-btn-sm" disabled={(deployment?.eligible_files ?? 0) < 100} onClick={() => transition.mutate({ candidate, action: "promote" })}>Promote</button>}
                {canPromote && candidate.status === "promoted" && deployment?.prior_version_id && <button className="sccap-btn sccap-btn-danger sccap-btn-sm" onClick={() => transition.mutate({ candidate, action: "rollback" })}>Rollback</button>}
              </div>
            </article>;
          })}
        </div>
      )}
      <footer style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
        <button className="sccap-btn sccap-btn-sm" disabled={page <= 1} onClick={() => setPage((value) => value - 1)}>Previous</button>
        <span style={{ alignSelf: "center", fontSize: 12 }}>Page {page}</span>
        <button className="sccap-btn sccap-btn-sm" disabled={!candidates.data || page * candidates.data.page_size >= candidates.data.total} onClick={() => setPage((value) => value + 1)}>Next</button>
      </footer>

      <Modal open={createOpen} onClose={() => setCreateOpen(false)} title="Create governed candidate" width={720}
        footer={<><button className="sccap-btn sccap-btn-sm" onClick={() => setCreateOpen(false)}>Cancel</button><button className="sccap-btn sccap-btn-primary sccap-btn-sm" disabled={!findingId || create.isPending} onClick={() => create.mutate()}>{create.isPending ? "Creating…" : "Create"}</button></>}>
        <div style={{ display: "grid", gap: 10 }}>
          <label>Confirmed finding ID<input className="sccap-input" type="number" min={1} value={findingId} onChange={(event) => setFindingId(event.target.value)} /></label>
          <label>Predicate<select className="sccap-input" value={predicate} onChange={(event) => setPredicate(event.target.value as RuleFoundryPredicate)}>
            <option value="semantic_runtime">Semantic/runtime (retain as AI)</option><option value="ast">Bounded AST → Semgrep</option>
            <option value="taint">Source/sink taint → Semgrep</option><option value="secret_pattern">Secret pattern → Gitleaks</option>
            <option value="dependency_advisory">Dependency advisory → OSV</option>
          </select></label>
          {predicate !== "semantic_runtime" && <>
            <label>Tool-native rule JSON<textarea className="sccap-input" rows={7} value={ruleJson} onChange={(event) => setRuleJson(event.target.value)} /></label>
            <label>Fixture pack JSON<textarea className="sccap-input" rows={7} placeholder={JSON.stringify(EMPTY_FIXTURES)} value={fixturesJson} onChange={(event) => setFixturesJson(event.target.value)} /></label>
          </>}
        </div>
      </Modal>
    </section>
  );
};
