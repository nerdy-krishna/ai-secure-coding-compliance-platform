import React, { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { findingGovernanceService } from "../../shared/api/findingGovernanceService";
import type { FindingGovernanceItem } from "../../shared/lib/scanContract";

export const FindingGovernancePanel: React.FC<{
  scanId: string;
  findingId: number;
  initial?: FindingGovernanceItem;
}> = ({ scanId, findingId, initial }) => {
  const queryClient = useQueryClient();
  const [reason, setReason] = useState("");
  const [scope, setScope] = useState<"finding" | "fingerprint" | "project">("finding");
  const [expiresAt, setExpiresAt] = useState(() => {
    const value = new Date(Date.now() + 24 * 60 * 60 * 1000);
    return value.toISOString().slice(0, 16);
  });
  const [error, setError] = useState("");
  const { data } = useQuery({
    queryKey: ["finding-governance-detail", scanId],
    queryFn: () => findingGovernanceService.getScan(scanId),
  });
  const item = data?.items.find((row) => row.finding_id === findingId) ?? initial;
  const waivers = useMemo(
    () => (data?.active_waivers ?? []).filter(
      (waiver) => waiver.finding_id === findingId || waiver.fingerprint === item?.fingerprint,
    ),
    [data?.active_waivers, findingId, item?.fingerprint],
  );
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["finding-governance-detail", scanId] });
  const grant = useMutation({
    mutationFn: () => findingGovernanceService.grantWaiver(scanId, findingId, {
      scope,
      reason: reason.trim(),
      expires_at: new Date(expiresAt).toISOString(),
    }),
    onSuccess: () => { setError(""); setReason(""); refresh(); },
    onError: (value) => setError(value instanceof Error ? value.message : "Waiver could not be granted."),
  });
  const revoke = useMutation({
    mutationFn: (waiverId: string) => findingGovernanceService.revokeWaiver(
      waiverId,
      reason.trim() || "Revoked from finding results.",
    ),
    onSuccess: () => { setError(""); refresh(); },
    onError: (value) => setError(value instanceof Error ? value.message : "Waiver could not be revoked."),
  });

  if (!item) return null;
  return (
    <details className="sccap-card" data-testid="finding-governance-detail" open>
      <summary style={{ cursor: "pointer", fontWeight: 700 }}>Evidence · {item.baseline_state}</summary>
      <div style={{ display: "grid", gap: 6, marginTop: 10, fontSize: 12 }}>
        <div><b>Fingerprint:</b> <code>{item.fingerprint}</code></div>
        <div><b>Attempt:</b> <code>{item.attempt_id || "legacy / unavailable"}</code></div>
        <div><b>Predecessor finding:</b> {item.predecessor_finding_id ?? "none"}</div>
        <div><b>Lineage record:</b> <code>{item.id || "legacy / unavailable"}</code></div>
        <div><b>Evidence object IDs:</b> {item.evidence_object_ids.length ? item.evidence_object_ids.map((id) => <code key={id} style={{ marginRight: 5 }}>{id}</code>) : "none retained"}</div>
        <div><b>Coverage entry IDs:</b> {item.coverage_entry_ids.length ? item.coverage_entry_ids.map((id) => <code key={id} style={{ marginRight: 5 }}>{id}</code>) : "none"}</div>
        <div><b>Dataflow:</b> <code>{Object.keys(item.dataflow).length ? JSON.stringify(item.dataflow) : "none recorded"}</code></div>
        <div><b>Exact ranges:</b> {item.exact_ranges.map((range, index) => <code key={index} style={{ marginRight: 5 }}>{String(range.file_path ?? "file")}:{String(range.start_line ?? "?")}–{String(range.end_line ?? "?")}</code>)}</div>
      </div>
      <div style={{ borderTop: "1px solid var(--border)", marginTop: 10, paddingTop: 10, display: "grid", gap: 6 }}>
        <strong style={{ fontSize: 12 }}>Policy waiver</strong>
        {waivers.map((waiver) => (
          <div key={waiver.id} style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 12 }}>
            <span>{waiver.scope} · expires {new Date(waiver.expires_at).toLocaleString()}</span>
            <button className="sccap-btn sccap-btn-sm" disabled={revoke.isPending} onClick={() => revoke.mutate(waiver.id)}>Revoke</button>
          </div>
        ))}
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          <select value={scope} onChange={(event) => setScope(event.target.value as typeof scope)} aria-label="Waiver scope">
            <option value="finding">Finding</option><option value="fingerprint">Fingerprint</option><option value="project">Project</option>
          </select>
          <input value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Waiver reason" aria-label="Waiver reason" />
          <input type="datetime-local" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} aria-label="Waiver expiry" />
          <button className="sccap-btn sccap-btn-sm" disabled={grant.isPending || reason.trim().length < 3} onClick={() => grant.mutate()}>Grant waiver</button>
        </div>
        {error && <div role="alert" style={{ color: "var(--critical)", fontSize: 12 }}>{error}</div>}
      </div>
    </details>
  );
};
