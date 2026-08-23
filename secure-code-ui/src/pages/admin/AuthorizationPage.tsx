import { useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useState } from "react";

import {
  authorizationService,
  type ActionRequest,
} from "../../shared/api/authorizationService";
import { useAuth } from "../../shared/hooks/useAuth";
import { hasPermission, Permission } from "../../shared/lib/permissions";
import { SectionHead } from "../../shared/ui/DashboardPrimitives";
import { Icon } from "../../shared/ui/Icon";
import { useToast } from "../../shared/ui/Toast";

const errorMessage = (error: unknown): string =>
  (error as { response?: { data?: { detail?: string } }; message?: string })
    ?.response?.data?.detail ||
  (error as { message?: string })?.message ||
  "Authorization request failed";

const formatDate = (value: string): string => new Date(value).toLocaleString();

const ActionRow: React.FC<{
  action: ActionRequest;
  busy: boolean;
  onDecision: (action: ActionRequest, approved: boolean) => void;
  onExecuteRelaxation: (action: ActionRequest) => void;
}> = ({ action, busy, onDecision, onExecuteRelaxation }) => (
  <tr>
    <td style={{ padding: 10 }}><code>{action.target_type}</code></td>
    <td style={{ padding: 10 }}>{action.approver_permission}</td>
    <td style={{ padding: 10 }}>{action.status}</td>
    <td style={{ padding: 10 }}>{formatDate(action.expires_at)}</td>
    <td style={{ padding: 10 }}>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        {action.can_decide && (
          <>
            <button className="sccap-btn sccap-btn-primary" disabled={busy} onClick={() => onDecision(action, true)}>
              Approve
            </button>
            <button className="sccap-btn sccap-btn-ghost" disabled={busy} onClick={() => onDecision(action, false)}>
              Reject
            </button>
          </>
        )}
        {action.is_requester && action.status === "approved" && action.target_type === "tenant_policy_change" && (
          <button className="sccap-btn sccap-btn-primary" disabled={busy} onClick={() => onExecuteRelaxation(action)}>
            Apply approved change
          </button>
        )}
      </div>
    </td>
  </tr>
);

const AuthorizationPage: React.FC = () => {
  const { user } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [busyId, setBusyId] = useState<string | null>(null);
  const canReadPolicy = hasPermission(user?.permissions, Permission.auditRead);
  const canManagePolicy = hasPermission(
    user?.permissions,
    Permission.tenantPolicyManage,
  );
  const policy = useQuery({
    queryKey: ["authorization-policy"],
    queryFn: authorizationService.getPolicy,
    enabled: canReadPolicy,
  });
  const actions = useQuery({
    queryKey: ["authorization-actions"],
    queryFn: authorizationService.listActions,
  });

  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: ["authorization-actions"] });
    await queryClient.invalidateQueries({ queryKey: ["authorization-policy"] });
  };

  const run = async (id: string, operation: () => Promise<unknown>, success: string) => {
    setBusyId(id);
    try {
      await operation();
      toast.success(success);
      await refresh();
    } catch (error) {
      toast.error(errorMessage(error));
    } finally {
      setBusyId(null);
    }
  };

  const decide = (action: ActionRequest, approved: boolean) => {
    const reason = window.prompt(
      `${approved ? "Approval" : "Rejection"} reason`,
      approved ? "Reviewed and approved" : "Rejected after review",
    );
    if (!reason?.trim()) return;
    void run(
      action.id,
      () => authorizationService.decide(action.id, approved, reason.trim()),
      approved ? "Action approved." : "Action rejected.",
    );
  };

  const mode = policy.data?.separation_of_duties_mode;
  const rows = actions.data ?? [];

  return (
    <div className="fade-in" style={{ display: "grid", gap: 20 }}>
      {canReadPolicy && (
        <section className="sccap-card">
          <SectionHead title={<><Icon.Lock size={16} /> Separation of duties</>} />
          <p style={{ color: "var(--fg-muted)", fontSize: 13 }}>
            Critical mode requires a distinct authorized second actor for scan gates,
            finding waivers, rule promotion, and other high-risk changes.
          </p>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <strong>Mode: {policy.isLoading ? "Loading…" : mode ?? "Unavailable"}</strong>
            {canManagePolicy && mode === "off" && (
              <button
                className="sccap-btn sccap-btn-primary"
                disabled={busyId !== null}
                onClick={() => void run("policy", () => authorizationService.setPolicy("critical"), "Critical separation of duties enabled.")}
              >
                Enable critical mode
              </button>
            )}
            {canManagePolicy && mode === "critical" && (
              <button
                className="sccap-btn sccap-btn-ghost"
                disabled={busyId !== null}
                onClick={() => void run("policy-request", authorizationService.requestRelaxation, "Relaxation sent for distinct approval.")}
              >
                Request relaxation
              </button>
            )}
          </div>
        </section>
      )}

      <section className="sccap-card">
        <SectionHead title={<><Icon.Check size={16} /> Action inbox</>} />
        <p style={{ color: "var(--fg-muted)", fontSize: 13 }}>
          Only requests you submitted or are currently authorized to decide appear here.
        </p>
        {actions.isLoading ? (
          <div>Loading…</div>
        ) : actions.isError ? (
          <div style={{ color: "var(--danger)" }}>{errorMessage(actions.error)}</div>
        ) : rows.length === 0 ? (
          <div style={{ color: "var(--fg-muted)" }}>No action requests.</div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr><th>Target</th><th>Required permission</th><th>Status</th><th>Expires</th><th>Actions</th></tr></thead>
              <tbody>
                {rows.map((action) => (
                  <ActionRow
                    key={action.id}
                    action={action}
                    busy={busyId === action.id}
                    onDecision={decide}
                    onExecuteRelaxation={(row) => void run(row.id, () => authorizationService.setPolicy("off", row.id), "Approved policy relaxation applied.")}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
};

export default AuthorizationPage;
