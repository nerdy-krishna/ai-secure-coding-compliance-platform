import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useMemo, useState } from "react";

import { useAuth } from "../../shared/hooks/useAuth";
import { hasPermission, Permission } from "../../shared/lib/permissions";
import {
  type BudgetPolicyPayload,
  type UsageCostStatus,
  type UsageDimension,
  type UsageFilters,
  usageService,
} from "../../shared/api/usageService";
import { MetricCard } from "../../shared/ui/DashboardPrimitives";
import { PageHeader } from "../../shared/ui/PageHeader";

const money = (value: string | null, currency = "USD") =>
  value === null
    ? "Unknown"
    : new Intl.NumberFormat(undefined, {
        style: "currency",
        currency,
        minimumFractionDigits: 2,
        maximumFractionDigits: 6,
      }).format(Number(value));

const integer = (value: number) => new Intl.NumberFormat().format(value);

function initialDates() {
  const end = new Date();
  const start = new Date(end);
  start.setUTCDate(start.getUTCDate() - 30);
  return {
    from: start.toISOString().slice(0, 10),
    to: end.toISOString().slice(0, 10),
  };
}

const statusColor = new Map<string, string>([
  ["exact", "var(--success)"],
  ["reconciled", "var(--info)"],
  ["estimated", "var(--high)"],
  ["unknown", "var(--critical)"],
  ["normal", "var(--success)"],
  ["warning", "var(--high)"],
  ["critical", "var(--critical)"],
  ["exhausted", "var(--critical)"],
]);

const StatusChip: React.FC<{ value: string }> = ({ value }) => (
  <span
    style={{
      display: "inline-flex",
      alignItems: "center",
      border: `1px solid color-mix(in oklch, ${statusColor.get(value) ?? "var(--border)"} 45%, var(--border))`,
      color: statusColor.get(value) ?? "var(--fg-muted)",
      borderRadius: 999,
      padding: "2px 7px",
      fontSize: 11,
      fontWeight: 600,
      textTransform: "capitalize",
    }}
  >
    {value}
  </span>
);

const inputStyle: React.CSSProperties = {
  background: "var(--bg-elev)",
  color: "var(--fg)",
  border: "1px solid var(--border)",
  borderRadius: 8,
  padding: "8px 10px",
  minHeight: 36,
};

export const UsagePage: React.FC = () => {
  const dates = useMemo(initialDates, []);
  const [from, setFrom] = useState(dates.from);
  const [to, setTo] = useState(dates.to);
  const [operation, setOperation] = useState<"" | "scan" | "chat" | "rag">("");
  const [costStatus, setCostStatus] = useState<"" | UsageCostStatus>("");
  const [dimension, setDimension] = useState<UsageDimension>("operation");
  const [breakdownPage, setBreakdownPage] = useState(1);
  const [eventCursor, setEventCursor] = useState<string | undefined>();
  const [cursorHistory, setCursorHistory] = useState<Array<string | undefined>>([]);
  const filters: UsageFilters = useMemo(
    () => ({
      from_at: new Date(`${from}T00:00:00Z`).toISOString(),
      to_at: new Date(`${to}T23:59:59.999Z`).toISOString(),
      operation_kind: operation || undefined,
      cost_status: costStatus || undefined,
    }),
    [costStatus, from, operation, to],
  );

  const summary = useQuery({
    queryKey: ["usage", "summary", filters],
    queryFn: () => usageService.summary(filters),
  });
  const trends = useQuery({
    queryKey: ["usage", "trends", filters],
    queryFn: () => usageService.trends(filters),
  });
  const breakdown = useQuery({
    queryKey: ["usage", "breakdown", filters, dimension, breakdownPage],
    queryFn: () => usageService.breakdown(filters, dimension, breakdownPage),
  });
  const events = useQuery({
    queryKey: ["usage", "events", filters, eventCursor],
    queryFn: () => usageService.events(filters, eventCursor),
  });
  const budgets = useQuery({
    queryKey: ["usage", "budgets"],
    queryFn: () => usageService.budgets(),
  });
  const { user } = useAuth();
  const canAudit = hasPermission(user?.permissions, Permission.auditRead);
  const reconciliation = useQuery({
    queryKey: ["usage", "reconciliation-summary"],
    queryFn: () => usageService.reconciliationSummary(),
    enabled: canAudit,
  });

  const totals = summary.data?.totals;
  const maxTrend = Math.max(
    0.000001,
    ...(trends.data ?? []).map((point) => Number(point.actual_cost)),
  );

  const resetPagination = () => {
    setBreakdownPage(1);
    setEventCursor(undefined);
    setCursorHistory([]);
  };

  return (
    <div style={{ display: "grid", gap: 22 }}>
      <PageHeader
        crumbs={[{ label: "Usage" }]}
        title="Usage & budget center"
        subtitle={
          summary.data
            ? `${summary.data.scope} visibility · Canonical ledger · UTC windows`
            : "Canonical model usage, spend, and remaining allowances"
        }
        actions={
          <>
            <button
              className="sccap-btn sccap-btn-sm sccap-btn-ghost"
              onClick={() => void usageService.export(filters, "json")}
            >
              Export JSON
            </button>
            <button
              className="sccap-btn sccap-btn-sm sccap-btn-primary"
              onClick={() => void usageService.export(filters, "csv")}
            >
              Export CSV
            </button>
          </>
        }
      />

      <section className="sccap-card" style={{ padding: 16 }} aria-label="Usage filters">
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))",
            gap: 12,
            alignItems: "end",
          }}
        >
          <label style={{ display: "grid", gap: 5, fontSize: 12 }}>
            From (UTC)
            <input
              aria-label="Usage from date"
              type="date"
              value={from}
              max={to}
              onChange={(event) => {
                setFrom(event.target.value);
                resetPagination();
              }}
              style={inputStyle}
            />
          </label>
          <label style={{ display: "grid", gap: 5, fontSize: 12 }}>
            To (UTC)
            <input
              aria-label="Usage to date"
              type="date"
              value={to}
              min={from}
              onChange={(event) => {
                setTo(event.target.value);
                resetPagination();
              }}
              style={inputStyle}
            />
          </label>
          <label style={{ display: "grid", gap: 5, fontSize: 12 }}>
            Operation
            <select
              aria-label="Usage operation"
              value={operation}
              onChange={(event) => {
                setOperation(event.target.value as typeof operation);
                resetPagination();
              }}
              style={inputStyle}
            >
              <option value="">All operations</option>
              <option value="scan">Scans</option>
              <option value="chat">Advisor</option>
              <option value="rag">RAG</option>
            </select>
          </label>
          <label style={{ display: "grid", gap: 5, fontSize: 12 }}>
            Accounting state
            <select
              aria-label="Usage accounting state"
              value={costStatus}
              onChange={(event) => {
                setCostStatus(event.target.value as typeof costStatus);
                resetPagination();
              }}
              style={inputStyle}
            >
              <option value="">All states</option>
              <option value="exact">Actual</option>
              <option value="estimated">Estimated</option>
              <option value="unknown">Unknown price</option>
              <option value="reconciled">Reconciled</option>
            </select>
          </label>
        </div>
      </section>

      {summary.isError ? (
        <div className="sccap-card" role="alert" style={{ padding: 18, color: "var(--critical)" }}>
          Usage could not be loaded. Retry or narrow the selected window.
        </div>
      ) : (
        <section
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))",
            gap: 12,
          }}
          aria-label="Usage summary"
        >
          <MetricCard label="Actual cost" value={money(totals?.actual_cost ?? "0")} />
          <MetricCard label="Estimated cost" value={money(totals?.estimated_cost ?? "0")} />
          <MetricCard
            label="Variance"
            value={money(totals?.variance ?? "0")}
            tone={Number(totals?.variance ?? 0) > 0 ? "bad" : "good"}
          />
          <MetricCard label="Total tokens" value={integer(totals?.total_tokens ?? 0)} />
          <MetricCard
            label="Input / output"
            value={`${integer(totals?.input_tokens ?? 0)} / ${integer(totals?.output_tokens ?? 0)}`}
          />
          <MetricCard label="Reasoning tokens" value={integer(totals?.reasoning_tokens ?? 0)} />
          <MetricCard label="Requests" value={integer(totals?.requests ?? 0)} />
          <MetricCard label="Cache-hit rate" value={`${totals?.cache_hit_rate ?? "0"}%`} />
        </section>
      )}

      <section className="sccap-card" style={{ padding: 18 }}>
        <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
          <div>
            <h2 style={{ margin: 0, fontSize: 16 }}>Daily actual vs estimate</h2>
            <p className="muted" style={{ margin: "4px 0 0", fontSize: 12 }}>
              Unknown-price events remain visible but are never silently valued at zero.
            </p>
          </div>
          <div style={{ display: "flex", gap: 10, fontSize: 12 }}>
            <span><StatusChip value="exact" /> actual</span>
            <span><StatusChip value="estimated" /> estimate</span>
            <span><StatusChip value="reconciled" /> reconciled</span>
          </div>
        </div>
        <div style={{ display: "grid", gap: 8, marginTop: 18 }}>
          {(trends.data ?? []).map((point) => (
            <div key={point.bucket} style={{ display: "grid", gridTemplateColumns: "90px 1fr 110px", gap: 10, alignItems: "center" }}>
              <span className="muted" style={{ fontSize: 12 }}>{new Date(point.bucket).toLocaleDateString()}</span>
              <div style={{ height: 8, background: "var(--bg-soft)", borderRadius: 999, overflow: "hidden" }}>
                <div style={{ width: `${Math.max(1, (Number(point.actual_cost) / maxTrend) * 100)}%`, height: "100%", background: "var(--primary)", borderRadius: 999 }} />
              </div>
              <span style={{ textAlign: "right", fontVariantNumeric: "tabular-nums", fontSize: 12 }}>{money(point.actual_cost)}</span>
            </div>
          ))}
          {!trends.isLoading && !trends.data?.length && <p className="muted">No usage in this window.</p>}
        </div>
      </section>

      <BudgetPanel
        status={budgets.data}
        loading={budgets.isLoading}
        reconciliation={reconciliation.data}
      />

      <section className="sccap-card" style={{ padding: 18, overflowX: "auto" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12 }}>
          <h2 style={{ margin: 0, fontSize: 16 }}>Breakdown</h2>
          <select
            aria-label="Usage breakdown dimension"
            value={dimension}
            onChange={(event) => {
              setDimension(event.target.value as UsageDimension);
              setBreakdownPage(1);
            }}
            style={inputStyle}
          >
            {(["operation", "project", "scan", "stage", "agent", "provider", "model", "account", "group"] as const).map((value) => (
              <option value={value} key={value}>{value}</option>
            ))}
          </select>
        </div>
        <table style={{ width: "100%", borderCollapse: "collapse", marginTop: 12, minWidth: 620 }}>
          <thead><tr>{[dimension, "Actual", "Estimated", "Tokens", "Requests", "State"].map((heading) => <th key={heading} style={{ textAlign: "left", padding: "9px 8px", borderBottom: "1px solid var(--border)", fontSize: 11, textTransform: "uppercase", color: "var(--fg-muted)" }}>{heading}</th>)}</tr></thead>
          <tbody>
            {(breakdown.data?.items ?? []).map((item) => (
              <tr key={item.key}>
                <td style={{ padding: 8, borderBottom: "1px solid var(--border)", fontFamily: "var(--font-mono)", fontSize: 12 }}>{item.key}</td>
                <td style={{ padding: 8, borderBottom: "1px solid var(--border)" }}>{money(item.actual_cost)}</td>
                <td style={{ padding: 8, borderBottom: "1px solid var(--border)" }}>{money(item.estimated_cost)}</td>
                <td style={{ padding: 8, borderBottom: "1px solid var(--border)" }}>{integer(item.total_tokens)}</td>
                <td style={{ padding: 8, borderBottom: "1px solid var(--border)" }}>{integer(item.requests)}</td>
                <td style={{ padding: 8, borderBottom: "1px solid var(--border)" }}>{item.unknown_events ? <StatusChip value="unknown" /> : item.reconciled_events ? <StatusChip value="reconciled" /> : <StatusChip value="exact" />}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
          <button className="sccap-btn sccap-btn-sm sccap-btn-ghost" disabled={breakdownPage === 1} onClick={() => setBreakdownPage((page) => Math.max(1, page - 1))}>Previous</button>
          <button className="sccap-btn sccap-btn-sm sccap-btn-ghost" disabled={breakdownPage * 10 >= (breakdown.data?.total ?? 0)} onClick={() => setBreakdownPage((page) => page + 1)}>Next</button>
        </div>
      </section>

      <section className="sccap-card" style={{ padding: 18, overflowX: "auto" }}>
        <h2 style={{ margin: 0, fontSize: 16 }}>Ledger drilldown</h2>
        <p className="muted" style={{ margin: "4px 0 12px", fontSize: 12 }}>
          Attribution only. Prompts, responses, source contents, and secrets are intentionally excluded.
        </p>
        <table style={{ width: "100%", borderCollapse: "collapse", minWidth: 840 }}>
          <thead><tr>{["Time", "Operation", "Stage / agent", "Provider / model", "Tokens", "Cost", "Accounting"].map((heading) => <th key={heading} style={{ textAlign: "left", padding: "9px 8px", borderBottom: "1px solid var(--border)", fontSize: 11, textTransform: "uppercase", color: "var(--fg-muted)" }}>{heading}</th>)}</tr></thead>
          <tbody>
            {(events.data?.items ?? []).map((event) => (
              <tr key={event.id}>
                <td style={{ padding: 8, borderBottom: "1px solid var(--border)", whiteSpace: "nowrap", fontSize: 12 }}>{new Date(event.created_at).toLocaleString()}</td>
                <td style={{ padding: 8, borderBottom: "1px solid var(--border)", fontSize: 12 }}><strong>{event.operation_kind}</strong><br /><span className="muted" style={{ fontFamily: "var(--font-mono)" }}>{event.operation_id.slice(0, 12)}…</span></td>
                <td style={{ padding: 8, borderBottom: "1px solid var(--border)", fontSize: 12 }}>{event.stage}<br /><span className="muted">{event.agent_name}</span></td>
                <td style={{ padding: 8, borderBottom: "1px solid var(--border)", fontSize: 12 }}>{event.provider}<br /><span className="muted">{event.requested_model}</span></td>
                <td style={{ padding: 8, borderBottom: "1px solid var(--border)" }}>{integer(event.total_tokens)}</td>
                <td style={{ padding: 8, borderBottom: "1px solid var(--border)" }}>{money(event.total_cost, event.currency ?? "USD")}</td>
                <td style={{ padding: 8, borderBottom: "1px solid var(--border)" }}><StatusChip value={event.cost_status} /></td>
              </tr>
            ))}
          </tbody>
        </table>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
          <button className="sccap-btn sccap-btn-sm sccap-btn-ghost" disabled={!cursorHistory.length} onClick={() => { const history = [...cursorHistory]; const previous = history.pop(); setCursorHistory(history); setEventCursor(previous); }}>Previous</button>
          <button className="sccap-btn sccap-btn-sm sccap-btn-ghost" disabled={!events.data?.next_cursor} onClick={() => { setCursorHistory((history) => [...history, eventCursor]); setEventCursor(events.data?.next_cursor ?? undefined); }}>Next</button>
        </div>
      </section>

      <PolicyAdmin />
    </div>
  );
};

const BudgetPanel: React.FC<{
  status?: Awaited<ReturnType<typeof usageService.budgets>>;
  loading: boolean;
  reconciliation?: Awaited<ReturnType<typeof usageService.reconciliationSummary>>;
}> = ({ status, loading, reconciliation }) => (
  <section className="sccap-card" style={{ padding: 18 }}>
    <h2 style={{ margin: 0, fontSize: 16 }}>Remaining allowances</h2>
    <p className="muted" style={{ margin: "4px 0 14px", fontSize: 12 }}>Spent and held capacity are shown separately. All resets use UTC.</p>
    {loading && <p className="muted">Loading budget state…</p>}
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(230px, 1fr))", gap: 10 }}>
      {(status?.states ?? []).map((state) => (
        <article key={`${state.policy_id}:${state.window}`} style={{ border: "1px solid var(--border)", borderRadius: 10, padding: 14 }}>
          <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}><strong style={{ textTransform: "capitalize" }}>{state.scope} · {state.window}</strong><StatusChip value={state.threshold_state} /></div>
          <div style={{ height: 7, background: "var(--bg-soft)", borderRadius: 999, margin: "12px 0", overflow: "hidden" }}><div style={{ width: `${Math.min(100, Number(state.utilization_percent))}%`, height: "100%", background: statusColor.get(state.threshold_state) }} /></div>
          <div style={{ fontSize: 13 }}>Remaining: <strong>{state.remaining_usd === null ? `${integer(state.remaining_total_tokens ?? 0)} tokens` : money(state.remaining_usd)}</strong></div>
          <div className="muted" style={{ fontSize: 11, marginTop: 5 }}>Held {money(state.held_usd)} · {state.window_end ? `resets ${new Date(state.window_end).toLocaleString()}` : "window begins on first use"}</div>
        </article>
      ))}
    </div>
    {!!status?.recent_denials.length && <p style={{ color: "var(--critical)", fontSize: 12, marginTop: 12 }}>{status.recent_denials.length} recent operation(s) stopped at a hard budget limit.</p>}
    {reconciliation && (
      <div style={{ borderTop: "1px solid var(--border)", marginTop: 14, paddingTop: 12, fontSize: 12 }}>
        Provider reconciliation: <StatusChip value={reconciliation.status} /> · {reconciliation.coverage_percent}% coverage · {reconciliation.unresolved_dimensions} unresolved dimension(s)
      </div>
    )}
  </section>
);

const PolicyAdmin: React.FC = () => {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const canManage = hasPermission(user?.permissions, Permission.tenantPolicyManage);
  const [scope, setScope] = useState<BudgetPolicyPayload["scope"]>("tenant");
  const [window, setWindow] = useState<BudgetPolicyPayload["window"]>("month");
  const [usd, setUsd] = useState("100");
  const [tokens, setTokens] = useState("");
  const [target, setTarget] = useState("");
  const [reason, setReason] = useState("Set production usage allowance");
  const [effectiveFrom, setEffectiveFrom] = useState("");
  const [effectiveTo, setEffectiveTo] = useState("");
  const [preview, setPreview] = useState<Record<string, unknown> | null>(null);
  const policies = useQuery({ queryKey: ["usage", "policies"], queryFn: usageService.listPolicies, enabled: canManage });
  const payload = (): BudgetPolicyPayload => ({
    scope,
    window,
    ...(scope === "group" && target ? { group_id: target } : {}),
    ...(scope === "user" && target ? { user_id: Number(target) } : {}),
    caps: { ...(usd ? { usd } : {}), ...(tokens ? { total_tokens: Number(tokens) } : {}) },
    soft_thresholds: [80, 95],
    unknown_price_action: "deny",
    ...(effectiveFrom ? { effective_from: new Date(effectiveFrom).toISOString() } : {}),
    ...(effectiveTo ? { effective_to: new Date(effectiveTo).toISOString() } : {}),
    reason,
  });
  const save = useMutation({
    mutationFn: () => usageService.createPolicy(payload()),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["usage"] });
      setPreview(null);
    },
  });
  if (!canManage) return null;
  return (
    <section className="sccap-card" style={{ padding: 18 }} aria-label="Budget policy administration">
      <h2 style={{ margin: 0, fontSize: 16 }}>Policy administration</h2>
      <p className="muted" style={{ margin: "4px 0 14px", fontSize: 12 }}>Preview strictest effective precedence before creating or scheduling an immutable policy version.</p>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 10 }}>
        <label style={{ display: "grid", gap: 5, fontSize: 12 }}>Scope<select value={scope} onChange={(event) => { setScope(event.target.value as typeof scope); setTarget(""); }} style={inputStyle}><option value="tenant">Tenant</option><option value="group">Group</option><option value="user">User</option></select></label>
        {scope !== "tenant" && <label style={{ display: "grid", gap: 5, fontSize: 12 }}>{scope === "group" ? "Group UUID" : "User ID"}<input value={target} onChange={(event) => setTarget(event.target.value)} style={inputStyle} /></label>}
        <label style={{ display: "grid", gap: 5, fontSize: 12 }}>Window<select value={window} onChange={(event) => setWindow(event.target.value as typeof window)} style={inputStyle}><option value="request">Request</option><option value="scan">Scan</option><option value="day">UTC day</option><option value="month">UTC month</option></select></label>
        <label style={{ display: "grid", gap: 5, fontSize: 12 }}>USD cap<input type="number" min="0" step="0.01" value={usd} onChange={(event) => setUsd(event.target.value)} style={inputStyle} /></label>
        <label style={{ display: "grid", gap: 5, fontSize: 12 }}>Token cap (optional)<input type="number" min="0" value={tokens} onChange={(event) => setTokens(event.target.value)} style={inputStyle} /></label>
        <label style={{ display: "grid", gap: 5, fontSize: 12 }}>Starts (optional)<input type="datetime-local" value={effectiveFrom} onChange={(event) => setEffectiveFrom(event.target.value)} style={inputStyle} /></label>
        <label style={{ display: "grid", gap: 5, fontSize: 12 }}>Ends (optional)<input type="datetime-local" value={effectiveTo} onChange={(event) => setEffectiveTo(event.target.value)} style={inputStyle} /></label>
        <label style={{ display: "grid", gap: 5, fontSize: 12 }}>Audit reason<input value={reason} minLength={10} onChange={(event) => setReason(event.target.value)} style={inputStyle} /></label>
      </div>
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
        <button className="sccap-btn sccap-btn-sm sccap-btn-ghost" onClick={() => void usageService.previewPolicy(payload()).then(setPreview)}>Preview precedence</button>
        <button className="sccap-btn sccap-btn-sm sccap-btn-primary" disabled={save.isPending || reason.trim().length < 10 || (!usd && !tokens) || (scope !== "tenant" && !target)} onClick={() => save.mutate()}>Create policy</button>
      </div>
      {preview && <pre style={{ background: "var(--bg-soft)", borderRadius: 8, padding: 12, overflowX: "auto", fontSize: 11 }}>{JSON.stringify(preview, null, 2)}</pre>}
      {(save.isError) && <p role="alert" style={{ color: "var(--critical)" }}>Policy could not be saved. Review the target, interval, and reason.</p>}
      <div style={{ marginTop: 16, display: "grid", gap: 8 }}>
        {(policies.data ?? []).map((policy) => {
          const id = String(policy.id);
          return <div key={id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderTop: "1px solid var(--border)", paddingTop: 8, gap: 12 }}><span style={{ fontSize: 12 }}><strong>{String(policy.scope)}</strong> · {String(policy.window)} · version {String(policy.version)}</span><button className="sccap-btn sccap-btn-sm sccap-btn-ghost" onClick={() => void usageService.disablePolicy(id, "Disabled from usage budget center").then(() => queryClient.invalidateQueries({ queryKey: ["usage"] }))}>Disable</button></div>;
        })}
      </div>
    </section>
  );
};

export default UsagePage;
