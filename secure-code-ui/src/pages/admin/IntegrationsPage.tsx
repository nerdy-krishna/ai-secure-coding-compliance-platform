import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useMemo, useState } from "react";

import {
  integrationsService,
  type IntegrationKind,
  type IntegrationPrincipal,
} from "../../shared/api/integrationsService";
import { isSafeHttpUrl } from "../../shared/lib/safeUrl";
import { ErrorState, LoadingState } from "../../shared/ui/AsyncState";
import { PageHeader } from "../../shared/ui/PageHeader";

const FEATURES: Record<IntegrationKind, string[]> = {
  github_app: [
    "repository_contents_read",
    "security_events_write",
    "webhook_metadata_read",
  ],
  jira_cloud: ["ticket_sync"],
  siem_webhook: ["siem_emit"],
};

function ConnectorForm({ onCreated }: { onCreated: () => void }) {
  const [kind, setKind] = useState<IntegrationKind>("github_app");
  const [name, setName] = useState("");
  const [configJson, setConfigJson] = useState("{}");
  const [secretsJson, setSecretsJson] = useState("{}");
  const [error, setError] = useState("");
  const create = useMutation({
    mutationFn: () => {
      const config = JSON.parse(configJson) as Record<string, unknown>;
      const secret_values = JSON.parse(secretsJson) as Record<string, string>;
      return integrationsService.createPrincipal({
        kind,
        display_name: name.trim(),
        config,
        secret_values,
      });
    },
    onSuccess: () => {
      setError("");
      setName("");
      setSecretsJson("{}");
      onCreated();
    },
    onError: (value) => setError(value instanceof Error ? value.message : "Connector creation failed."),
  });
  return (
    <section className="sccap-card" style={{ display: "grid", gap: 10 }}>
      <strong>Create tenant service principal</strong>
      <div style={{ color: "var(--fg-muted)", fontSize: 12 }}>
        Secrets are encrypted at rest and are never returned by this page. Configure only the least-privilege grants used below.
      </div>
      <select aria-label="Integration kind" value={kind} onChange={(event) => setKind(event.target.value as IntegrationKind)}>
        <option value="github_app">GitHub App</option>
        <option value="jira_cloud">Jira Cloud</option>
        <option value="siem_webhook">Signed SIEM webhook</option>
      </select>
      <input aria-label="Integration name" value={name} onChange={(event) => setName(event.target.value)} placeholder="Production security integration" />
      <label>
        <span>Non-secret configuration JSON</span>
        <textarea aria-label="Integration configuration JSON" rows={7} value={configJson} onChange={(event) => setConfigJson(event.target.value)} />
      </label>
      <label>
        <span>Secret values JSON</span>
        <textarea aria-label="Integration secret values JSON" rows={5} value={secretsJson} onChange={(event) => setSecretsJson(event.target.value)} autoComplete="off" />
      </label>
      <div style={{ color: "var(--fg-muted)", fontSize: 11 }}>
        GitHub secrets: private_key_pem, webhook_secret. Jira: email, api_token. SIEM: signing_secret (32+ bytes).
      </div>
      {error && <div role="alert" style={{ color: "var(--critical)" }}>{error}</div>}
      <button className="sccap-btn sccap-btn-primary" disabled={create.isPending || name.trim().length < 3} onClick={() => {
        try { JSON.parse(configJson); JSON.parse(secretsJson); setError(""); create.mutate(); }
        catch { setError("Configuration and secrets must be valid JSON objects."); }
      }}>
        Create encrypted connector
      </button>
    </section>
  );
}

function PrincipalCard({ principal, refresh }: { principal: IntegrationPrincipal; refresh: () => void }) {
  const queryClient = useQueryClient();
  const grants = useQuery({
    queryKey: ["integration-grants", principal.id],
    queryFn: () => integrationsService.listGrants(principal.id),
  });
  const active = new Set((grants.data ?? []).filter((grant) => !grant.revoked_at).map((grant) => grant.feature));
  const grant = useMutation({
    mutationFn: (feature: string) => integrationsService.createGrant(
      principal.id,
      feature,
      principal.kind === "github_app"
        ? { repository: `${String(principal.config.owner)}/${String(principal.config.repository)}` }
        : principal.kind === "jira_cloud"
          ? { project_key: principal.config.project_key }
          : { event_types: ["policy.evaluated", "finding.changed"] },
    ),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["integration-grants", principal.id] }),
  });
  const revokeGrant = useMutation({
    mutationFn: (grantId: string) => integrationsService.revokeGrant(principal.id, grantId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["integration-grants", principal.id] });
      queryClient.invalidateQueries({ queryKey: ["integration-deliveries"] });
    },
  });
  const revoke = useMutation({
    mutationFn: () => integrationsService.revokePrincipal(principal.id),
    onSuccess: refresh,
  });
  return (
    <article className="sccap-card" style={{ display: "grid", gap: 9 }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
        <div><strong>{principal.display_name}</strong><div className="mono" style={{ fontSize: 11 }}>{principal.kind} · {principal.id}</div></div>
        <span className={`chip ${principal.enabled ? "chip-success" : "chip-warn"}`}>{principal.enabled ? "active" : "revoked"}</span>
      </div>
      <div style={{ fontSize: 12 }}>Secret fingerprint: <code>{principal.secret_fingerprint.slice(0, 16)}…</code></div>
      <div style={{ fontSize: 12 }}>
        Outbound policy: revision <code>{String(principal.config.outbound_policy_revision ?? "unknown")}</code>
        {principal.config.outbound_policy_fingerprint
          ? <> · <code>{String(principal.config.outbound_policy_fingerprint).slice(0, 16)}…</code></>
          : null}
      </div>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
        {FEATURES[principal.kind].map((feature) => (
          <button key={feature} className="sccap-btn sccap-btn-sm" disabled={!principal.enabled || active.has(feature) || grant.isPending} onClick={() => grant.mutate(feature)}>
            {active.has(feature) ? `Granted: ${feature}` : `Grant ${feature}`}
          </button>
        ))}
      </div>
      {(grants.data ?? []).filter((item) => !item.revoked_at).map((item) => (
        <div key={item.id} style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 12 }}>
          <code>{item.feature}</code>
          <span className="mono">{JSON.stringify(item.scope)}</span>
          <button
            className="sccap-btn sccap-btn-sm"
            disabled={revokeGrant.isPending}
            onClick={() => revokeGrant.mutate(item.id)}
          >
            Revoke grant
          </button>
        </div>
      ))}
      {principal.enabled && <button className="sccap-btn sccap-btn-sm" onClick={() => revoke.mutate()} disabled={revoke.isPending}>Revoke principal and pending delivery</button>}
    </article>
  );
}

const IntegrationsPage: React.FC = () => {
  const queryClient = useQueryClient();
  const principals = useQuery({ queryKey: ["integration-principals"], queryFn: integrationsService.listPrincipals });
  const deliveries = useQuery({ queryKey: ["integration-deliveries"], queryFn: integrationsService.listDeliveries });
  const tickets = useQuery({ queryKey: ["integration-tickets"], queryFn: integrationsService.listTickets });
  const retry = useMutation({
    mutationFn: integrationsService.retryDelivery,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["integration-deliveries"] }),
  });
  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ["integration-principals"] });
    queryClient.invalidateQueries({ queryKey: ["integration-deliveries"] });
  };
  const deadLetters = useMemo(() => (deliveries.data ?? []).filter((row) => row.state === "dead_letter"), [deliveries.data]);

  if (principals.isLoading) return <LoadingState title="Loading integrations…" />;
  if (principals.isError) return <ErrorState title="Integrations unavailable" detail="The tenant integration inventory could not be loaded." action={<button className="sccap-btn" onClick={() => principals.refetch()}>Retry</button>} />;
  return (
    <div style={{ display: "grid", gap: 18 }}>
      <PageHeader crumbs={[{ label: "Administration", to: "/admin/authorization" }, { label: "Integrations" }]} title="Enterprise integrations" subtitle="Tenant-owned GitHub App, Jira Cloud, and signed SIEM delivery with revocable feature grants." />
      <ConnectorForm onCreated={refresh} />
      <section style={{ display: "grid", gap: 10 }}>
        <h2 style={{ fontSize: 17 }}>Service principals</h2>
        {(principals.data ?? []).map((principal) => <PrincipalCard key={principal.id} principal={principal} refresh={refresh} />)}
        {(principals.data ?? []).length === 0 && <div className="sccap-card">No integration principals configured.</div>}
      </section>
      <section className="sccap-card">
        <h2 style={{ fontSize: 17 }}>Delivery outbox</h2>
        <div>Pending/retry/dead-letter deliveries retain redacted evidence only. Dead letters: {deadLetters.length}</div>
        {(deliveries.data ?? []).map((row) => (
          <div key={row.id} style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 8, flexWrap: "wrap" }}>
            <code>{row.event_type}</code><span className="chip">{row.state}</span><span>attempt {row.attempts}/{row.max_attempts}</span>
            {row.state === "dead_letter" && <button className="sccap-btn sccap-btn-sm" disabled={retry.isPending} onClick={() => retry.mutate(row.id)}>Retry</button>}
          </div>
        ))}
      </section>
      <section className="sccap-card">
        <h2 style={{ fontSize: 17 }}>Canonical finding tickets</h2>
        {(tickets.data ?? []).map((ticket) => (
          <div key={ticket.id} style={{ display: "flex", gap: 8, marginTop: 8 }}>
            {ticket.external_url && isSafeHttpUrl(ticket.external_url)
              ? <a href={ticket.external_url} target="_blank" rel="noopener noreferrer">{ticket.external_key}</a>
              : <span>{ticket.external_key}</span>}
            <span>{ticket.status}</span><code>{ticket.canonical_root_id}</code>
          </div>
        ))}
      </section>
    </div>
  );
};

export default IntegrationsPage;
