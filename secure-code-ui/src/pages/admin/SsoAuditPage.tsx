// secure-code-ui/src/pages/admin/SsoAuditPage.tsx
//
// Append-only audit log viewer for authentication events. The underlying
// table has a Postgres immutability trigger; admin can only read.
// Most-recent-first; cursor pagination on `ts`.

import { useQuery } from "@tanstack/react-query";
import React, { useState } from "react";
import { ssoService, type SsoAuditEvent } from "../../shared/api/ssoService";
import { Icon } from "../../shared/ui/Icon";

const EVENT_FILTERS: { value: string; label: string }[] = [
  { value: "", label: "All events" },
  { value: "sso.login.success", label: "SSO login success" },
  { value: "sso.login.failure", label: "SSO login failure" },
  { value: "sso.provisioned", label: "SSO provisioned" },
  { value: "sso.linked", label: "SSO linked" },
  { value: "sso.link.refused", label: "SSO link refused" },
  { value: "sso.logout", label: "SSO logout" },
  { value: "session.absolute_lifetime_exceeded", label: "Session lifetime exceeded" },
  { value: "auth.password_login.blocked_by_force_sso", label: "Password blocked by force-SSO" },
  { value: "auth.provider.created", label: "Provider created" },
  { value: "auth.provider.updated", label: "Provider updated" },
  { value: "auth.provider.deleted", label: "Provider deleted" },
];

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 60_000) return "just now";
  const m = Math.floor(diff / 60_000);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d < 7) return `${d}d ago`;
  return new Date(iso).toLocaleDateString();
}

const SsoAuditPage: React.FC = () => {
  const [eventFilter, setEventFilter] = useState<string>("");

  const { data, isLoading, isError, error } = useQuery<SsoAuditEvent[], Error>({
    queryKey: ["admin-sso-audit", eventFilter],
    queryFn: () =>
      ssoService.adminListAuditEvents({
        limit: 200,
        event: eventFilter || undefined,
      }),
  });

  return (
    <div className="fade-in" style={{ display: "grid", gap: 16 }}>
      <div>
        <h1 style={{ color: "var(--fg)" }}>Authentication audit log</h1>
        <div style={{ color: "var(--fg-muted)", marginTop: 4, fontSize: 13 }}>
          Append-only log of authentication events. SOC 2 / ISO 27001
          evidence — UPDATE/DELETE rejected at the database layer.
        </div>
      </div>

      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <select
          className="sccap-input"
          value={eventFilter}
          onChange={(e) => setEventFilter(e.target.value)}
          style={{ maxWidth: 320 }}
        >
          {EVENT_FILTERS.map((f) => (
            <option key={f.value} value={f.value}>
              {f.label}
            </option>
          ))}
        </select>
        <span style={{ color: "var(--fg-subtle)", fontSize: 12 }}>
          {data ? `${data.length} event${data.length === 1 ? "" : "s"}` : ""}
        </span>
      </div>

      {isLoading ? (
        <div className="sccap-card" style={{ padding: 40, textAlign: "center", color: "var(--fg-muted)" }}>
          Loading…
        </div>
      ) : isError ? (
        <div className="sccap-card" style={{ padding: 40, textAlign: "center", color: "var(--critical)" }}>
          Failed to load audit log: {error.message}
        </div>
      ) : !data || data.length === 0 ? (
        <div className="sccap-card" style={{ padding: 60, textAlign: "center" }}>
          <div style={{ color: "var(--fg)", fontWeight: 500, marginBottom: 4 }}>
            No events
          </div>
          <div style={{ color: "var(--fg-muted)", fontSize: 13 }}>
            Authentication events will appear here as users sign in.
          </div>
        </div>
      ) : (
        <div className="sccap-card" style={{ padding: 0, overflow: "hidden" }}>
          <table className="sccap-t">
            <thead>
              <tr>
                <th>When</th>
                <th>Event</th>
                <th>User</th>
                <th>IP</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {data.map((row) => (
                <tr key={row.id}>
                  <td style={{ color: "var(--fg-muted)", fontSize: 12.5 }} title={row.ts}>
                    {relativeTime(row.ts)}
                  </td>
                  <td>
                    <span className={`chip ${eventChip(row.event)}`}>
                      {eventIcon(row.event)} {row.event}
                    </span>
                  </td>
                  <td style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>
                    {row.user_id ? `#${row.user_id}` : row.email_hash ? `hash:${row.email_hash.slice(0, 12)}` : "—"}
                  </td>
                  <td style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--fg-muted)" }}>
                    {row.ip ?? "—"}
                  </td>
                  <td style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--fg-muted)", maxWidth: 360, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {row.details ? JSON.stringify(row.details) : ""}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

function eventChip(event: string): string {
  if (event.endsWith("success") || event === "sso.linked") return "chip-success";
  if (event.endsWith("failure") || event.endsWith("refused") || event.endsWith("blocked_by_force_sso") || event === "session.absolute_lifetime_exceeded") {
    return "chip-critical";
  }
  if (event.startsWith("auth.provider.")) return "chip-info";
  return "";
}

function eventIcon(event: string): React.ReactNode {
  if (event.endsWith("success")) return <Icon.Check size={10} />;
  if (event.endsWith("failure") || event.endsWith("refused")) return <Icon.Alert size={10} />;
  return null;
}

export default SsoAuditPage;
