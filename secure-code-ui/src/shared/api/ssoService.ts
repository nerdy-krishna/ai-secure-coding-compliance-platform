// secure-code-ui/src/shared/api/ssoService.ts
//
// Public + admin SSO API client. The public surface drives the login page
// (provider list + force-SSO preflight); the admin surface drives the
// SSO Providers + Auth Audit pages under /admin.
//
// Token-redaction contract: secret fields (`client_secret`, `sp_private_key`)
// are NEVER returned plaintext. The admin form shows "***" placeholders;
// PATCH passes the literal "<<unchanged>>" sentinel to keep an existing
// secret without re-entry.

import apiClient from "./apiClient";

export type SsoProtocol = "oidc" | "saml";

export interface SsoProviderPublic {
  id: string;
  name: string;
  display_name: string;
  protocol: SsoProtocol;
}

export interface SsoProvidersListResponse {
  providers: SsoProviderPublic[];
  forced_for_email: SsoProviderPublic | null;
}

export interface LoginGuardResponse {
  forced: boolean;
  is_master_admin?: boolean;
  provider?: SsoProviderPublic;
}

// Admin shape — secrets redacted in `config`.
export interface SsoProviderAdmin {
  id: string;
  name: string;
  display_name: string;
  protocol: SsoProtocol;
  enabled: boolean;
  allowed_email_domains: string[] | null;
  force_for_domains: string[] | null;
  jit_policy: "auto" | "approve" | "deny";
  created_at: string;
  updated_at: string;
  config: Record<string, unknown>;
}

export interface SsoProviderCreate {
  name: string;
  display_name: string;
  protocol: SsoProtocol;
  config: Record<string, unknown>;
  enabled?: boolean;
  allowed_email_domains?: string[] | null;
  force_for_domains?: string[] | null;
  jit_policy?: "auto" | "approve" | "deny";
}

export interface SsoProviderUpdate {
  display_name?: string;
  enabled?: boolean;
  config?: Record<string, unknown>;
  allowed_email_domains?: string[] | null;
  force_for_domains?: string[] | null;
  jit_policy?: "auto" | "approve" | "deny";
}

export interface SsoAuditEvent {
  id: string;
  ts: string;
  event: string;
  user_id: number | null;
  provider_id: string | null;
  email_hash: string | null;
  ip: string | null;
  user_agent: string | null;
  details: Record<string, unknown> | null;
}

export const ssoService = {
  // Public — login page lists enabled providers.
  async listEnabledProviders(email?: string): Promise<SsoProvidersListResponse> {
    const params: Record<string, string> = {};
    if (email) params.email = email;
    const res = await apiClient.get<SsoProvidersListResponse>(
      "/auth/sso/providers",
      { params },
    );
    return res.data;
  },

  // Public — force-SSO preflight (frontend hides the password field).
  async loginGuard(email: string): Promise<LoginGuardResponse> {
    const res = await apiClient.get<LoginGuardResponse>("/auth/login-guard", {
      params: { email },
    });
    return res.data;
  },

  // Admin CRUD.
  async adminListProviders(): Promise<SsoProviderAdmin[]> {
    const res = await apiClient.get<SsoProviderAdmin[]>(
      "/admin/sso/providers",
    );
    return res.data;
  },

  async adminCreateProvider(
    payload: SsoProviderCreate,
  ): Promise<SsoProviderAdmin> {
    const res = await apiClient.post<SsoProviderAdmin>(
      "/admin/sso/providers",
      payload,
    );
    return res.data;
  },

  async adminGetProvider(id: string): Promise<SsoProviderAdmin> {
    const res = await apiClient.get<SsoProviderAdmin>(
      `/admin/sso/providers/${id}`,
    );
    return res.data;
  },

  async adminUpdateProvider(
    id: string,
    payload: SsoProviderUpdate,
  ): Promise<SsoProviderAdmin> {
    const res = await apiClient.patch<SsoProviderAdmin>(
      `/admin/sso/providers/${id}`,
      payload,
    );
    return res.data;
  },

  async adminDeleteProvider(id: string): Promise<void> {
    await apiClient.delete(`/admin/sso/providers/${id}`);
  },

  async adminTestProvider(id: string): Promise<Record<string, unknown>> {
    const res = await apiClient.post<Record<string, unknown>>(
      `/admin/sso/providers/${id}/test`,
    );
    return res.data;
  },

  async adminListAuditEvents(args: {
    limit?: number;
    cursor?: string;
    event?: string;
  }): Promise<SsoAuditEvent[]> {
    const params: Record<string, string | number> = {
      limit: args.limit ?? 100,
    };
    if (args.cursor) params.cursor = args.cursor;
    if (args.event) params.event = args.event;
    const res = await apiClient.get<SsoAuditEvent[]>("/admin/sso/audit", {
      params,
    });
    return res.data;
  },
};
