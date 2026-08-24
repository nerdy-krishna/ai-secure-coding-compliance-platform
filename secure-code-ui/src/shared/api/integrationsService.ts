import apiClient from "./apiClient";

export type IntegrationKind = "github_app" | "jira_cloud" | "siem_webhook";

export interface IntegrationPrincipal {
  id: string;
  tenant_id: string;
  kind: IntegrationKind;
  display_name: string;
  config: Record<string, unknown>;
  enabled: boolean;
  secret_fingerprint: string;
  revoked_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface IntegrationGrant {
  id: string;
  principal_id: string;
  feature: string;
  scope: Record<string, unknown>;
  scope_digest: string;
  created_at: string;
  revoked_at: string | null;
}

export interface IntegrationDelivery {
  id: string;
  principal_id: string;
  event_type: string;
  idempotency_key: string;
  state: string;
  attempts: number;
  max_attempts: number;
  next_attempt_at: string;
  delivered_at: string | null;
  last_error_code: string | null;
  created_at: string;
}

export interface IntegrationTicket {
  id: string;
  principal_id: string;
  canonical_root_id: string;
  external_key: string;
  external_url: string | null;
  status: string;
  waiver_expires_at: string | null;
  created_at: string;
  updated_at: string;
}

export const integrationsService = {
  listPrincipals: async (): Promise<IntegrationPrincipal[]> =>
    (await apiClient.get<IntegrationPrincipal[]>("/admin/integrations/principals")).data,
  createPrincipal: async (payload: {
    kind: IntegrationKind;
    display_name: string;
    config: Record<string, unknown>;
    secret_values: Record<string, string>;
  }): Promise<IntegrationPrincipal> =>
    (await apiClient.post<IntegrationPrincipal>("/admin/integrations/principals", payload)).data,
  revokePrincipal: async (principalId: string): Promise<void> => {
    await apiClient.post(`/admin/integrations/principals/${encodeURIComponent(principalId)}/revoke`);
  },
  listGrants: async (principalId: string): Promise<IntegrationGrant[]> =>
    (await apiClient.get<IntegrationGrant[]>(
      `/admin/integrations/principals/${encodeURIComponent(principalId)}/grants`,
    )).data,
  createGrant: async (
    principalId: string,
    feature: string,
    scope: Record<string, unknown>,
  ): Promise<IntegrationGrant> =>
    (await apiClient.post<IntegrationGrant>(
      `/admin/integrations/principals/${encodeURIComponent(principalId)}/grants`,
      { feature, scope },
    )).data,
  revokeGrant: async (principalId: string, grantId: string): Promise<void> => {
    await apiClient.post(
      `/admin/integrations/principals/${encodeURIComponent(principalId)}/grants/${encodeURIComponent(grantId)}/revoke`,
    );
  },
  listDeliveries: async (): Promise<IntegrationDelivery[]> =>
    (await apiClient.get<IntegrationDelivery[]>("/admin/integrations/deliveries")).data,
  retryDelivery: async (deliveryId: string): Promise<IntegrationDelivery> =>
    (await apiClient.post<IntegrationDelivery>(
      `/admin/integrations/deliveries/${encodeURIComponent(deliveryId)}/retry`,
    )).data,
  listTickets: async (): Promise<IntegrationTicket[]> =>
    (await apiClient.get<IntegrationTicket[]>("/admin/integrations/tickets")).data,
};
