// secure-code-ui/src/shared/api/tenantService.ts
//
// Platform tenant metadata and explicit short-lived tenant-entry grants.

import apiClient, { clearTenantEntryGrant, setTenantEntryGrant } from "./apiClient";

export interface Tenant {
  id: string;
  slug: string;
  display_name: string;
  created_at: string;
  updated_at: string;
  is_default: boolean;
}

export interface TenantCreatePayload {
  slug: string;
  display_name: string;
}

export interface TenantUpdatePayload {
  display_name: string;
}

interface TenantEntryResponse {
  tenant_id: string;
  entry_token: string;
  expires_in: number;
}

export const tenantService = {
  async list(): Promise<Tenant[]> {
    const r = await apiClient.get<Tenant[]>("/admin/tenants");
    return r.data;
  },
  async create(payload: TenantCreatePayload): Promise<Tenant> {
    const r = await apiClient.post<Tenant>("/admin/tenants", payload);
    return r.data;
  },
  async update(id: string, payload: TenantUpdatePayload): Promise<Tenant> {
    const r = await apiClient.patch<Tenant>(`/admin/tenants/${id}`, payload);
    return r.data;
  },
  async remove(id: string): Promise<void> {
    await apiClient.delete(`/admin/tenants/${id}`);
  },
  async enter(id: string, password: string, reason: string): Promise<void> {
    const response = await apiClient.post<TenantEntryResponse>("/admin/tenants/entry", {
      tenant_id: id,
      password,
      reason,
    });
    setTenantEntryGrant(response.data.entry_token, response.data.expires_in);
  },
  leave(): void {
    clearTenantEntryGrant();
  },
};

export default tenantService;
