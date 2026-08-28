// secure-code-ui/src/shared/api/tenantService.ts
//
// Platform tenant metadata and browser-session tenant selection.

import apiClient from "./apiClient";

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

export interface ActiveTenant {
  tenant_id: string;
  slug: string;
  display_name: string;
  is_default: boolean;
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
  async current(): Promise<ActiveTenant> {
    const r = await apiClient.get<ActiveTenant>("/admin/tenants/entry");
    return r.data;
  },
  async enter(id: string): Promise<ActiveTenant> {
    const r = await apiClient.post<ActiveTenant>("/admin/tenants/entry", {
      tenant_id: id,
    });
    return r.data;
  },
  async leave(): Promise<void> {
    await apiClient.delete("/admin/tenants/entry");
  },
};

export default tenantService;
