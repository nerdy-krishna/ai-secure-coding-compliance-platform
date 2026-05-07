// secure-code-ui/src/shared/api/tenantService.ts
//
// Admin-only client for /api/v1/admin/tenants. Tenant scoping is
// foundation-only today (Chunk 7); this surface exists so operators can
// create new tenants ahead of per-tenant enforcement work landing.

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
};

export default tenantService;
