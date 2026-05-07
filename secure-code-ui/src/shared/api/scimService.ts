// secure-code-ui/src/shared/api/scimService.ts
//
// Admin-only client for /api/v1/admin/scim/tokens. The plaintext token
// is returned exactly once at issue time — the caller (ScimTokensPage)
// must surface it so the operator can copy it before navigating away.

import apiClient from "./apiClient";

export type ScimScope = "users:read" | "users:write" | "groups:read" | "groups:write";

export const ALL_SCIM_SCOPES: ScimScope[] = [
  "users:read",
  "users:write",
  "groups:read",
  "groups:write",
];

export interface ScimToken {
  id: string;
  name: string;
  scopes: ScimScope[];
  created_at: string;
  expires_at: string | null;
  last_used_at: string | null;
}

export interface ScimTokenIssued extends ScimToken {
  plaintext_token: string;
}

export interface ScimTokenCreatePayload {
  name: string;
  scopes: ScimScope[];
  expires_at?: string | null;
}

export const scimService = {
  async listTokens(): Promise<ScimToken[]> {
    const r = await apiClient.get<ScimToken[]>("/admin/scim/tokens");
    return r.data;
  },
  async createToken(payload: ScimTokenCreatePayload): Promise<ScimTokenIssued> {
    const r = await apiClient.post<ScimTokenIssued>(
      "/admin/scim/tokens",
      payload,
    );
    return r.data;
  },
  async revokeToken(id: string): Promise<void> {
    await apiClient.delete(`/admin/scim/tokens/${id}`);
  },
};

export default scimService;
