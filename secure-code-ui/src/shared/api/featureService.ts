// src/shared/api/featureService.ts
//
// Client for the public feature-flag discovery endpoint (modular setup).
// GET /features is unauthenticated — the route guards and login page need the
// enabled-feature set before a user authenticates.

import apiClient from "./apiClient";

/** Static catalog metadata for one feature (carries no flag state). */
export interface FeatureCatalogEntry {
  name: string;
  description: string;
  depends_on: string[];
  container_backed: boolean;
  compose_profile: string | null;
  always_on: boolean;
}

export interface FeaturesResponse {
  enabled_features: string[];
  all_features: string[];
  variant: string;
  compose_profiles: string[];
  catalog: FeatureCatalogEntry[];
}

/** A catalog feature with its admin-visible state (GET /admin/features). */
export interface AdminFeature {
  name: string;
  description: string;
  enabled: boolean;
  always_on: boolean;
  container_backed: boolean;
  compose_profile: string | null;
  depends_on: string[];
}

export const featureService = {
  getFeatures: async (): Promise<FeaturesResponse> => {
    const response = await apiClient.get<FeaturesResponse>("/features");
    return response.data;
  },

  getAdminFeatures: async (): Promise<AdminFeature[]> => {
    const response = await apiClient.get<{ features: AdminFeature[] }>(
      "/admin/features",
    );
    return response.data.features;
  },

  updateFeatures: async (
    enabled: string[],
    confirmDestructive = false,
  ): Promise<{ features: AdminFeature[]; note: string }> => {
    const response = await apiClient.put<{
      features: AdminFeature[];
      note: string;
    }>("/admin/features", {
      enabled,
      confirm_destructive: confirmDestructive,
    });
    return response.data;
  },
};
