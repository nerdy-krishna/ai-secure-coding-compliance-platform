// src/shared/api/featureService.ts
//
// Client for the public feature-flag discovery endpoint (modular setup).
// GET /features is unauthenticated — the route guards and login page need the
// enabled-feature set before a user authenticates.

import apiClient from "./apiClient";

export interface FeaturesResponse {
  enabled_features: string[];
  all_features: string[];
}

export const featureService = {
  getFeatures: async (): Promise<FeaturesResponse> => {
    const response = await apiClient.get<FeaturesResponse>("/features");
    return response.data;
  },
};
