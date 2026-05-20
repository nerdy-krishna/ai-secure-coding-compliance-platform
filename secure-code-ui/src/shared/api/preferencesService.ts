// secure-code-ui/src/shared/api/preferencesService.ts
//
// Per-user preferences synced to the server so theme/variant/accent
// choices persist across browsers and devices.

import apiClient from "./apiClient";

export interface UserPreferences {
  theme: string | null;
  variant: string | null;
  accent: string | null;
}

export const preferencesService = {
  get: async (): Promise<UserPreferences> => {
    const { data } = await apiClient.get<UserPreferences>(
      "/account/preferences",
    );
    return data;
  },

  update: async (
    patch: Partial<UserPreferences>,
  ): Promise<UserPreferences> => {
    const { data } = await apiClient.put<UserPreferences>(
      "/account/preferences",
      patch,
    );
    return data;
  },
};
