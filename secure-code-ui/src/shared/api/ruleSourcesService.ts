// src/shared/api/ruleSourcesService.ts
import apiClient from "./apiClient";
import type {
  RuleSourceRead,
  RuleSourceCreate,
  RuleSourceUpdate,
  PaginatedSyncRunsResponse,
  PaginatedRulesResponse,
  IngestionSettingsRead,
  IngestionSettingsUpdate,
  ScanCoverageResponse,
} from "../types/api";

const _uuidRe = /^[0-9a-fA-F-]{32,36}$/;
function _checkId(id: string) {
  if (!_uuidRe.test(id)) throw new Error("Invalid source id");
}

export const ruleSourcesService = {
  // Settings
  getSettings: async (): Promise<IngestionSettingsRead> =>
    (await apiClient.get<IngestionSettingsRead>("/admin/rule-sources/settings")).data,
  updateSettings: async (u: IngestionSettingsUpdate): Promise<IngestionSettingsRead> =>
    (await apiClient.patch<IngestionSettingsRead>("/admin/rule-sources/settings", u)).data,

  // Seed
  seedSources: async (): Promise<RuleSourceRead[]> =>
    (await apiClient.post<RuleSourceRead[]>("/admin/rule-sources/seed")).data,

  // CRUD
  listSources: async (): Promise<RuleSourceRead[]> =>
    (await apiClient.get<RuleSourceRead[]>("/admin/rule-sources/")).data,
  createSource: async (data: RuleSourceCreate): Promise<RuleSourceRead> =>
    (await apiClient.post<RuleSourceRead>("/admin/rule-sources/", data)).data,
  getSource: async (id: string): Promise<RuleSourceRead> => {
    _checkId(id);
    return (await apiClient.get<RuleSourceRead>(`/admin/rule-sources/${encodeURIComponent(id)}`)).data;
  },
  updateSource: async (id: string, data: RuleSourceUpdate): Promise<RuleSourceRead> => {
    _checkId(id);
    const payload: RuleSourceUpdate = {};
    if (data.display_name !== undefined) payload.display_name = data.display_name;
    if (data.description !== undefined) payload.description = data.description;
    if (data.repo_url !== undefined) payload.repo_url = data.repo_url;
    if (data.branch !== undefined) payload.branch = data.branch;
    if (data.subpath !== undefined) payload.subpath = data.subpath;
    if (data.license_spdx !== undefined) payload.license_spdx = data.license_spdx;
    if (data.author !== undefined) payload.author = data.author;
    if (data.sync_cron !== undefined) payload.sync_cron = data.sync_cron;
    if (data.enabled !== undefined) payload.enabled = data.enabled;
    if (data.auto_sync !== undefined) payload.auto_sync = data.auto_sync;
    return (await apiClient.patch<RuleSourceRead>(`/admin/rule-sources/${encodeURIComponent(id)}`, payload)).data;
  },
  deleteSource: async (id: string): Promise<void> => {
    _checkId(id);
    await apiClient.delete(`/admin/rule-sources/${encodeURIComponent(id)}`);
  },

  // Sync
  triggerSync: async (id: string): Promise<{ detail: string; source_id: string }> => {
    _checkId(id);
    return (await apiClient.post(`/admin/rule-sources/${encodeURIComponent(id)}/sync`)).data;
  },

  // Sync runs
  listSyncRuns: async (id: string, page = 1, pageSize = 20): Promise<PaginatedSyncRunsResponse> => {
    _checkId(id);
    return (await apiClient.get<PaginatedSyncRunsResponse>(
      `/admin/rule-sources/${encodeURIComponent(id)}/runs`,
      { params: { page, page_size: pageSize } }
    )).data;
  },

  // Rules browse
  listRules: async (
    id: string,
    opts?: { lang?: string; severity?: string; q?: string; page?: number; page_size?: number }
  ): Promise<PaginatedRulesResponse> => {
    _checkId(id);
    return (await apiClient.get<PaginatedRulesResponse>(
      `/admin/rule-sources/${encodeURIComponent(id)}/rules`,
      { params: opts }
    )).data;
  },

  // Scan coverage (authenticated, not admin-only).
  // 5-second timeout — a hung coverage check must not block submission.
  checkCoverage: async (languages: string[]): Promise<ScanCoverageResponse> => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    try {
      return (
        await apiClient.get<ScanCoverageResponse>("/scan-coverage/check", {
          params: { "languages[]": languages },
          signal: controller.signal,
        })
      ).data;
    } finally {
      clearTimeout(timer);
    }
  },
};
