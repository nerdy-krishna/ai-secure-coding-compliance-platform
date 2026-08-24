import apiClient from "./apiClient";
import type {
  FindingGovernanceSummary,
} from "../lib/scanContract";

export interface FindingWaiver {
  id: string;
  scan_id?: string | null;
  finding_id?: number | null;
  fingerprint: string;
  scope: "finding" | "fingerprint" | "project";
  scope_value: string;
  reason: string;
  expires_at: string;
  actor_user_id?: number | null;
  created_at: string;
  events: Array<{
    id: number;
    action: "granted" | "revoked" | "expired";
    actor_user_id?: number | null;
    reason: string;
    created_at: string;
  }>;
}

export const findingGovernanceService = {
  getScan: async (scanId: string): Promise<FindingGovernanceSummary> => {
    const response = await apiClient.get<{ counts: FindingGovernanceSummary["counts"]; items: FindingGovernanceSummary["items"]; policy_evaluation?: FindingGovernanceSummary["policy_evaluation"] }>(
      `/finding-governance/scans/${encodeURIComponent(scanId)}/findings`,
    );
    return response.data;
  },
  grantWaiver: async (
    scanId: string,
    findingId: number,
    body: { scope: "finding" | "fingerprint" | "project"; reason: string; expires_at: string },
  ): Promise<FindingWaiver> => {
    const response = await apiClient.post<FindingWaiver>(
      `/finding-governance/scans/${encodeURIComponent(scanId)}/findings/${findingId}/waivers`,
      body,
    );
    return response.data;
  },
  revokeWaiver: async (waiverId: string, reason: string): Promise<FindingWaiver> => {
    const response = await apiClient.post<FindingWaiver>(
      `/finding-governance/waivers/${encodeURIComponent(waiverId)}/revoke`,
      { reason },
    );
    return response.data;
  },
};
