import apiClient from "./apiClient";

export type SeparationOfDutiesMode = "off" | "critical";
export type ActionStatus =
  | "pending"
  | "approved"
  | "rejected"
  | "expired"
  | "executed"
  | "cancelled";

export interface AuthorizationPolicy {
  separation_of_duties_mode: SeparationOfDutiesMode;
}

export interface ActionRequest {
  id: string;
  requester_permission: string;
  approver_permission: string;
  target_type: string;
  status: ActionStatus;
  expires_at: string;
  created_at: string;
  decided_at: string | null;
  executed_at: string | null;
  is_requester: boolean;
  can_decide: boolean;
}

export const authorizationService = {
  getPolicy: async (): Promise<AuthorizationPolicy> =>
    (await apiClient.get<AuthorizationPolicy>("/admin/authorization/policy")).data,

  setPolicy: async (
    separation_of_duties_mode: SeparationOfDutiesMode,
    action_request_id?: string,
  ): Promise<AuthorizationPolicy> =>
    (
      await apiClient.patch<AuthorizationPolicy>("/admin/authorization/policy", {
        separation_of_duties_mode,
        action_request_id,
      })
    ).data,

  requestRelaxation: async (): Promise<ActionRequest> =>
    (
      await apiClient.post<ActionRequest>(
        "/admin/authorization/policy-change-requests",
        { separation_of_duties_mode: "off" },
        { headers: { "X-Idempotency-Key": crypto.randomUUID() } },
      )
    ).data,

  listActions: async (): Promise<ActionRequest[]> =>
    (await apiClient.get<ActionRequest[]>("/admin/authorization/actions")).data,

  decide: async (
    requestId: string,
    approved: boolean,
    reason: string,
  ): Promise<ActionRequest> =>
    (
      await apiClient.post<ActionRequest>(
        `/admin/authorization/actions/${requestId}/decision`,
        { approved, reason },
      )
    ).data,
};
