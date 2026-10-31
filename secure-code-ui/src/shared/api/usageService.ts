import apiClient from "./apiClient";
import type { components } from "../types/api-generated";

type Schemas = components["schemas"];

export type UsageCostStatus = "exact" | "estimated" | "unknown" | "reconciled";
export type UsageDimension =
  | "operation"
  | "project"
  | "scan"
  | "stage"
  | "agent"
  | "provider"
  | "model"
  | "account"
  | "group";

export type UsageTotals = Schemas["UsageTotals"];
export type UsageSummary = Schemas["UsageSummaryResponse"];
export type UsageTrendPoint = Schemas["UsageTrendPoint"];
export type UsageEvent = Schemas["UsageEventRead"];
export type UsageBudgetState = Schemas["UsageBudgetStateRead"];
export type UsageBudgetStatus = Schemas["UsageBudgetStatusResponse"];
export type ReconciliationSummary = Schemas["ReconciliationSummaryRead"];

export interface UsageFilters {
  from_at: string;
  to_at: string;
  operation_kind?: "scan" | "chat" | "rag" | "pentest";
  cost_status?: UsageCostStatus;
  stage?: string;
  provider?: string;
}

export interface BudgetPolicyPayload {
  scope: "tenant" | "group" | "user";
  group_id?: string;
  user_id?: number;
  window: "request" | "scan" | "day" | "month";
  caps: { usd?: string; total_tokens?: number };
  soft_thresholds: [number, number];
  unknown_price_action: "deny" | "token_only";
  effective_from?: string;
  effective_to?: string;
  reason: string;
}

function params(filters: UsageFilters): Record<string, string> {
  return Object.fromEntries(
    Object.entries(filters).filter((entry): entry is [string, string] => Boolean(entry[1])),
  );
}

export const usageService = {
  async summary(filters: UsageFilters): Promise<UsageSummary> {
    return (await apiClient.get<UsageSummary>("/usage/summary", { params: params(filters) })).data;
  },
  async trends(filters: UsageFilters): Promise<UsageTrendPoint[]> {
    return (
      await apiClient.get<{ points: UsageTrendPoint[] }>("/usage/trends", {
        params: { ...params(filters), interval: "day" },
      })
    ).data.points;
  },
  async breakdown(filters: UsageFilters, dimension: UsageDimension, page: number) {
    return (
      await apiClient.get<{ items: Array<UsageTotals & { key: string }>; total: number }>(
        "/usage/breakdowns",
        { params: { ...params(filters), dimension, page, page_size: 10 } },
      )
    ).data;
  },
  async events(filters: UsageFilters, cursor?: string) {
    return (
      await apiClient.get<{ items: UsageEvent[]; next_cursor: string | null }>(
        "/usage/events",
        { params: { ...params(filters), cursor, limit: 25 } },
      )
    ).data;
  },
  async budgets(): Promise<UsageBudgetStatus> {
    return (await apiClient.get<UsageBudgetStatus>("/usage/budgets")).data;
  },
  async reconciliationSummary(): Promise<ReconciliationSummary> {
    return (
      await apiClient.get<ReconciliationSummary>(
        "/admin/usage-reconciliation/summary",
      )
    ).data;
  },
  async export(filters: UsageFilters, format: "csv" | "json"): Promise<void> {
    const response = await apiClient.get(`/usage/export`, {
      params: { ...params(filters), format },
      responseType: "blob",
    });
    const href = URL.createObjectURL(response.data as Blob);
    const link = document.createElement("a");
    link.href = href;
    link.download = `usage.${format}`;
    link.click();
    URL.revokeObjectURL(href);
  },
  async listPolicies() {
    return (await apiClient.get<Array<Record<string, unknown>>>("/admin/usage-budgets/policies")).data;
  },
  async previewPolicy(policy: BudgetPolicyPayload) {
    return (
      await apiClient.post<Record<string, unknown>>("/usage/policy-preview", { policy })
    ).data;
  },
  async createPolicy(policy: BudgetPolicyPayload) {
    return (
      await apiClient.post<Record<string, unknown>>("/admin/usage-budgets/policies", policy)
    ).data;
  },
  async disablePolicy(policyId: string, reason: string) {
    return (
      await apiClient.post<Record<string, unknown>>(
        `/admin/usage-budgets/policies/${encodeURIComponent(policyId)}/disable`,
        { reason },
      )
    ).data;
  },
};
