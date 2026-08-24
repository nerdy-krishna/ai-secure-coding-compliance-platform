import type { UsageBudgetState, UsageCostStatus } from "../api/usageService";

export function usageCostLabel(
  value: string | null,
  currency = "USD",
): string {
  if (value === null) return "Unknown";
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency,
    minimumFractionDigits: 2,
    maximumFractionDigits: 6,
  }).format(Number(value));
}

export function accountingLabel(status: UsageCostStatus): string {
  switch (status) {
    case "exact":
      return "Actual";
    case "estimated":
      return "Estimated";
    case "unknown":
      return "Unknown price";
    case "reconciled":
      return "Reconciled";
  }
}

export function budgetStateAt(
  utilizationPercent: string,
  low = 80,
  high = 95,
): UsageBudgetState["threshold_state"] {
  const value = Number(utilizationPercent);
  if (value >= 100) return "exhausted";
  if (value >= high) return "critical";
  if (value >= low) return "warning";
  return "normal";
}
