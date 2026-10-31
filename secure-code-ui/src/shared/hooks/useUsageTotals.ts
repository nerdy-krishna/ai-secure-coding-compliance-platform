import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { usageService, type UsageFilters } from "../api/usageService";

export interface UsageTotalsView {
  input_tokens: number;
  output_tokens: number;
  total_tokens: number;
  cost_usd: number | null;
  requests: number;
}

/**
 * Token and cost totals for one operation kind over a window.
 *
 * The usage ledger is the single source of truth for spend, so every page that
 * shows a token or cost tile reads it here instead of inventing its own sum.
 */
export function useUsageTotals(
  operation_kind: "scan" | "pentest" | "chat" | "rag",
  days = 30,
): { data: UsageTotalsView; isLoading: boolean } {
  const filters: UsageFilters = useMemo(() => {
    const to = new Date();
    const from = new Date(to.getTime() - days * 24 * 60 * 60 * 1000);
    return {
      from_at: from.toISOString(),
      to_at: to.toISOString(),
      operation_kind,
    };
  }, [operation_kind, days]);

  const query = useQuery({
    queryKey: ["usage", "totals", operation_kind, days],
    queryFn: () => usageService.summary(filters),
    refetchInterval: 60_000,
  });

  const totals = query.data?.totals;
  // Exact and estimated buckets are disjoint: exact = priced from the provider
  // invoice, estimated = ledger price list. Their sum is what was spent.
  const cost = totals
    ? Number(totals.actual_cost ?? 0) + Number(totals.estimated_cost ?? 0)
    : null;

  return {
    data: {
      input_tokens: Number(totals?.input_tokens ?? 0),
      output_tokens: Number(totals?.output_tokens ?? 0),
      total_tokens: Number(totals?.total_tokens ?? 0),
      cost_usd: cost,
      requests: Number(totals?.requests ?? 0),
    },
    isLoading: query.isLoading,
  };
}
