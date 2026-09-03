import type { C13Filters, C13Resource, OwnerTuple } from "./types";

const normalizedFilters = (filters: C13Filters = {}) => ({
  cursor: filters.cursor ?? "",
  state: filters.state ?? "",
  kind: filters.kind ?? "",
  query: filters.query ?? "",
});

export const capability13Keys = {
  all: ["capability13"] as const,
  tenant: (tenantId: string) => ["capability13", tenantId] as const,
  engagements: (tenantId: string, filters: C13Filters = {}) =>
    ["capability13", tenantId, "engagements", normalizedFilters(filters)] as const,
  attempts: (tenantId: string, engagementId: string) =>
    ["capability13", tenantId, engagementId, "attempts"] as const,
  resourceFamily: (
    tenantId: string,
    owner: Pick<OwnerTuple, "engagement_id" | "attempt_id">,
    resource: C13Resource,
    generation: number,
  ) => ["capability13", tenantId, owner.engagement_id, owner.attempt_id, resource, generation] as const,
  resource: (
    tenantId: string,
    owner: Pick<OwnerTuple, "engagement_id" | "attempt_id">,
    resource: C13Resource,
    generation: number,
    filters: C13Filters = {},
  ) => [
    ...capability13Keys.resourceFamily(tenantId, owner, resource, generation),
    normalizedFilters(filters),
  ] as const,
};
