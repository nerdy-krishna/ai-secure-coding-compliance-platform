// secure-code-ui/src/shared/api/debugService.ts

import apiClient from "./apiClient";
import type { Finding } from "../types/api";

export interface SankeyNode {
  id: string;
  label: string;
}

export interface SankeyLink {
  source: string;
  target: string;
  value: number;
}

export interface ScanFindingsDebug {
  sast_findings: Finding[];
  raw_llm_findings: Finding[];
  consolidated_findings: Finding[];
  sankey_nodes: SankeyNode[];
  sankey_links: SankeyLink[];
  source_groups: Record<string, number>;
  severity_groups: Record<string, number>;
  cwe_groups: Record<string, number>;
  agent_groups: Record<string, number>;
  flow_map?: Array<{
    raw_title: string;
    raw_source: string;
    raw_severity: string;
    raw_cwe?: string | null;
    raw_line?: number | null;
    consolidated_title: string;
    status: string;
  }> | null;
  full_sankey_nodes?: Array<{ id: string; label: string }> | null;
  full_sankey_links?: Array<{ source: string; target: string; value: number }> | null;
}

export interface FindingFixCandidate {
  candidate_id: string;
  raw_finding_id: string;
  canonical_finding_id?: string | null;
  source_snapshot_hash: string;
  anchor_fingerprint: string;
  patch_fingerprint: string;
  resolved_range?: {
    start_byte: number; end_byte: number;
    start_line: number; start_column: number;
    end_line: number; end_column: number;
  } | null;
  context_fingerprint?: string | null;
  patch_hunk_id?: string | null;
  applicability_status: string;
  language?: string | null;
  symbol?: string | null;
  required_imports: string[];
  required_dependencies: string[];
  configuration_changes: string[];
  migration_changes: string[];
  required_commands: string[];
  manual_steps: string[];
  file_path: string;
  line_number: number;
  suggestion: { description?: string; original_snippet?: string; code?: string };
  disposition: "pending" | "selected" | "alternative" | "duplicate" | "conflict" | "rejected";
  decision_reason?: string | null;
  contributing_agents: string[];
  contributing_models: string[];
  validation_status: "not_run" | "passed" | "failed";
  is_applied: boolean;
}

export const debugService = {
  getFindingsDebug: async (scanId: string): Promise<ScanFindingsDebug> => {
    const { data } = await apiClient.get<ScanFindingsDebug>(
      `/scans/${encodeURIComponent(scanId)}/findings/debug`,
    );
    return data;
  },

  getFindingLineage: async (
    scanId: string,
    expandedNodeIds: string[] = [],
    focusedNodeId?: string | null,
    maxNodes = 250,
    filters?: Record<string, string[]> | null,
  ): Promise<{
    nodes: Array<{
      id: string; type: string; label: string; column: number;
      count: number; expandable: boolean; expanded: boolean;
      badges: Array<Record<string, unknown>>;
    }>;
    edges: Array<{ id: string; source: string; target: string; value: number }>;
    lineage_quality: string;
    warnings: string[];
    available_expansions: Record<string, number>;
    fix_candidates: FindingFixCandidate[];
  }> => {
    const { data } = await apiClient.post(
      `/scans/${encodeURIComponent(scanId)}/finding-lineage`,
      {
        expanded_node_ids: expandedNodeIds,
        focused_node_id: focusedNodeId ?? null,
        filters: filters ?? null,
        max_nodes: maxNodes,
      },
    );
    return data;
  },
};
