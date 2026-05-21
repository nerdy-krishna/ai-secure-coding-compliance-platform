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
    consolidated_title: string;
    status: string;
  }> | null;
  full_sankey_nodes?: Array<{ id: string; label: string }> | null;
  full_sankey_links?: Array<{ source: string; target: string; value: number }> | null;
}

export const debugService = {
  getFindingsDebug: async (scanId: string): Promise<ScanFindingsDebug> => {
    const { data } = await apiClient.get<ScanFindingsDebug>(
      `/scans/${encodeURIComponent(scanId)}/findings/debug`,
    );
    return data;
  },
};
