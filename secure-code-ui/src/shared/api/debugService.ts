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
}

export const debugService = {
  getFindingsDebug: async (scanId: string): Promise<ScanFindingsDebug> => {
    const { data } = await apiClient.get<ScanFindingsDebug>(
      `/scans/${encodeURIComponent(scanId)}/findings/debug`,
    );
    return data;
  },
};
