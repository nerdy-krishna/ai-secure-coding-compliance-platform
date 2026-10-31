// Client for GET /scans/{scan_id}/scanner-coverage — the per-file coverage manifest.
//
// Each entry is one (scanner, input) pair; the panel folds them back into one row
// per file so an operator can see whether a file was scanned, and if not, why.

import apiClient from "./apiClient";

export type CoverageStatus =
  | "planned"
  | "completed"
  | "clean"
  | "skipped"
  | "failed"
  | "timeout"
  | "unsupported"
  | "truncated";

export interface CoverageEntry {
  id: string;
  scanner_name: string;
  input_path: string;
  status: CoverageStatus;
  reason_code: string | null;
  reason: string | null;
  finding_count: number;
  details?: {
    role?: string;
    language?: string | null;
    input_bytes?: number;
    limit_bytes?: number;
    limit?: number;
    [key: string]: unknown;
  } | null;
}

export interface CoverageManifest {
  attempt_id: string;
  overall_status: "unavailable" | "complete" | "degraded";
  is_complete: boolean;
  counts: Record<string, number>;
  entries: CoverageEntry[];
}

export async function getScannerCoverage(scanId: string): Promise<CoverageManifest> {
  const { data } = await apiClient.get<CoverageManifest>(`/scans/${scanId}/scanner-coverage`);
  return data;
}


/** Raw findings that consolidation folded into one consolidated finding. */
export interface MergedFinding {
  id: number;
  title: string;
  severity?: string | null;
  file_path: string;
  line_number?: number | null;
  source?: string | null;
  corroborating_agents: string[];
}

export interface MergedFindings {
  scan_id: string;
  finding_id: number;
  raw_count: number;
  findings: MergedFinding[];
}

export async function getMergedFindings(
  scanId: string,
  findingId: number,
): Promise<MergedFindings> {
  const { data } = await apiClient.get<MergedFindings>(
    `/scans/${scanId}/findings/${findingId}/merged`,
  );
  return data;
}
