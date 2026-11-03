// secure-code-ui/src/shared/api/assetsService.ts
//
// Asset inventory and CVE applicability.
//
// The inventory is the authorisation boundary: an in-scope asset is one whose hosts
// may be fingerprinted and probed. Verdicts always carry a basis — declared (a
// dependency version), observed (a banner) or probe (a check that was actually run)
// — so the UI can show how much an answer is worth instead of a bare yes.

import apiClient from "./apiClient";

export type AssetKind =
  | "web_app"
  | "api"
  | "host"
  | "service"
  | "repo"
  | "vm"
  | "container"
  | "k8s"
  | "database"
  | "firewall"
  | "network"
  | "cloud";

export type TechCategory =
  | "os"
  | "database"
  | "web"
  | "container"
  | "orchestrator"
  | "network"
  | "library"
  | "other";
export type Verdict = "applicable" | "not_applicable" | "undetermined";
export type Basis = "declared" | "observed" | "probe";

export interface Asset {
  id: string;
  name: string;
  kind: AssetKind;
  description: string | null;
  owner: string | null;
  environment: string | null;
  in_scope: boolean;
  authorization_basis: string | null;
  created_at: string | null;
  services?: number;
  dependencies?: number;
  technologies?: number;
}

export interface AssetService {
  id: string;
  host: string;
  port: number | null;
  protocol: string;
  path: string | null;
  product: string | null;
  version: string | null;
  banner: string | null;
  source: string;
  confidence: string;
  last_seen: string | null;
}

export interface AssetDependency {
  id: string;
  ecosystem: string;
  package: string;
  version: string | null;
  direct: boolean;
  source: string;
}

export interface AssetTechnology {
  id: string;
  product: string;
  version: string | null;
  category: TechCategory;
  source: string;
  confidence: string;
}

export interface AssetDetail extends Omit<Asset, "services" | "dependencies" | "technologies"> {
  services: AssetService[];
  dependencies: AssetDependency[];
  technologies: AssetTechnology[];
}

export interface CorpusStats {
  cves: number;
  kev: number;
  affected_ranges: number;
  dependencies: number;
  services: number;
}

export interface CveVerdict {
  id: string;
  asset_id: string;
  asset_name: string;
  cve_id: string;
  title: string;
  cvss_score: number | null;
  severity: string | null;
  kev: boolean;
  verdict: Verdict;
  confidence: string;
  basis: Basis;
  reason: string | null;
  evidence: Record<string, unknown> | null;
  probe: {
    plan?: { reasoning?: string; checks?: Array<{ method: string; url: string; decides: string }> };
    observations?: Array<{ n: number; url?: string; status?: number; body?: string; error?: string }>;
    deciding_check?: number | null;
  } | null;
  checked_at: string | null;
}

export async function listAssets(): Promise<{ items: Asset[]; corpus: CorpusStats }> {
  const { data } = await apiClient.get<{ items: Asset[]; corpus: CorpusStats }>("/assets");
  return data;
}

export async function createAsset(input: {
  name: string;
  kind: AssetKind;
  description?: string | null;
  owner?: string | null;
  environment?: string | null;
  in_scope: boolean;
  authorization_basis?: string | null;
}): Promise<Asset> {
  const { data } = await apiClient.post<Asset>("/assets", input);
  return data;
}

export async function getAsset(assetId: string): Promise<AssetDetail> {
  const { data } = await apiClient.get<AssetDetail>(`/assets/${assetId}`);
  return data;
}

export async function deleteAsset(assetId: string): Promise<void> {
  await apiClient.delete(`/assets/${assetId}`);
}

export async function addService(
  assetId: string,
  input: {
    host: string;
    port?: number | null;
    protocol?: string;
    path?: string | null;
    product?: string | null;
    version?: string | null;
    banner?: string | null;
    source?: string;
    confidence?: "exact" | "heuristic";
  },
): Promise<AssetService> {
  const { data } = await apiClient.post<AssetService>(`/assets/${assetId}/services`, input);
  return data;
}

export async function addTechnology(
  assetId: string,
  input: { product: string; version?: string | null; category?: TechCategory; confidence?: "exact" | "heuristic" },
): Promise<AssetTechnology> {
  const { data } = await apiClient.post<AssetTechnology>(
    `/assets/${assetId}/technologies`,
    input,
  );
  return data;
}

/** Probe the inventory and store what each asset is. `rescan` refreshes known ones. */
export async function probeInventory(input: {
  asset_ids?: string[] | null;
  rescan?: boolean;
}): Promise<{
  assets_probed: number;
  endpoints_probed: number;
  fingerprints_found: number;
  products: string[];
  note?: string;
}> {
  const { data } = await apiClient.post("/assets/probe", input);
  return data;
}

export async function addDependencies(
  assetId: string,
  packages: Array<{ ecosystem: string; package: string; version?: string | null; direct?: boolean }>,
  scanId?: string | null,
): Promise<{ stored: number }> {
  const { data } = await apiClient.post<{ stored: number }>(`/assets/${assetId}/dependencies`, {
    packages,
    scan_id: scanId ?? null,
  });
  return data;
}

export async function checkCves(input: {
  cve_ids?: string[] | null;
  asset_ids?: string[] | null;
  verify: boolean;
  /** Fingerprint assets that have no recorded product/version first. */
  scan?: boolean;
  max_verifications?: number;
}): Promise<{
  scanned: boolean;
  assets_probed?: number;
  endpoints_probed?: number;
  fingerprints_found?: number;
  products?: string[];
  /** CVE ids that are not in the local corpus, so nothing could match them. */
  unknown_cves?: string[];
  matched: number;
  applicable: number;
  undetermined: number;
  not_applicable: number;
  verified: number;
  verification_errors: number;
}> {
  const { data } = await apiClient.post("/cve/check", input);
  return data;
}

export async function listVerdicts(params: {
  assetId?: string;
  cveId?: string;
  verdict?: Verdict;
}): Promise<CveVerdict[]> {
  const { data } = await apiClient.get<{ items: CveVerdict[] }>("/cve/verdicts", {
    params: {
      asset_id: params.assetId,
      cve_id: params.cveId,
      verdict: params.verdict,
    },
  });
  return data.items;
}

export async function verifyVerdict(verdictId: string): Promise<{
  verdict: Verdict;
  confidence: string;
  reason: string;
  checks: number;
}> {
  const { data } = await apiClient.post(`/cve/verdicts/${verdictId}/verify`);
  return data;
}

export async function corpusStats(): Promise<CorpusStats> {
  const { data } = await apiClient.get<CorpusStats>("/cve/corpus");
  return data;
}

export async function importCorpus(
  kind: "nvd" | "osv" | "kev",
  file: File,
): Promise<Record<string, number>> {
  const form = new FormData();
  form.append("file", file);
  const { data } = await apiClient.post<Record<string, number>>(
    `/cve/import?kind=${kind}`,
    form,
    { headers: { "Content-Type": "multipart/form-data" } },
  );
  return data;
}

export async function sweepInventory(input: {
  asset_ids?: string[] | null;
  cve_ids?: string[] | null;
  verify: boolean;
}): Promise<{
  assets: number;
  endpoints_fingerprinted: number;
  services_updated: number;
  matched: number;
  applicable: number;
  undetermined: number;
  verified: number;
}> {
  const { data } = await apiClient.post("/assets/sweep", input);
  return data;
}

/** The stored Nuclei-style detection check for a CVE. */
export async function getCveCheck(
  cveId: string,
): Promise<{ cve_id: string; template: string; source: string; created_at: string | null } | null> {
  try {
    const { data } = await apiClient.get(`/cve/${cveId}/check`);
    return data;
  } catch {
    return null;
  }
}

/** Store a check for a CVE, or have one designed and validated. */
export async function putCveCheck(
  cveId: string,
  template?: string,
): Promise<{ cve_id: string; stored: boolean; source?: string }> {
  const { data } = await apiClient.post(`/cve/${cveId}/check`, { template: template ?? null });
  return data;
}
