// Browser API client for the HttpOnly server-side session boundary.
import axios from "axios";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "/api/v1";

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true,
  maxRedirects: 0,
});

let csrfToken: string | null = null;
let browserSessionEstablished = false;
let tenantEntryGrant: string | null = null;
let tenantEntryExpiryTimer: ReturnType<typeof setTimeout> | null = null;

const SAFE_METHODS = new Set(["get", "head", "options"]);

export const SESSION_EXPIRED_EVENT = "sccap:session-expired";
export const TENANT_ENTRY_REQUIRED_EVENT = "sccap:tenant-entry-required";

export type AuthBoundaryAction =
  | "session-expired"
  | "tenant-entry-required";

type ApiErrorShape = {
  config?: { url?: string };
  response?: {
    status?: number;
    data?: { detail?: unknown };
  };
};

export function getAuthBoundaryAction(error: unknown): AuthBoundaryAction | null {
  const apiError = error as ApiErrorShape;
  const status = apiError.response?.status;
  if (status === 401) return "session-expired";
  if (status !== 403) return null;

  const detail = apiError.response?.data?.detail;
  if (detail === "Tenant entry required.") return "tenant-entry-required";
  if (
    detail === "Tenant entry denied." &&
    !apiError.config?.url?.endsWith("/admin/tenants/entry")
  ) {
    return "tenant-entry-required";
  }
  return null;
}

export function shouldRetryApiQuery(failureCount: number, error: unknown): boolean {
  const status = (error as ApiErrorShape).response?.status;
  if (typeof status === "number" && status >= 400 && status < 500) return false;
  return failureCount < 3;
}

export function setBrowserSessionEstablished(established: boolean): void {
  browserSessionEstablished = established;
  if (!established) {
    csrfToken = null;
    clearTenantEntryGrant();
  }
}

export function setTenantEntryGrant(token: string, expiresInSeconds: number): void {
  tenantEntryGrant = token;
  if (tenantEntryExpiryTimer) clearTimeout(tenantEntryExpiryTimer);
  tenantEntryExpiryTimer = setTimeout(
    () => clearTenantEntryGrant(),
    Math.max(0, expiresInSeconds * 1000),
  );
}

export function clearTenantEntryGrant(): void {
  tenantEntryGrant = null;
  if (tenantEntryExpiryTimer) clearTimeout(tenantEntryExpiryTimer);
  tenantEntryExpiryTimer = null;
}

apiClient.interceptors.request.use((config) => {
  const method = (config.method || "get").toLowerCase();
  if (!SAFE_METHODS.has(method) && csrfToken && config.headers) {
    config.headers["X-CSRF-Token"] = csrfToken;
  }
  if (tenantEntryGrant && config.headers) {
    config.headers["X-SCCAP-Tenant-Entry"] = tenantEntryGrant;
  }
  return config;
});

apiClient.interceptors.response.use(
  (response) => {
    const issuedCsrf = response.headers["x-csrf-token"];
    if (typeof issuedCsrf === "string" && issuedCsrf) {
      csrfToken = issuedCsrf;
    }
    return response;
  },
  (error) => {
    const action = getAuthBoundaryAction(error);
    if (action === "session-expired" && browserSessionEstablished) {
      browserSessionEstablished = false;
      csrfToken = null;
      clearTenantEntryGrant();
      window.dispatchEvent(new CustomEvent(SESSION_EXPIRED_EVENT));
    } else if (action === "tenant-entry-required" && browserSessionEstablished) {
      clearTenantEntryGrant();
      window.dispatchEvent(new CustomEvent(TENANT_ENTRY_REQUIRED_EVENT));
    }
    return Promise.reject(error);
  },
);

export default apiClient;
