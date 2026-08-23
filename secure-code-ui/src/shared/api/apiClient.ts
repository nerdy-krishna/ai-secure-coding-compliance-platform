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
    if (error.response?.status === 401 && browserSessionEstablished) {
      browserSessionEstablished = false;
      csrfToken = null;
      clearTenantEntryGrant();
      window.dispatchEvent(new CustomEvent("sccap:session-expired"));
    }
    return Promise.reject(error);
  },
);

export default apiClient;
