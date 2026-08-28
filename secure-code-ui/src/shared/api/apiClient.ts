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

const SAFE_METHODS = new Set(["get", "head", "options"]);

export const SESSION_EXPIRED_EVENT = "sccap:session-expired";
export type AuthBoundaryAction = "session-expired";

type ApiErrorShape = {
  config?: {
    url?: string;
  };
  response?: {
    status?: number;
    data?: { detail?: unknown };
  };
};

export function getAuthBoundaryAction(error: unknown): AuthBoundaryAction | null {
  const apiError = error as ApiErrorShape;
  const status = apiError.response?.status;
  if (status === 401) return "session-expired";
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
  }
}

apiClient.interceptors.request.use((config) => {
  const method = (config.method || "get").toLowerCase();
  if (!SAFE_METHODS.has(method) && csrfToken && config.headers) {
    config.headers["X-CSRF-Token"] = csrfToken;
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
      window.dispatchEvent(new CustomEvent(SESSION_EXPIRED_EVENT));
    }
    return Promise.reject(error);
  },
);

export default apiClient;
