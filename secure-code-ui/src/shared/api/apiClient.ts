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

export function setBrowserSessionEstablished(established: boolean): void {
  browserSessionEstablished = established;
  if (!established) csrfToken = null;
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
    if (error.response?.status === 401 && browserSessionEstablished) {
      browserSessionEstablished = false;
      csrfToken = null;
      window.dispatchEvent(new CustomEvent("sccap:session-expired"));
    }
    return Promise.reject(error);
  },
);

export default apiClient;
