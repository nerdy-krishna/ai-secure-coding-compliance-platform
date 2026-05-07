// secure-code-ui/src/shared/api/apiClient.ts
import axios from "axios";
import { authService } from "./authService";

// Get the API base URL from environment variables, fallback back to relative proxy path
const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "/api/v1";
// V15.3.2: Disable automatic redirects — all /api/v1 endpoints must respond with
// the final resource directly. A redirect could forward the Authorization header
// to an attacker-controlled origin. OAuth flows that require redirect-following
// must use a separate axios instance that does NOT carry the Authorization header.
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true, // Let Axios handle the Content-Type header per request
  maxRedirects: 0,
});

// Request Interceptor
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("accessToken");
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  },
);
// V15.4.1: Single-tab dedupe only. Safe because JS is single-threaded on the
// main event loop; do NOT import this module into a SharedWorker, ServiceWorker,
// or any other realm — refreshInFlight is per-realm state, so a cross-realm
// import would defeat the dedupe and risk cross-tab refresh-token races.
let refreshInFlight: Promise<string> | null = null;

// V02.4.1: Circuit breaker for the /auth/refresh endpoint. After 3 consecutive
// failures within any window, all refresh attempts are rejected immediately for
// 30 seconds. This is defense-in-depth alongside server-side rate limiting on
// /auth/refresh; it prevents a misbehaving client from hammering the endpoint.
let refreshFailureCount = 0;
let refreshOpenUntil = 0;

// Proactive refresh: schedule a silent refresh ~5 minutes before the access
// token expires so users don't experience a 401-flash near the boundary.
// The reactive 401 path remains as last-resort fallback (e.g. clock skew).
let proactiveRefreshTimer: ReturnType<typeof setTimeout> | null = null;
const PROACTIVE_LEAD_MS = 5 * 60 * 1000; // 5 min before expiry

function decodeJwtExpMs(token: string): number | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    // base64url → base64 → JSON
    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    const payload = JSON.parse(atob(padded)) as { exp?: number };
    if (typeof payload.exp !== "number") return null;
    return payload.exp * 1000;
  } catch {
    return null;
  }
}

export function cancelProactiveRefresh(): void {
  if (proactiveRefreshTimer !== null) {
    clearTimeout(proactiveRefreshTimer);
    proactiveRefreshTimer = null;
  }
}

export function scheduleProactiveRefresh(token: string | null | undefined): void {
  cancelProactiveRefresh();
  if (!token) return;
  const expMs = decodeJwtExpMs(token);
  if (expMs === null) return;
  const fireIn = expMs - Date.now() - PROACTIVE_LEAD_MS;
  // If the token is already past the lead window (or nearly expired), let the
  // 401 interceptor handle it. Don't fire a refresh from a stale schedule.
  if (fireIn <= 0) return;
  proactiveRefreshTimer = setTimeout(() => {
    refreshAccessToken().catch(() => {
      // Swallow: the 401 interceptor will retry the next real request,
      // and if refresh truly fails the user is bounced to /login there.
    });
  }, fireIn);
}

function refreshAccessToken(): Promise<string> {
  // Circuit breaker: reject immediately if the breaker is open
  if (Date.now() < refreshOpenUntil) {
    return Promise.reject(new Error("Token refresh circuit breaker open — too many consecutive failures."));
  }

  if (refreshInFlight) return refreshInFlight;
  refreshInFlight = authService
    .refreshToken()
    .then(({ access_token }) => {
      // Success: reset the circuit breaker failure count
      refreshFailureCount = 0;
      localStorage.setItem("accessToken", access_token);
      apiClient.defaults.headers.common["Authorization"] = `Bearer ${access_token}`;
      // Re-arm the proactive refresh timer for the new token's expiry.
      scheduleProactiveRefresh(access_token);
      return access_token;
    })
    .catch((err) => {
      // Failure: increment counter and open breaker after threshold
      refreshFailureCount += 1;
      if (refreshFailureCount >= 3) {
        refreshOpenUntil = Date.now() + 30_000;
        refreshFailureCount = 0;
      }
      return Promise.reject(err);
    })
    .finally(() => {
      refreshInFlight = null;
    });
  return refreshInFlight;
}

// Response Interceptor
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // 401s trigger a single shared refresh attempt; skip the refresh endpoint
    // itself to prevent infinite loops.
    const isRefreshRequest = originalRequest.url?.includes("/auth/refresh");
    if (error.response?.status === 401 && !originalRequest._retry && !isRefreshRequest) {
      originalRequest._retry = true;

      try {
        const access_token = await refreshAccessToken();
        originalRequest.headers["Authorization"] = `Bearer ${access_token}`;
        return apiClient(originalRequest);
      } catch (refreshError) {
        // V16.2.5: Log only safe fields — never the full axios error object, which
        // includes config.headers.Authorization (Bearer JWT) and the response body.
        const safeErr = refreshError as
          | { response?: { status?: unknown }; code?: unknown }
          | undefined;
        console.error("Session refresh failed, logging out.", {
          status: safeErr?.response?.status ?? "unknown",
          code: safeErr?.code ?? "unknown",
        });
        localStorage.removeItem("accessToken");
        window.location.href = "/login";
        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  },
);

export default apiClient;