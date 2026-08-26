import { AxiosError } from "axios";
import React, {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";

import apiClient, {
  SESSION_EXPIRED_EVENT,
  setBrowserSessionEstablished,
} from "../../shared/api/apiClient";
import { authService } from "../../shared/api/authService";
import {
  type SetupStatusResponse,
  type UserLoginData,
  type UserRead,
} from "../../shared/types/api";
import { AuthContext, type AuthContextType } from "./AuthContext";

const WARNING_LEAD_MS = 2 * 60 * 1000;
const USER_ACTIVITY_TOUCH_INTERVAL_MS = 5 * 60 * 1000;
let lastLoginAt = 0;

// Purge the retired browser bearer credential before the provider's first
// render. The API client never reads this key.
if (typeof window !== "undefined") window.localStorage.removeItem("accessToken");

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserRead | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [initialAuthChecked, setInitialAuthChecked] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isSetupCompleted, setIsSetupCompleted] = useState<boolean | null>(null);
  const [sessionWarning, setSessionWarning] = useState(false);
  const bootstrapStarted = useRef(false);
  const warningTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const expiryTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const absoluteDeadlineMs = useRef<number | null>(null);
  const idleDurationMs = useRef<number | null>(null);
  const lastServerActivityMs = useRef(0);

  const clearTimers = useCallback(() => {
    if (warningTimer.current) clearTimeout(warningTimer.current);
    if (expiryTimer.current) clearTimeout(expiryTimer.current);
    warningTimer.current = null;
    expiryTimer.current = null;
  }, []);

  const clearSession = useCallback(() => {
    clearTimers();
    absoluteDeadlineMs.current = null;
    idleDurationMs.current = null;
    setSessionWarning(false);
    setBrowserSessionEstablished(false);
    setUser(null);
  }, [clearTimers]);

  const scheduleDeadline = useCallback(
    (idleDeadlineMs: number, absoluteMs: number) => {
      clearTimers();
      absoluteDeadlineMs.current = absoluteMs;
      const deadline = Math.min(idleDeadlineMs, absoluteMs);
      const warningDelay = deadline - Date.now() - WARNING_LEAD_MS;
      const expiryDelay = deadline - Date.now();
      if (warningDelay <= 0) setSessionWarning(true);
      else warningTimer.current = setTimeout(() => setSessionWarning(true), warningDelay);
      expiryTimer.current = setTimeout(() => clearSession(), Math.max(0, expiryDelay));
    },
    [clearSession, clearTimers],
  );

  const loadSessionDeadline = useCallback(async () => {
    const sessions = await authService.listSessions();
    const current = sessions.find((session) => session.current);
    if (!current) throw new Error("Current browser session is missing");
    const idleDeadline = Date.parse(current.idle_expires_at);
    const absoluteDeadline = Date.parse(current.absolute_expires_at);
    const lastSeen = Date.parse(current.last_seen_at);
    idleDurationMs.current = Math.max(0, idleDeadline - lastSeen);
    lastServerActivityMs.current = Date.now();
    scheduleDeadline(idleDeadline, absoluteDeadline);
  }, [scheduleDeadline]);

  const establishBrowserSession = useCallback(async () => {
    const currentUser = await authService.getCurrentUser();
    setBrowserSessionEstablished(true);
    await authService.bootstrapCsrf();
    setUser(currentUser);
    await loadSessionDeadline();
    window.dispatchEvent(new CustomEvent("sccap:auth-changed"));
  }, [loadSessionDeadline]);

  const clearError = useCallback(() => setError(null), []);

  const checkSetupStatus = useCallback(async () => {
    try {
      const response = await apiClient.get<SetupStatusResponse>("/setup/status");
      setIsSetupCompleted(response.data.is_setup_completed);
    } catch (e) {
      console.error("AuthProvider: Failed to check setup status:", {
        message: (e as { message?: string })?.message,
        status: (e as { response?: { status?: number } })?.response?.status,
      });
      setIsSetupCompleted(null);
    }
  }, []);

  useEffect(() => {
    if (initialAuthChecked || bootstrapStarted.current) return;
    bootstrapStarted.current = true;
    const initializeAuth = async () => {
      setIsLoading(true);
      await checkSetupStatus();
      try {
        await establishBrowserSession();
      } catch (e) {
        if ((e as { response?: { status?: number } })?.response?.status !== 401) {
          console.error("AuthProvider: Session bootstrap failed:", {
            message: (e as { message?: string })?.message,
            status: (e as { response?: { status?: number } })?.response?.status,
          });
        }
        clearSession();
      } finally {
        setInitialAuthChecked(true);
        setIsLoading(false);
      }
    };
    void initializeAuth();
  }, [checkSetupStatus, clearSession, establishBrowserSession, initialAuthChecked]);

  useEffect(() => {
    const onExpired = () => clearSession();
    window.addEventListener(SESSION_EXPIRED_EVENT, onExpired);
    return () => {
      window.removeEventListener(SESSION_EXPIRED_EVENT, onExpired);
    };
  }, [clearSession]);

  // Coalesced browser activity touch: visible user activity can extend the idle
  // deadline, while the server-side absolute deadline remains unchanged.
  useEffect(() => {
    if (!user) return;
    const touch = () => {
      if (Date.now() - lastServerActivityMs.current < USER_ACTIVITY_TOUCH_INTERVAL_MS)
        return;
      lastServerActivityMs.current = Date.now();
      void authService
        .getCurrentUser()
        .then(() => {
          if (!idleDurationMs.current || !absoluteDeadlineMs.current) return;
          setSessionWarning(false);
          scheduleDeadline(
            Date.now() + idleDurationMs.current,
            absoluteDeadlineMs.current,
          );
        })
        .catch(() => {});
    };
    window.addEventListener("pointerdown", touch, { passive: true });
    window.addEventListener("keydown", touch);
    return () => {
      window.removeEventListener("pointerdown", touch);
      window.removeEventListener("keydown", touch);
    };
  }, [scheduleDeadline, user]);

  const login = useCallback(
    async (credentials: UserLoginData) => {
      const now = Date.now();
      if (now - lastLoginAt < 1000) {
        setError("Please wait a moment before retrying.");
        throw new Error("Please wait a moment before retrying.");
      }
      lastLoginAt = now;
      if (
        !credentials.username ||
        credentials.username.length > 320 ||
        !credentials.password ||
        credentials.password.length > 256
      ) {
        setError("Invalid credentials format");
        throw new Error("client validation");
      }

      setIsLoading(true);
      setError(null);
      try {
        await authService.loginUser(credentials);
        await establishBrowserSession();
      } catch (err: unknown) {
        console.error("AuthProvider: Login failed:", {
          message: (err as { message?: string })?.message,
          status: (err as { response?: { status?: number } })?.response?.status,
        });
        let errorMessage = "Login failed. Please check your username and password.";
        if (err instanceof AxiosError && err.response?.data?.detail) {
          const sanitise = (value: string) => value.replace(/[\r\n]/g, " ");
          errorMessage =
            typeof err.response.data.detail === "string"
              ? sanitise(err.response.data.detail)
              : JSON.stringify(err.response.data.detail);
        }
        setError(errorMessage);
        clearSession();
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    [clearSession, establishBrowserSession],
  );

  const completeBrowserLogin = useCallback(async () => {
    setIsLoading(true);
    try {
      await establishBrowserSession();
    } finally {
      setIsLoading(false);
    }
  }, [establishBrowserSession]);

  const logout = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      if (user) await authService.logoutUser();
    } catch (err: unknown) {
      console.error("AuthProvider: API logout failed; clearing local state:", {
        message: (err as { message?: string })?.message,
        status: (err as { response?: { status?: number } })?.response?.status,
      });
    } finally {
      clearSession();
      setIsLoading(false);
      window.dispatchEvent(new CustomEvent("sccap:auth-changed"));
    }
  }, [clearSession, user]);

  const stayActive = useCallback(async () => {
    try {
      await authService.getCurrentUser();
      await loadSessionDeadline();
      setSessionWarning(false);
    } catch {
      clearSession();
    }
  }, [clearSession, loadSessionDeadline]);

  const contextValue: AuthContextType = {
    user,
    isAuthenticated: user !== null,
    isLoading,
    initialAuthChecked,
    isSetupCompleted,
    error,
    login,
    completeBrowserLogin,
    logout,
    clearError,
    checkSetupStatus,
  };

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
      {sessionWarning && user && (
        <div className="session-warning-backdrop" role="presentation">
          <section
            className="surface session-warning-dialog"
            role="alertdialog"
            aria-modal="true"
            aria-labelledby="session-warning-title"
          >
            <h2 id="session-warning-title">Your session is ending soon</h2>
            <p>
              Save any unsaved work now. Activity can extend the inactivity
              deadline, but the overall sign-in limit cannot be extended.
            </p>
            <div className="session-warning-actions">
              <button className="sccap-btn" type="button" onClick={() => void logout()}>
                Sign out
              </button>
              <button
                className="sccap-btn sccap-btn-primary"
                type="button"
                onClick={() => void stayActive()}
              >
                Stay active
              </button>
            </div>
          </section>
        </div>
      )}
    </AuthContext.Provider>
  );
};
