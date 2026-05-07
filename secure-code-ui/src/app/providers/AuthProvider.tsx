// secure-code-ui/src/app/providers/AuthProvider.tsx
import { AxiosError } from "axios";
import React, { useCallback, useEffect, useState, type ReactNode } from "react";
import apiClient, {
  cancelProactiveRefresh,
  scheduleProactiveRefresh,
} from "../../shared/api/apiClient";
import { authService } from "../../shared/api/authService";
import {
  type TokenResponse,
  type UserLoginData,
  type UserRead,
  type UserRegisterData,
  type SetupStatusResponse,
} from "../../shared/types/api";
import { AuthContext, type AuthContextType } from "./AuthContext";

// SECURITY (V15.1.5 dangerous functionality): JWT access token is held in localStorage to enable
// cross-tab silent refresh. This is XSS-recoverable; CSP + sanitised React rendering are the
// compensating controls. See .agent/threat-model.md row "client-token-storage" for the explicit
// risk acceptance.
const ACCESS_TOKEN_KEY = "accessToken";

// V02.4.1: Module-scoped timestamp to enforce a minimum 1-second interval between login attempts,
// providing client-side anti-automation defense in depth (server rate-limiting remains authoritative).
let lastLoginAt = 0;

export const AuthProvider: React.FC<{ children: ReactNode }> = ({
  children,
}) => {
  const [user, setUser] = useState<UserRead | null>(null);
  const [accessToken, setAccessToken] = useState<string | null>(
    localStorage.getItem(ACCESS_TOKEN_KEY),
  );
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [initialAuthChecked, setInitialAuthChecked] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [isSetupCompleted, setIsSetupCompleted] = useState<boolean | null>(
    null,
  );

  const clearError = useCallback(() => {
    setError(null);
  }, []);

  const checkSetupStatus = useCallback(async () => {
    try {
      const response =
        await apiClient.get<SetupStatusResponse>("/setup/status");
      setIsSetupCompleted(response.data.is_setup_completed);
    } catch (e) {
      // V16.2.5: Never log the raw axios error — it contains the Bearer token in request headers.
      console.error("AuthProvider: Failed to check setup status:", {
        message: (e as { message?: string })?.message,
        status: (e as { response?: { status?: number } })?.response?.status,
      });
      // Wait for backend services to come up instead of assuming setup is incomplete
      setIsSetupCompleted(null);
    }
  }, []);

  // Effect to synchronize the accessToken state with localStorage
  useEffect(() => {
    if (accessToken) {
      localStorage.setItem(ACCESS_TOKEN_KEY, accessToken);
    } else {
      localStorage.removeItem(ACCESS_TOKEN_KEY);
    }
  }, [accessToken]);

  // Effect to detect silent token refreshes performed by the apiClient interceptor.
  // The interceptor writes the new token directly to localStorage, so we listen
  // for 'storage' events and also poll for changes to keep React state in sync.
  useEffect(() => {
    // Cross-tab sync via the 'storage' event
    const handleStorageChange = (event: StorageEvent) => {
      if (event.key === ACCESS_TOKEN_KEY) {
        setAccessToken(event.newValue);
      }
    };
    window.addEventListener("storage", handleStorageChange);

    // Same-tab sync: the interceptor updates localStorage in the same tab,
    // which does NOT fire 'storage' events. Poll periodically to catch it.
    const intervalId = setInterval(() => {
      const storedToken = localStorage.getItem(ACCESS_TOKEN_KEY);
      setAccessToken((prev) => (storedToken !== prev ? storedToken : prev));
    }, 5000); // Check every 5 seconds

    return () => {
      window.removeEventListener("storage", handleStorageChange);
      clearInterval(intervalId);
    };
  }, []);

  const fetchAndSetUser = useCallback(async () => {
    if (!localStorage.getItem(ACCESS_TOKEN_KEY)) {
      setUser(null);
      return;
    }
    // V15.4.1: Capture the token value before the async call so we can guard against
    // a concurrent interceptor refresh clobbering a newer token in the catch path.
    const tokenAtRequestTime = localStorage.getItem(ACCESS_TOKEN_KEY);
    try {
      const response = await apiClient.get<UserRead>("/users/me");
      setUser(response.data);
    } catch (e) {
      // V16.2.5: Never log the raw axios error — it contains the Bearer token in request headers.
      console.error(
        "AuthProvider: Failed to fetch user (token likely invalid/expired):",
        {
          message: (e as { message?: string })?.message,
          status: (e as { response?: { status?: number } })?.response?.status,
        },
      );
      // V15.4.1: Only clear the token if it hasn't been replaced by a successful interceptor
      // refresh that ran concurrently — prevents a stale error from clobbering the new token.
      if (localStorage.getItem(ACCESS_TOKEN_KEY) === tokenAtRequestTime) {
        setUser(null);
        setAccessToken(null);
      }
    }
  }, []);

  // Effect to run on initial load to check for an existing session AND setup status
  useEffect(() => {
    const initializeAuth = async () => {
      setIsLoading(true);

      // Check setup status first
      await checkSetupStatus();

      if (accessToken) {
        // Arm the proactive refresh timer on app boot so a tab that
        // already has a valid token (resumed session) keeps it warm.
        scheduleProactiveRefresh(accessToken);
        await fetchAndSetUser();
      }
      setInitialAuthChecked(true);
      setIsLoading(false);
    };
    initializeAuth();
  }, [accessToken, fetchAndSetUser, checkSetupStatus]);

  const login = useCallback(async (credentials: UserLoginData) => {
    // V02.4.1: Enforce minimum 1-second interval between login attempts (client-side defense in depth).
    const now = Date.now();
    if (now - lastLoginAt < 1000) {
      setError("Please wait a moment before retrying.");
      throw new Error("Please wait a moment before retrying.");
    }
    lastLoginAt = now;

    // V02.2.1: Enforce non-empty and length bounds before sending credentials to the network.
    // 320 chars = RFC-5321 max email length; 4096 chars = generous upper bound on password length.
    if (
      !credentials.username ||
      credentials.username.length > 320 ||
      !credentials.password ||
      credentials.password.length > 4096
    ) {
      setError("Invalid credentials format");
      setIsLoading(false);
      throw new Error("client validation");
    }

    setIsLoading(true);
    setError(null);
    try {
      const response: TokenResponse = await authService.loginUser(credentials);
      localStorage.setItem("accessToken", response.access_token);
      setAccessToken(response.access_token);
      // Arm proactive refresh so the user doesn't see a 401 flash near
      // access-token expiry.
      scheduleProactiveRefresh(response.access_token);
    } catch (err: unknown) {
      // V16.2.5: Never log the raw axios error — it contains the Bearer token in request headers.
      console.error("AuthProvider: Login failed:", {
        message: (err as { message?: string })?.message,
        status: (err as { response?: { status?: number } })?.response?.status,
      });
      let errorMessage =
        "Login failed. Please check your username and password.";
      if (err instanceof AxiosError && err.response?.data?.detail) {
        // V16.4.1: Sanitise backend-supplied strings to prevent log-forgery via CRLF injection.
        const sanitise = (s: string) => s.replace(/[\r\n]/g, " ");
        errorMessage =
          typeof err.response.data.detail === "string"
            ? sanitise(err.response.data.detail)
            : JSON.stringify(err.response.data.detail);
      }
      setError(errorMessage);
      setAccessToken(null);
      setUser(null);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const register = useCallback(
    async (credentials: UserRegisterData): Promise<UserRead> => {
      setIsLoading(true);
      setError(null);
      try {
        return await authService.registerUser(credentials);
      } catch (err: unknown) {
        // V16.2.5: Never log the raw axios error — it contains the Bearer token in request headers.
        console.error("AuthProvider: Registration failed:", {
          message: (err as { message?: string })?.message,
          status: (err as { response?: { status?: number } })?.response?.status,
        });
        let errorMessage = "Registration failed. Please try again.";
        if (err instanceof AxiosError && err.response?.data?.detail) {
          // V16.4.1: Sanitise backend-supplied strings to prevent log-forgery via CRLF injection.
          const sanitise = (s: string) => s.replace(/[\r\n]/g, " ");
          errorMessage =
            typeof err.response.data.detail === "string"
              ? sanitise(err.response.data.detail)
              : "An unexpected error occurred.";
        }
        setError(errorMessage);
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    [],
  );

  const logout = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      if (accessToken) {
        await authService.logoutUser();
      }
    } catch (err: unknown) {
      // V16.2.5: Never log the raw axios error — it contains the Bearer token in request headers.
      console.error(
        "AuthProvider: API Logout failed but proceeding with client-side logout:",
        {
          message: (err as { message?: string })?.message,
          status: (err as { response?: { status?: number } })?.response?.status,
        },
      );
    } finally {
      cancelProactiveRefresh();
      setAccessToken(null);
      setUser(null);
      setIsLoading(false);
    }
  }, [accessToken]);

  const contextValue: AuthContextType = {
    user,
    accessToken,
    isLoading,
    initialAuthChecked,
    isSetupCompleted,
    error,
    login,
    register,
    logout,
    clearError,
    checkSetupStatus,
  };

  return (
    <AuthContext.Provider value={contextValue}>
      {" "}
      {children}{" "}
    </AuthContext.Provider>
  );
};
