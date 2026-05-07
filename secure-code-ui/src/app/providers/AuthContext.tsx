// secure-code-ui/src/app/providers/AuthContext.tsx
import { createContext } from "react";
import {
  type UserLoginData,
  type UserRead,
  type UserRegisterData,
} from "../../shared/types/api";
export interface AuthContextType {
  user: UserRead | null;
  accessToken: string | null;
  isLoading: boolean;
  initialAuthChecked: boolean;
  error: string | null;
  login: (credentials: UserLoginData) => Promise<void>;
  /**
   * Drop an already-issued access token into the session as if the user
   * had just signed in (passkey, SSO callback, etc.). Mirrors the
   * post-credential-success path of `login` without going through the
   * password endpoint.
   */
  loginWithAccessToken: (accessToken: string) => void;
  register: (credentials: UserRegisterData) => Promise<UserRead>;
  logout: () => Promise<void>;
  clearError: () => void;
  isSetupCompleted: boolean | null;
  checkSetupStatus: () => Promise<void>;
}

export const AuthContext = createContext<AuthContextType | undefined>(
  undefined,
);
