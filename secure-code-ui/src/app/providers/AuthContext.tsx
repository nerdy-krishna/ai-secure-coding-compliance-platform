// secure-code-ui/src/app/providers/AuthContext.tsx
import { createContext } from "react";
import {
  type UserLoginData,
  type UserRead,
} from "../../shared/types/api";
export interface AuthContextType {
  user: UserRead | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  initialAuthChecked: boolean;
  error: string | null;
  login: (credentials: UserLoginData) => Promise<void>;
  completeBrowserLogin: () => Promise<void>;
  logout: () => Promise<void>;
  clearError: () => void;
  isSetupCompleted: boolean | null;
  checkSetupStatus: () => Promise<void>;
}

export const AuthContext = createContext<AuthContextType | undefined>(
  undefined,
);
