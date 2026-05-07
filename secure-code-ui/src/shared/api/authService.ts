// secure-code-ui/src/shared/api/authService.ts
import apiClient from "../../shared/api/apiClient";
import type { components } from "../types/api-generated";
import {
  type TokenResponse,
  type UserLoginData,
  type UserRead,
  type UserRegisterData,
} from "../types/api";

type AdminUserCreate = components["schemas"]["AdminUserCreate"];

export interface AdminUserRead {
  id: number;
  email: string;
  is_active: boolean;
  is_superuser: boolean;
  is_verified: boolean;
}

export const authService = {
  // Login
  // FastAPI Users' /auth/login endpoint expects form data (username, password)
  // It returns an access_token and token_type.
  // The refresh token is set as an HttpOnly cookie.
  loginUser: async (
    loginData: UserLoginData,
  ): Promise<TokenResponse> => {
    // V02.2.1: client-side input bounds (server enforcement remains authoritative)
    if (typeof loginData.username !== "string" || loginData.username.length > 254)
      throw new Error("Invalid username");
    if (typeof loginData.password !== "string" || loginData.password.length < 8 || loginData.password.length > 256)
      throw new Error("Password must be 8-256 chars");
    const formData = new URLSearchParams();
    formData.append("username", loginData.username); // FastAPI Users uses 'username' which can be email
    formData.append("password", loginData.password);
    // Optional OAuth2 password flow parameters (usually not needed for simple user login)
    // if (loginData.grant_type) formData.append("grant_type", loginData.grant_type);
    // if (loginData.scope) formData.append("scope", loginData.scope);
    // if (loginData.client_id) formData.append("client_id", loginData.client_id);
    // if (loginData.client_secret) formData.append("client_secret", loginData.client_secret);
    const response = await apiClient.post("/auth/login", formData, {
      // CORRECTED PATH: relative to baseURL
      headers: {
        "Content-Type": "application/x-www-form-urlencoded", // Correct for this endpoint
      },
    });
    return response.data;
  },

  // Refresh Token
  refreshToken: async (): Promise<TokenResponse> => {
    // The refresh token is in an HttpOnly cookie, so the browser sends it automatically.
    // We just need to hit the refresh endpoint at the correct path.
    const response = await apiClient.post<TokenResponse>("/auth/refresh");
    return response.data;
  },

  // Register
  registerUser: async (
    registerData: UserRegisterData,
  ): Promise<UserRead> => {
    // V08.2.3 / V15.3.3: explicit payload prevents mass-assignment of privileged fields
    // (is_superuser, is_active, is_verified). Backend mass-assignment guards remain authoritative.
    const payload = { email: registerData.email, password: registerData.password };
    const response = await apiClient.post<UserRead>(
      "/auth/register", // CORRECT PATH: relative to baseURL
      payload,
    );
    return response.data;
  },

  // Get Current User
  getCurrentUser: async (): Promise<UserRead> => {
    const response = await apiClient.get<UserRead>("/users/me");
    // CORRECT PATH: relative to baseURL
    return response.data;
  },
  // Logout
  logoutUser: async (): Promise<unknown> => {
    // FastAPI Users /auth/logout
    const response = await apiClient.post("/auth/logout");
    return response.data;
  },

  forgotPassword: async (email: string): Promise<void> => {
    // V02.2.1: client-side email format and length check (server enforcement remains authoritative)
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || email.length > 254)
      throw new Error("Invalid email");
    await apiClient.post("/auth/forgot-password", { email });
  },

  resetPassword: async (token: string, password: string): Promise<void> => {
    // V02.2.1: client-side token and password bounds (server enforcement remains authoritative)
    if (typeof token !== "string" || token.length < 8 || token.length > 1024)
      throw new Error("Invalid reset token");
    if (typeof password !== "string" || password.length < 8 || password.length > 256)
      throw new Error("Password must be 8-256 chars");
    await apiClient.post("/auth/reset-password", { token, password });
  },

  adminCreateUser: async (userData: AdminUserCreate): Promise<UserRead> => {
    // V15.3.3: explicit payload prevents unintended mass-assignment; backend guards remain authoritative.
    // Password is generated server-side; admin only supplies email + privilege flags.
    const payload = {
      email: userData.email,
      is_superuser: userData.is_superuser,
      is_active: userData.is_active,
      is_verified: userData.is_verified,
    };
    const response = await apiClient.post<UserRead>("/admin/users", payload);
    return response.data;
  },

  adminListUsers: async (): Promise<AdminUserRead[]> => {
    const response = await apiClient.get<AdminUserRead[]>("/admin/users");
    return response.data;
  },

  adminUpdateUser: async (
    userId: number,
    data: { is_active?: boolean; is_superuser?: boolean; is_verified?: boolean },
  ): Promise<AdminUserRead> => {
    const response = await apiClient.patch<AdminUserRead>(`/admin/users/${userId}`, data);
    return response.data;
  },

  adminDeleteUser: async (userId: number): Promise<void> => {
    await apiClient.delete(`/admin/users/${userId}`);
  },
};
