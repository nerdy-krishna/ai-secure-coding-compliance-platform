import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React from "react";
import {
  Navigate,
  Outlet,
  Route,
  BrowserRouter as Router,
  Routes,
} from "react-router-dom";
import { useAuth } from "../shared/hooks/useAuth";
import { AuthProvider } from "./providers/AuthProvider";
import { ToastProvider } from "../shared/ui/Toast";

import LLMSettingsPage from "../features/admin-settings/components/LLMSettingsPage";
import AppearanceSettingsPage from "../pages/account/AppearanceSettingsPage";
import DashboardPage from "../pages/account/DashboardPage";
import SecuritySettingsPage from "../pages/account/SecuritySettingsPage";
import SubmissionHistoryPage from "../pages/account/SubmissionHistoryPage";
import AdminFindingsPage from "../pages/admin/AdminFindingsPage";
import SystemConfigTab from "../pages/admin/SystemConfigTab";
import UserManagementTab from "../pages/admin/UserManagement";
import UserGroupsPage from "../pages/admin/UserGroupsPage";
import SMTPSettingsTab from "../pages/admin/SMTPSettingsTab";
import AgentManagementPage from "../pages/admin/AgentManagementPage";
import FrameworkManagementPage from "../pages/admin/FrameworkManagementPage";
import PromptManagementPage from "../pages/admin/PromptManagementPage";
import LlmLogViewerPage from "../pages/analysis/LlmLogViewerPage";
import ProjectDetailPage from "../pages/analysis/ProjectDetailPage";
import ProjectsPage from "../pages/analysis/ProjectsPage";
import ResultsPage from "../pages/analysis/ResultsPage";
import LoginPage from "../pages/auth/LoginPage";
import SsoCallbackPage from "../pages/auth/SsoCallbackPage";
import SsoProvidersPage from "../pages/admin/SsoProvidersPage";
import SsoAuditPage from "../pages/admin/SsoAuditPage";
import ScimTokensPage from "../pages/admin/ScimTokensPage";
import TenantsPage from "../pages/admin/TenantsPage";
import SecurityAdvisorPage from "../pages/chat/SecurityAdvisorPage";
import CompliancePage from "../pages/compliance/CompliancePage";
import SubmitPage from "../pages/submission/SubmitPage";
import ScanRunningPage from "../pages/submission/ScanRunningPage";
import SetupPage from "../pages/setup/SetupPage";
import AuthLayout from "../widgets/AuthLayout";
import DashboardLayout from "../widgets/DashboardLayout";

const NotFoundPage: React.FC = () => (
  <div style={{ textAlign: "center", marginTop: "50px", padding: "20px" }}>
    <h1>404 - Page Not Found </h1>
    <p> Sorry, the page you are looking for does not exist.</p>
    <button
      onClick={() => window.history.back()}
      style={{ padding: "10px 15px", marginTop: "15px", cursor: "pointer" }}
    >
      Go Back
    </button>
  </div>
);

const LoadingScreen: React.FC = () => (
  <div
    style={{
      display: "flex",
      justifyContent: "center",
      alignItems: "center",
      height: "100vh",
      flexDirection: "column",
    }}
  >
    <h2>Connecting to Services...</h2>
    <p> Please wait while SCCAP is starting up.</p>
  </div>
);

import ForgotPasswordPage from "../features/authentication/components/ForgotPasswordPage";
import ResetPasswordPage from "../features/authentication/components/ResetPasswordPage";

type RouteRequirement =
  | "auth" // Authenticated user → renders inside DashboardLayout.
  | "unauth" // Unauthenticated only (login / forgot-password) → AuthLayout.
  | "superuser" // Authenticated + is_superuser → DashboardLayout.
  | "root-redirect"; // No render; redirect based on auth state.

interface RouteGuardProps {
  requires: RouteRequirement;
}

/**
 * Single route guard consolidating the four copies this file had
 * (protected / auth-only / root / superuser). All variants share:
 *  - the same "is auth/setup state resolved yet?" loading gate, and
 *  - the same "setup not completed → /setup" forced redirect.
 * The `requires` prop selects the post-setup-gate behavior.
 */
const RouteGuard: React.FC<RouteGuardProps> = ({ requires }) => {
  const { accessToken, user, initialAuthChecked, isLoading, isSetupCompleted } =
    useAuth();

  if (!initialAuthChecked || isLoading || isSetupCompleted === null) {
    return <LoadingScreen />;
  }

  if (isSetupCompleted === false) {
    return <Navigate to="/setup" replace />;
  }

  if (requires === "root-redirect") {
    return accessToken ? (
      <Navigate to="/account/dashboard" replace />
    ) : (
      <Navigate to="/login" replace />
    );
  }

  if (requires === "unauth") {
    return accessToken ? (
      <Navigate to="/" replace />
    ) : (
      <AuthLayout>
        <Outlet />
      </AuthLayout>
    );
  }

  // Both "auth" and "superuser" need a token.
  if (!accessToken) {
    return <Navigate to="/login" replace />;
  }

  if (requires === "superuser" && !user?.is_superuser) {
    return <Navigate to="/account/dashboard" replace />;
  }

  return (
    <DashboardLayout>
      <Outlet />
    </DashboardLayout>
  );
};

function AppContent() {
  return (
    <Router>
      <Routes>
        <Route element={<RouteGuard requires="unauth" />}>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/forgot-password" element={<ForgotPasswordPage />} />
          {/* SSO callback landing — gated as "unauth" so the user lands here
              after the IdP redirect (no token in localStorage yet); the
              page itself stores the token from the URL fragment, then
              navigates to /analysis/results. */}
          <Route path="/auth/sso/complete" element={<SsoCallbackPage />} />
          <Route path="/reset-password" element={<ResetPasswordPage />} />
        </Route>

        {/* Setup Route */}
        <Route path="/setup" element={<SetupPage />} />

        <Route element={<RouteGuard requires="auth" />}>
          <Route path="/account/dashboard" element={<DashboardPage />} />
          <Route path="/submission/submit" element={<SubmitPage />} />
          <Route
            path="/analysis/scanning/:scanId"
            element={<ScanRunningPage />}
          />
          <Route path="/analysis/results" element={<ProjectsPage />} />
          <Route
            path="/analysis/projects/:projectId"
            element={<ProjectDetailPage />}
          />
          <Route path="/analysis/results/:scanId" element={<ResultsPage />} />
          <Route
            path="/scans/:scanId/llm-logs"
            element={<LlmLogViewerPage />}
          />
          <Route path="/advisor" element={<SecurityAdvisorPage />} />
          <Route path="/compliance" element={<CompliancePage />} />
          <Route path="/account/history" element={<SubmissionHistoryPage />} />
          <Route
            path="/account/settings/appearance"
            element={<AppearanceSettingsPage />}
          />
          <Route
            path="/account/settings/security"
            element={<SecuritySettingsPage />}
          />
        </Route>

        <Route element={<RouteGuard requires="superuser" />}>
          <Route path="/admin/system" element={<SystemConfigTab />} />
          <Route path="/admin/users" element={<UserManagementTab />} />
          <Route path="/admin/user-groups" element={<UserGroupsPage />} />
          <Route path="/admin/findings" element={<AdminFindingsPage />} />
          <Route path="/admin/appearance" element={<AppearanceSettingsPage />} />
          <Route path="/admin/smtp" element={<SMTPSettingsTab />} />
          <Route path="/admin/sso/providers" element={<SsoProvidersPage />} />
          <Route path="/admin/sso/audit" element={<SsoAuditPage />} />
          <Route path="/admin/scim/tokens" element={<ScimTokensPage />} />
          <Route path="/admin/tenants" element={<TenantsPage />} />
          <Route path="/account/settings/llm" element={<LLMSettingsPage />} />
          <Route path="/admin/agents" element={<AgentManagementPage />} />
          <Route
            path="/admin/frameworks"
            element={<FrameworkManagementPage />}
          />
          <Route path="/admin/prompts" element={<PromptManagementPage />} />
          {/* /admin/rag has been merged into /compliance; redirect any
              bookmarks and the ?framework=…&action=git-ingest deep-link
              (now unused — the Compliance page handles ingestion inline). */}
          <Route
            path="/admin/rag"
            element={<Navigate to="/compliance" replace />}
          />
        </Route>

        <Route path="/" element={<RouteGuard requires="root-redirect" />} />
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </Router>
  );
}

const queryClient = new QueryClient();

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <AuthProvider>
          <AppContent />
        </AuthProvider>
      </ToastProvider>
    </QueryClientProvider>
  );
}

export default App;
