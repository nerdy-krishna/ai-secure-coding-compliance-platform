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
import { FeatureProvider } from "./providers/FeatureProvider";
import { useFeatures } from "../shared/hooks/useFeatures";
import { ToastProvider } from "../shared/ui/Toast";

import LLMSettingsPage from "../features/admin-settings/components/LLMSettingsPage";
import AppearanceSettingsPage from "../pages/account/AppearanceSettingsPage";
import DashboardPage from "../pages/account/DashboardPage";
import SecuritySettingsPage from "../pages/account/SecuritySettingsPage";
import SubmissionHistoryPage from "../pages/account/SubmissionHistoryPage";
import AdminFindingsPage from "../pages/admin/AdminFindingsPage";
import FeaturesPage from "../pages/admin/FeaturesPage";
import SystemConfigTab from "../pages/admin/SystemConfigTab";
import UserManagementTab from "../pages/admin/UserManagement";
import UserGroupsPage from "../pages/admin/UserGroupsPage";
import SMTPSettingsTab from "../pages/admin/SMTPSettingsTab";
import AgentManagementPage from "../pages/admin/AgentManagementPage";
import FrameworkManagementPage from "../pages/admin/FrameworkManagementPage";
import PromptManagementPage from "../pages/admin/PromptManagementPage";
import { ScanDiagnosticsPage } from "../pages/analysis/ScanDiagnosticsPage";
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
import { ScanWatcher } from "../features/scans/ScanWatcher";
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
      <ScanWatcher />
      <Outlet />
    </DashboardLayout>
  );
};

/**
 * Route guard for a feature-flagged area (modular setup). Redirects to the
 * dashboard when the named feature is disabled. The backend already 404s the
 * disabled feature's endpoints; this keeps the SPA from rendering a dead page.
 */
const FeatureRoute: React.FC<{ feature: string }> = ({ feature }) => {
  const { isFeatureEnabled, featuresLoading } = useFeatures();

  if (featuresLoading) {
    return <LoadingScreen />;
  }
  if (!isFeatureEnabled(feature)) {
    return <Navigate to="/account/dashboard" replace />;
  }
  return <Outlet />;
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
          {/* Scan diagnostics reads DB events — no container-backend needed;
              deliberately NOT gated behind log_stack (which only gates
              the Grafana/Loki/Fluentd stack). */}
          <Route
            path="/scans/:scanId/diagnostics"
            element={<ScanDiagnosticsPage />}
          />
          <Route element={<FeatureRoute feature="chat" />}>
            <Route path="/advisor" element={<SecurityAdvisorPage />} />
          </Route>
          <Route element={<FeatureRoute feature="compliance" />}>
            <Route path="/compliance" element={<CompliancePage />} />
          </Route>
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
          <Route path="/admin/features" element={<FeaturesPage />} />
          <Route path="/admin/findings" element={<AdminFindingsPage />} />
          <Route path="/admin/appearance" element={<AppearanceSettingsPage />} />
          <Route path="/account/settings/llm" element={<LLMSettingsPage />} />
          <Route element={<FeatureRoute feature="multi_user" />}>
            <Route path="/admin/users" element={<UserManagementTab />} />
          </Route>
          <Route element={<FeatureRoute feature="user_groups" />}>
            <Route path="/admin/user-groups" element={<UserGroupsPage />} />
          </Route>
          <Route element={<FeatureRoute feature="email" />}>
            <Route path="/admin/smtp" element={<SMTPSettingsTab />} />
          </Route>
          <Route element={<FeatureRoute feature="sso" />}>
            <Route path="/admin/sso/providers" element={<SsoProvidersPage />} />
            <Route path="/admin/sso/audit" element={<SsoAuditPage />} />
          </Route>
          <Route element={<FeatureRoute feature="scim" />}>
            <Route path="/admin/scim/tokens" element={<ScimTokensPage />} />
          </Route>
          <Route element={<FeatureRoute feature="multi_tenant" />}>
            <Route path="/admin/tenants" element={<TenantsPage />} />
          </Route>
          <Route element={<FeatureRoute feature="admin_authoring" />}>
            <Route path="/admin/agents" element={<AgentManagementPage />} />
            <Route
              path="/admin/frameworks"
              element={<FrameworkManagementPage />}
            />
            <Route path="/admin/prompts" element={<PromptManagementPage />} />
          </Route>
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
          <FeatureProvider>
            <AppContent />
          </FeatureProvider>
        </AuthProvider>
      </ToastProvider>
    </QueryClientProvider>
  );
}

export default App;
