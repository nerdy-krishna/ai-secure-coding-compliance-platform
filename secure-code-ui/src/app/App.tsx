import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React, { Suspense } from "react";
import {
  Navigate,
  Outlet,
  Route,
  BrowserRouter as Router,
  Routes,
} from "react-router-dom";
import { useAuth } from "../shared/hooks/useAuth";
import { AuthProvider } from "./providers/AuthProvider";
import { ThemeProvider } from "./providers/ThemeProvider";
import { FeatureProvider } from "./providers/FeatureProvider";
import { useFeatures } from "../shared/hooks/useFeatures";
import { ToastProvider } from "../shared/ui/Toast";
import { hasAnyPermission } from "../shared/lib/permissions";
import { LoadingState } from "../shared/ui/AsyncState";
import { RouteErrorBoundary } from "../shared/ui/RouteErrorBoundary";
import { ScanWatcher } from "../features/scans/ScanWatcher";
import AuthLayout from "../widgets/AuthLayout";
import DashboardLayout from "../widgets/DashboardLayout";

// Each top-level screen is a separate async boundary. Keep the authenticated
// shell and ScanWatcher eager so route downloads never interrupt live scan
// event handling or diagnostics reconnect state.
const LLMSettingsPage = React.lazy(() => import("../features/admin-settings/components/LLMSettingsPage"));
const ForgotPasswordPage = React.lazy(() => import("../features/authentication/components/ForgotPasswordPage"));
const ResetPasswordPage = React.lazy(() => import("../features/authentication/components/ResetPasswordPage"));
const AppearanceSettingsPage = React.lazy(() => import("../pages/account/AppearanceSettingsPage"));
const DashboardPage = React.lazy(() => import("../pages/account/DashboardPage"));
const SecuritySettingsPage = React.lazy(() => import("../pages/account/SecuritySettingsPage"));
const SubmissionHistoryPage = React.lazy(() => import("../pages/account/SubmissionHistoryPage"));
const UsagePage = React.lazy(() => import("../pages/account/UsagePage"));
const AdminFindingsPage = React.lazy(() => import("../pages/admin/AdminFindingsPage"));
const FeaturesPage = React.lazy(() => import("../pages/admin/FeaturesPage"));
const SystemConfigTab = React.lazy(() => import("../pages/admin/SystemConfigTab"));
const UserManagementTab = React.lazy(() => import("../pages/admin/UserManagement"));
const UserGroupsPage = React.lazy(() => import("../pages/admin/UserGroupsPage"));
const SMTPSettingsTab = React.lazy(() => import("../pages/admin/SMTPSettingsTab"));
const AgentManagementPage = React.lazy(() => import("../pages/admin/AgentManagementPage"));
const FrameworkManagementPage = React.lazy(() => import("../pages/admin/FrameworkManagementPage"));
const PromptManagementPage = React.lazy(() => import("../pages/admin/PromptManagementPage"));
const ScanDiagnosticsPage = React.lazy(() => import("../pages/analysis/ScanDiagnosticsPage"));
const ProjectDetailPage = React.lazy(() => import("../pages/analysis/ProjectDetailPage"));
const ProjectsPage = React.lazy(() => import("../pages/analysis/ProjectsPage"));
const ResultsPage = React.lazy(() => import("../pages/analysis/ResultsPage"));
const LoginPage = React.lazy(() => import("../pages/auth/LoginPage"));
const SsoCallbackPage = React.lazy(() => import("../pages/auth/SsoCallbackPage"));
const SsoProvidersPage = React.lazy(() => import("../pages/admin/SsoProvidersPage"));
const SsoAuditPage = React.lazy(() => import("../pages/admin/SsoAuditPage"));
const ScimTokensPage = React.lazy(() => import("../pages/admin/ScimTokensPage"));
const TenantsPage = React.lazy(() => import("../pages/admin/TenantsPage"));
const AuthorizationPage = React.lazy(() => import("../pages/admin/AuthorizationPage"));
const SecurityAdvisorPage = React.lazy(() => import("../pages/chat/SecurityAdvisorPage"));
const CompliancePage = React.lazy(() => import("../pages/compliance/CompliancePage"));
const SubmitPage = React.lazy(() => import("../pages/submission/SubmitPage"));
const ScanRunningPage = React.lazy(() => import("../pages/submission/ScanRunningPage"));
const SetupPage = React.lazy(() => import("../pages/setup/SetupPage"));

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
  <LoadingState
    title="Connecting to services…"
    detail="Please wait while SCCAP restores your session."
    fullscreen
  />
);

const RouteContent: React.FC<React.PropsWithChildren> = ({ children }) => (
  <RouteErrorBoundary>
    <Suspense
      fallback={
        <LoadingState title="Loading page…" detail="The application shell remains connected." />
      }
    >
      {children}
    </Suspense>
  </RouteErrorBoundary>
);

const routeContent = (page: React.ReactNode) => <RouteContent>{page}</RouteContent>;

type RouteRequirement =
  | "auth" // Authenticated user → renders inside DashboardLayout.
  | "unauth" // Unauthenticated only (login / forgot-password) → AuthLayout.
  | "permission" // Authenticated + one required stable permission.
  | "root-redirect"; // No render; redirect based on auth state.

interface RouteGuardProps {
  requires: RouteRequirement;
  anyPermission?: readonly string[];
}

/**
 * Single route guard consolidating the four copies this file had
 * (protected / auth-only / root / superuser). All variants share:
 *  - the same "is auth/setup state resolved yet?" loading gate, and
 *  - the same "setup not completed → /setup" forced redirect.
 * The `requires` prop selects the post-setup-gate behavior.
 */
const RouteGuard: React.FC<RouteGuardProps> = ({ requires, anyPermission = [] }) => {
  const { isAuthenticated, user, initialAuthChecked, isLoading, isSetupCompleted } =
    useAuth();

  if (!initialAuthChecked || isLoading || isSetupCompleted === null) {
    return <LoadingScreen />;
  }

  if (isSetupCompleted === false) {
    return <Navigate to="/setup" replace />;
  }

  if (requires === "root-redirect") {
    return isAuthenticated ? (
      <Navigate to="/account/dashboard" replace />
    ) : (
      <Navigate to="/login" replace />
    );
  }

  if (requires === "unauth") {
    return isAuthenticated ? (
      <Navigate to="/" replace />
    ) : (
      <AuthLayout>
        <Outlet />
      </AuthLayout>
    );
  }

  // Both authenticated variants need a valid server-side session.
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  if (requires === "permission" && !hasAnyPermission(user?.permissions, anyPermission)) {
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
          <Route path="/login" element={routeContent(<LoginPage />)} />
          <Route path="/forgot-password" element={routeContent(<ForgotPasswordPage />)} />
          {/* SSO callback landing. The HttpOnly session cookie is already set;
              this page asks AuthProvider to bootstrap it. */}
          <Route path="/auth/sso/complete" element={routeContent(<SsoCallbackPage />)} />
          <Route path="/reset-password" element={routeContent(<ResetPasswordPage />)} />
        </Route>

        {/* Setup Route */}
        <Route path="/setup" element={routeContent(<SetupPage />)} />

        <Route element={<RouteGuard requires="auth" />}>
          <Route path="/account/dashboard" element={routeContent(<DashboardPage />)} />
          <Route path="/submission/submit" element={routeContent(<SubmitPage />)} />
          <Route
            path="/analysis/scanning/:scanId"
            element={routeContent(<ScanRunningPage />)}
          />
          <Route path="/analysis/results" element={routeContent(<ProjectsPage />)} />
          <Route
            path="/analysis/projects/:projectId"
            element={routeContent(<ProjectDetailPage />)}
          />
          <Route path="/analysis/results/:scanId" element={routeContent(<ResultsPage />)} />
          {/* Scan diagnostics reads DB events — no container-backend needed;
              deliberately NOT gated behind log_stack (which only gates
              the Grafana/Loki/Fluentd stack). */}
          <Route
            path="/scans/:scanId/diagnostics"
            element={routeContent(<ScanDiagnosticsPage />)}
          />
          <Route element={<FeatureRoute feature="chat" />}>
            <Route path="/advisor" element={routeContent(<SecurityAdvisorPage />)} />
          </Route>
          <Route element={<FeatureRoute feature="compliance" />}>
            <Route path="/compliance" element={routeContent(<CompliancePage />)} />
          </Route>
          <Route path="/account/history" element={routeContent(<SubmissionHistoryPage />)} />
          <Route path="/usage" element={routeContent(<UsagePage />)} />
          <Route
            path="/account/settings/appearance"
            element={routeContent(<AppearanceSettingsPage />)}
          />
          <Route
            path="/account/settings/security"
            element={routeContent(<SecuritySettingsPage />)}
          />
        </Route>

        <Route element={<RouteGuard requires="permission" anyPermission={["platform.config.manage"]} />}>
          <Route path="/admin/system" element={routeContent(<SystemConfigTab />)} />
          <Route path="/admin/features" element={routeContent(<FeaturesPage />)} />
          <Route path="/admin/appearance" element={routeContent(<AppearanceSettingsPage />)} />
          <Route path="/account/settings/llm" element={routeContent(<LLMSettingsPage />)} />
          <Route element={<FeatureRoute feature="email" />}>
            <Route path="/admin/smtp" element={routeContent(<SMTPSettingsTab />)} />
          </Route>
          <Route element={<FeatureRoute feature="admin_authoring" />}>
            <Route path="/admin/agents" element={routeContent(<AgentManagementPage />)} />
            <Route
              path="/admin/frameworks"
              element={routeContent(<FrameworkManagementPage />)}
            />
            <Route path="/admin/prompts" element={routeContent(<PromptManagementPage />)} />
          </Route>
          {/* /admin/rag has been merged into /compliance; redirect any
              bookmarks and the ?framework=…&action=git-ingest deep-link
              (now unused — the Compliance page handles ingestion inline). */}
          <Route
            path="/admin/rag"
            element={<Navigate to="/compliance" replace />}
          />
        </Route>

        <Route element={<RouteGuard requires="permission" anyPermission={["audit.read"]} />}>
          <Route path="/admin/findings" element={routeContent(<AdminFindingsPage />)} />
          <Route element={<FeatureRoute feature="sso" />}>
            <Route path="/admin/sso/audit" element={routeContent(<SsoAuditPage />)} />
          </Route>
        </Route>
        <Route element={<RouteGuard requires="permission" anyPermission={["identity.read"]} />}>
          <Route element={<FeatureRoute feature="multi_user" />}>
            <Route path="/admin/users" element={routeContent(<UserManagementTab />)} />
          </Route>
        </Route>
        <Route element={<RouteGuard requires="permission" anyPermission={["group.manage"]} />}>
          <Route element={<FeatureRoute feature="user_groups" />}>
            <Route path="/admin/user-groups" element={routeContent(<UserGroupsPage />)} />
          </Route>
        </Route>
        <Route element={<RouteGuard requires="permission" anyPermission={["tenant.policy.manage"]} />}>
          <Route element={<FeatureRoute feature="sso" />}>
            <Route path="/admin/sso/providers" element={routeContent(<SsoProvidersPage />)} />
          </Route>
        </Route>
        <Route element={<RouteGuard requires="permission" anyPermission={["service_principal.manage"]} />}>
          <Route element={<FeatureRoute feature="scim" />}>
            <Route path="/admin/scim/tokens" element={routeContent(<ScimTokensPage />)} />
          </Route>
        </Route>
        <Route element={<RouteGuard requires="permission" anyPermission={["platform.tenant.manage"]} />}>
          <Route element={<FeatureRoute feature="multi_tenant" />}>
            <Route path="/admin/tenants" element={routeContent(<TenantsPage />)} />
          </Route>
        </Route>
        <Route element={<RouteGuard requires="auth" />}>
          <Route path="/admin/authorization" element={routeContent(<AuthorizationPage />)} />
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
          <ThemeProvider>
            <FeatureProvider>
              <AppContent />
            </FeatureProvider>
          </ThemeProvider>
        </AuthProvider>
      </ToastProvider>
    </QueryClientProvider>
  );
}

export default App;
