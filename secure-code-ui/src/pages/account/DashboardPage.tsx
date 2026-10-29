// secure-code-ui/src/pages/account/DashboardPage.tsx
//
// Role-aware dashboard router. H.3 dropped the enterprise variant and
// narrowed roles to user + admin. The choice is driven by the real
// `user.is_superuser` flag, which is also what the route guards use.

import React from "react";
import { AdminSnapshot } from "../../features/dashboard/components/AdminSnapshot";
import { UserDashboard } from "../../features/dashboard/components/UserDashboard";
import SemgrepReadinessBanner from "../../features/semgrep/SemgrepReadinessBanner";
import { useAuth } from "../../shared/hooks/useAuth";

const DashboardPage: React.FC = () => {
  const { user } = useAuth();
  return (
    <>
      {/* Pre-scan readiness gate: a fresh install has no enabled Semgrep rules,
          so the first scan would report zero findings. Shown before the
          operator can start one, and links straight to the sync page. */}
      <SemgrepReadinessBanner />
      {user?.is_superuser ? <AdminSnapshot /> : <UserDashboard />}
    </>
  );
};

export default DashboardPage;
