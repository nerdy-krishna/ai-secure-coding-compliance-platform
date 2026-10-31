import React from "react";
import { Link, useLocation } from "react-router-dom";
import { Icon } from "./Icon";
import { useAuth } from "../hooks/useAuth";
import { useFeatures } from "../hooks/useFeatures";

/**
 * Floating shortcut to the security advisor.
 *
 * The advisor answers questions about the findings that already exist, so it is
 * reachable from anywhere — one tap from a scan result or a pentest run — instead
 * of requiring a trip through the menu. Hidden on the advisor itself and when the
 * chat feature is off.
 */
export const AdvisorFab: React.FC = () => {
  const { pathname } = useLocation();
  const { isFeatureEnabled, featuresLoading } = useFeatures();
  const { user } = useAuth();

  if (!user) return null;
  if (featuresLoading || !isFeatureEnabled("chat")) return null;
  if (pathname.startsWith("/advisor")) return null;

  return (
    <Link className="advisor-fab" to="/advisor" aria-label="Ask the security advisor" title="Ask the security advisor">
      <Icon.Chat size={20} />
    </Link>
  );
};
