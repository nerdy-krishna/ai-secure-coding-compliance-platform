import React from "react";
import { useAuth } from "../../shared/hooks/useAuth";
import { Permission, hasPermission } from "../../shared/lib/permissions";
import { Icon } from "../../shared/ui/Icon";
import { TabbedAdminPage, type AdminTab } from "./TabbedAdminPage";
import SystemConfigTab from "./SystemConfigTab";
import FeaturesPage from "./FeaturesPage";

/**
 * How the installation behaves for everyone.
 *
 * The platform settings describe how the running services behave; feature flags then
 * decide which surfaces exist on top of them.
 */
const PlatformPage: React.FC = () => {
  const { user } = useAuth();
  const isAdmin = hasPermission(user?.permissions, Permission.platformConfigManage);

  const tabs: AdminTab[] = [
    {
      key: "settings",
      label: "Platform Settings",
      icon: <Icon.Settings size={13} />,
      description:
        "Core behaviour of the running services: LLM mode, allowed origins, and the raw configuration key/values.",
      render: () => <SystemConfigTab embedded />,
    },
    {
      key: "features",
      label: "Features",
      icon: <Icon.Zap size={13} />,
      description:
        "Installation-wide feature flags. A flag switches a whole surface on or off for every tenant; dependencies are resolved automatically.",
      requires: "the platform settings above (step 1)",
      render: () => <FeaturesPage />,
    },
  ];

  return (
    <TabbedAdminPage
      crumbs={[{ label: "Platform" }]}
      title="Platform"
      subtitle="Which surfaces exist in this installation, and how the running services behave."
      tabs={tabs}
      isAdmin={isAdmin}
    />
  );
};

export default PlatformPage;
