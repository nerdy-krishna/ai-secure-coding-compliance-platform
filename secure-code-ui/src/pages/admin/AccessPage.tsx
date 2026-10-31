import React from "react";
import { useAuth } from "../../shared/hooks/useAuth";
import { Permission, hasPermission } from "../../shared/lib/permissions";
import { Icon } from "../../shared/ui/Icon";
import { TabbedAdminPage, type AdminTab } from "./TabbedAdminPage";
import TenantsPage from "./TenantsPage";
import UserManagementTab from "./UserManagement";
import UserGroupsPage from "./UserGroupsPage";
import AuthorizationPage from "./AuthorizationPage";

/**
 * Tenancy, membership and permissions in one place, in the order they are set up:
 * a tenant exists, people join it, they are collected into groups, and finally the
 * authorisation policy says what each may do.
 */
const AccessPage: React.FC = () => {
  const { user } = useAuth();
  const isAdmin = hasPermission(user?.permissions, Permission.platformConfigManage);

  const tabs: AdminTab[] = [
    {
      key: "tenants",
      label: "Tenants",
      icon: <Icon.Layers size={13} />,
      description:
        "The isolation boundary every user, scan and finding belongs to. Create a tenant before inviting anyone into it.",
      render: () => <TenantsPage embedded />,
    },
    {
      key: "users",
      label: "Users",
      icon: <Icon.Users size={13} />,
      description:
        "Accounts inside the active tenant, their verification state and which roles they hold.",
      requires: "a tenant (step 1)",
      render: () => <UserManagementTab embedded />,
    },
    {
      key: "groups",
      label: "Groups",
      icon: <Icon.Users size={13} />,
      description:
        "Collections of users that share visibility: members of a group can see each other's scans.",
      requires: "at least two users (step 2)",
      render: () => <UserGroupsPage embedded />,
    },
    {
      key: "authorization",
      label: "Authorization",
      icon: <Icon.Lock size={13} />,
      description:
        "Separation-of-duties policy and the approval inbox. Says what the users, groups and roles above are allowed to do.",
      requires: "users and groups (steps 2 and 3)",
      render: () => <AuthorizationPage />,
    },
  ];

  return (
    <TabbedAdminPage
      crumbs={[{ label: "Access & Roles" }]}
      title="Access & Roles"
      subtitle="Who is in the platform, how they are grouped, and what they are permitted to do."
      tabs={tabs}
      isAdmin={isAdmin}
    />
  );
};

export default AccessPage;
