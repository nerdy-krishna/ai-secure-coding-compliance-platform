import React from "react";
import { useAuth } from "../../shared/hooks/useAuth";
import { Permission, hasPermission } from "../../shared/lib/permissions";
import { Icon } from "../../shared/ui/Icon";
import { TabbedAdminPage, type AdminTab } from "./TabbedAdminPage";
import SsoProvidersPage from "./SsoProvidersPage";
import ScimTokensPage from "./ScimTokensPage";
import SMTPSettingsTab from "./SMTPSettingsTab";

/**
 * How people sign in and how the platform reaches them: identity provider first,
 * then automated provisioning, then the outbound mail the account flows depend on.
 */
const IdentityPage: React.FC = () => {
  const { user } = useAuth();
  const isAdmin = hasPermission(user?.permissions, Permission.platformConfigManage);

  const tabs: AdminTab[] = [
    {
      key: "sso",
      label: "SSO providers",
      icon: <Icon.Key size={13} />,
      description:
        "OIDC and SAML 2.0 identity providers. Multiple providers run side by side and can be bound to email domains.",
      render: () => <SsoProvidersPage embedded />,
    },
    {
      key: "scim",
      label: "SCIM tokens",
      icon: <Icon.Refresh size={13} />,
      description:
        "Bearer tokens your IdP uses to push users and groups automatically, so leavers lose access without a manual step.",
      requires: "an SSO provider (step 1)",
      render: () => <ScimTokensPage />,
    },
    {
      key: "smtp",
      label: "Email (SMTP)",
      icon: <Icon.Mail size={13} />,
      description:
        "The outgoing mail server used for password resets and invitations. One profile is active at a time.",
      render: () => <SMTPSettingsTab embedded />,
    },
  ];

  return (
    <TabbedAdminPage
      crumbs={[{ label: "Identity & Email" }]}
      title="Identity & Email"
      subtitle="Sign-in, automated provisioning and the mail the account flows depend on."
      tabs={tabs}
      isAdmin={isAdmin}
    />
  );
};

export default IdentityPage;
