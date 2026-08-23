export const Permission = {
  auditRead: "audit.read",
  groupManage: "group.manage",
  identityRead: "identity.read",
  identityManage: "identity.manage",
  platformConfigManage: "platform.config.manage",
  platformTenantManage: "platform.tenant.manage",
  ruleCandidateCreate: "rule.candidate.create",
  rulePromote: "rule.promote",
  servicePrincipalManage: "service_principal.manage",
  tenantPolicyManage: "tenant.policy.manage",
  waiverApprove: "waiver.approve",
} as const;

export function hasPermission(
  permissions: readonly string[] | undefined,
  permission: string,
): boolean {
  return permissions?.includes(permission) === true;
}

export function hasAnyPermission(
  permissions: readonly string[] | undefined,
  required: readonly string[],
): boolean {
  return required.some((permission) => hasPermission(permissions, permission));
}

export const ADMIN_AREA_PERMISSIONS = [
  Permission.auditRead,
  Permission.groupManage,
  Permission.identityRead,
  Permission.identityManage,
  Permission.platformConfigManage,
  Permission.platformTenantManage,
  Permission.rulePromote,
  Permission.servicePrincipalManage,
  Permission.tenantPolicyManage,
  Permission.waiverApprove,
] as const;
