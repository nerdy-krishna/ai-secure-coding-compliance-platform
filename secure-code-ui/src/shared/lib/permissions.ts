export const Permission = {
  auditRead: "audit.read",
  groupManage: "group.manage",
  identityRead: "identity.read",
  identityManage: "identity.manage",
  platformConfigManage: "platform.config.manage",
  platformTenantManage: "platform.tenant.manage",
  pentestRead: "pentest.read",
  pentestControl: "pentest.control",
  pentestReportCreate: "pentest.report.create",
  pentestReportPublish: "pentest.report.publish",
  pentestEvidenceExport: "pentest.evidence.export",
  pentestGovernanceRequest: "pentest.governance.request",
  pentestGovernanceApprove: "pentest.governance.approve",
  pentestRetestCreate: "pentest.retest.create",
  ruleCandidateCreate: "rule.candidate.create",
  ruleCandidateReview: "rule.candidate.review",
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
  Permission.ruleCandidateReview,
  Permission.servicePrincipalManage,
  Permission.tenantPolicyManage,
  Permission.waiverApprove,
] as const;
