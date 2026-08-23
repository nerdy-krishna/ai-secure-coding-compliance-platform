"""Stable built-in authorization roles and permission keys.

Role names are assignment conveniences. Call sites authorize against permission
keys plus a resource-scope decision, never directly against a role name.
"""

from __future__ import annotations

from collections.abc import Iterable


PLATFORM_OWNER = "platform_owner"
TENANT_ADMIN = "tenant_admin"
SECURITY_APPROVER = "security_approver"
ANALYST = "analyst"
DEVELOPER = "developer"
AUDITOR = "auditor"

BUILTIN_ROLE_KEYS = frozenset(
    {
        PLATFORM_OWNER,
        TENANT_ADMIN,
        SECURITY_APPROVER,
        ANALYST,
        DEVELOPER,
        AUDITOR,
    }
)

SCAN_SUBMIT = "scan.submit"
SCAN_READ = "scan.read"
SCAN_READ_TENANT = "scan.read.tenant"
SCAN_CONTROL = "scan.control"
SCAN_APPROVE = "scan.approve"
SCAN_APPROVE_SELF = "scan.approve.self"
FINDING_TRIAGE = "finding.triage"
WAIVER_REQUEST = "waiver.request"
WAIVER_APPROVE = "waiver.approve"
RULE_CANDIDATE_CREATE = "rule.candidate.create"
RULE_PROMOTE = "rule.promote"
IDENTITY_READ = "identity.read"
IDENTITY_MANAGE = "identity.manage"
TENANT_POLICY_MANAGE = "tenant.policy.manage"
SERVICE_PRINCIPAL_MANAGE = "service_principal.manage"
AUDIT_READ = "audit.read"
PLATFORM_TENANT_MANAGE = "platform.tenant.manage"
PLATFORM_CONFIG_MANAGE = "platform.config.manage"
GROUP_MANAGE = "group.manage"

ALL_PERMISSION_KEYS = frozenset(
    {
        SCAN_SUBMIT,
        SCAN_READ,
        SCAN_READ_TENANT,
        SCAN_CONTROL,
        SCAN_APPROVE,
        SCAN_APPROVE_SELF,
        FINDING_TRIAGE,
        WAIVER_REQUEST,
        WAIVER_APPROVE,
        RULE_CANDIDATE_CREATE,
        RULE_PROMOTE,
        IDENTITY_READ,
        IDENTITY_MANAGE,
        TENANT_POLICY_MANAGE,
        SERVICE_PRINCIPAL_MANAGE,
        AUDIT_READ,
        PLATFORM_TENANT_MANAGE,
        PLATFORM_CONFIG_MANAGE,
        GROUP_MANAGE,
    }
)

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    PLATFORM_OWNER: ALL_PERMISSION_KEYS,
    TENANT_ADMIN: frozenset(
        {
            SCAN_READ,
            SCAN_READ_TENANT,
            WAIVER_REQUEST,
            IDENTITY_READ,
            IDENTITY_MANAGE,
            TENANT_POLICY_MANAGE,
            SERVICE_PRINCIPAL_MANAGE,
            AUDIT_READ,
            GROUP_MANAGE,
        }
    ),
    SECURITY_APPROVER: frozenset(
        {
            SCAN_READ,
            SCAN_READ_TENANT,
            SCAN_APPROVE,
            FINDING_TRIAGE,
            WAIVER_REQUEST,
            WAIVER_APPROVE,
            RULE_CANDIDATE_CREATE,
            RULE_PROMOTE,
            AUDIT_READ,
        }
    ),
    ANALYST: frozenset(
        {
            SCAN_SUBMIT,
            SCAN_READ,
            SCAN_CONTROL,
            FINDING_TRIAGE,
            WAIVER_REQUEST,
            RULE_CANDIDATE_CREATE,
        }
    ),
    DEVELOPER: frozenset(
        {
            SCAN_SUBMIT,
            SCAN_READ,
            SCAN_CONTROL,
            SCAN_APPROVE_SELF,
            WAIVER_REQUEST,
            RULE_CANDIDATE_CREATE,
        }
    ),
    AUDITOR: frozenset({SCAN_READ, SCAN_READ_TENANT, IDENTITY_READ, AUDIT_READ}),
}


def permissions_for_roles(role_keys: Iterable[str]) -> frozenset[str]:
    """Return the union of known built-in-role permissions.

    Unknown role keys fail closed. Database constraints prevent them in normal
    operation, while this behavior keeps corrupted or stale claims harmless.
    """

    effective: set[str] = set()
    for role_key in role_keys:
        effective.update(ROLE_PERMISSIONS.get(role_key, ()))
    return frozenset(effective)
