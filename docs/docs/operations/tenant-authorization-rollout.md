---
title: Tenant authorization rollout
---

# Tenant authorization rollout

This runbook covers the role-based authorization, forced PostgreSQL row-level
security (RLS), explicit platform-owner tenant entry, and optional critical
separation-of-duties (SoD) policy.

## What changes

Human access is resolved from immutable built-in role keys. `platform_owner` is
global; `tenant_admin`, `security_approver`, `analyst`, `developer`, and
`auditor` are tenant roles. Routes authorize stable permission keys and then
apply tenant and resource visibility. `is_superuser` remains a migration
compatibility field, not the authorization source of truth.

Tenant-owned rows are protected twice: repositories carry explicit tenant
predicates, and PostgreSQL forced RLS reads transaction-local principal context.
API and worker startup fail in production if the database login is a superuser,
has `BYPASSRLS`, or owns a forced-RLS table.

| Built-in role | Effective capability summary |
|---|---|
| `platform_owner` | All platform capabilities; tenant data still requires explicit entry |
| `tenant_admin` | Tenant scan/audit read, identities, groups, tenant policy, SSO, and service principals |
| `security_approver` | Tenant scan approval, finding triage/waivers, rule candidate/promotion seam, and audit read |
| `analyst` | Own/shared scan submit/read/control, finding triage, and waiver/rule requests |
| `developer` | Own/shared scan submit/read/control; self gate approval only while SoD is `off` |
| `auditor` | Read-only tenant scans, identities, and audit evidence |

Task 18 consumes the `rule.candidate.create` and `rule.promote` permission seam
and the generic action-request mechanism when it installs the rule promotion
workflow. Task 17 does not expose a parallel promotion implementation.

## Before upgrading

1. Take a tested PostgreSQL backup and record the current application and
   migration revisions.
2. Confirm every active human has one tenant and that the intended bootstrap
   operator still exists.
3. Prepare separate database URLs:

   - `ALEMBIC_DATABASE_URL` uses the migration owner.
   - `ASYNC_DATABASE_URL` uses a non-owner `NOSUPERUSER NOBYPASSRLS` runtime
     login with the migration-created `sccap_runtime` privileges (or equivalent
     explicit DML grants).

4. Keep the migration-owner credential out of the running API and worker after
   entrypoint migrations complete.
5. Rehearse the upgrade and restore in staging with a production-sized backup.

## Apply and verify

Run backend operations inside Compose networking:

```bash
docker compose up -d --build
docker compose exec app alembic upgrade head
docker compose logs app worker
```

The migration backfills existing superusers to `platform_owner`, assigns a
least-privilege tenant role to other existing users, creates the authorization
request/audit tables, installs tenant-reference invariants, and enables forced
RLS. Startup must emit `database.rls_role.safe` in production. An
`unsafe_development` warning is expected only from the single-owner local
Compose profile.

Verify the database posture using a read-only query with the runtime URL:

```sql
SELECT current_user,
       r.rolsuper,
       r.rolbypassrls
FROM pg_roles r
WHERE r.rolname = current_user;

SELECT count(*) AS forced_rls_tables
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relkind = 'r'
  AND c.relforcerowsecurity;
```

Then verify application behavior:

1. A tenant user can read an allowed same-tenant resource.
2. The same user receives `404` for a known foreign-tenant identifier.
3. Removing a role assignment takes effect on the next request.
4. A SCIM token can access only its bound tenant and cannot open a browser
   session or approve a human action.
5. A platform owner sees platform metadata only until selecting **Admin →
   Tenants → Enter tenant**, re-entering their password, and supplying a reason.
   The grant is memory-only and expires after ten minutes.

## Enable critical separation of duties

The tenant policy defaults to `off`. Enable `critical` from **Admin →
Authorization** only after at least two active people hold every approval
capability the tenant needs.

Critical mode requires a distinct current actor for:

- scan gates when the approver submitted the scan;
- finding waivers;
- tenant permission increases;
- SSO-provider deletion;
- SCIM service-principal revocation; and
- rule promotion and rollback when the Task 18 rule-foundry flow is enabled.

Durable requests bind the requester, tenant, target fingerprint, canonical
payload digest, required permissions, and a 24-hour expiry. Approval and
execution revalidate both actors. The requester cannot approve their own
action. Removing either actor's required permission, changing the target or
payload, changing tenants, or allowing the request to expire fails closed.

Relaxing a tenant from `critical` to `off` is itself a durable two-person
action. Do not enable critical mode with only one eligible administrator.

## Audit and monitoring

`authorization_audit_events` is append-only and stores privacy-safe target
fingerprints rather than resource contents, emails, tokens, or request
payloads. Authentication/session events remain in `auth_audit_events`.

Alert on:

- `database.rls_role.unsafe`;
- `authorization.break_glass_tenant_entry`;
- repeated denied or expired action requests;
- unexpected growth in platform-owner assignments; and
- worker messages rejected as untrusted tenant identity.

## Rollback

Prefer policy and application rollback over schema downgrade:

1. Stop new high-risk changes and preserve both audit tables.
2. If the application remains healthy, use the approved tenant-policy workflow
   to change `critical` to `off` where operationally necessary.
3. Roll the API and worker back together to the last compatible application
   image. Do not run an older worker against a newer authorization contract.
4. Keep the additive role/RLS schema in place. Do not disable forced RLS or
   restore a superuser runtime login as a convenience rollback.
5. If a schema downgrade is unavoidable, enter a maintenance window, stop API
   and worker traffic, use the migration-owner credential, follow the exact
   Alembic downgrade path tested in staging, and be prepared to restore the
   pre-upgrade backup.

After any rollback, repeat the tenant-isolation probes above before reopening
traffic.
