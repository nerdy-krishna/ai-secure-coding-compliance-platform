---
title: Modular Setup
sidebar_position: 8
---

# Modular Setup

SCCAP installs and runs as one of four packaging **variants**. A variant is a
preset bundle of runtime **feature flags** plus **docker-compose profiles**.
This is a product-packaging mechanism — not a security boundary.

## Decision

The platform ships as **one Docker image and one CI pipeline**. "A feature is
not installed" means:

- **Runtime feature flags** gate in-app features — a disabled feature's router
  is not mounted, so its endpoints return `404` and are absent from the
  OpenAPI schema.
- **docker-compose profiles** gate the optional container stacks (the
  Fluentd/Loki/Grafana log stack; the 6-container Langfuse tracing stack).

A build-time split (separate per-variant images) was rejected: it multiplies
the release and CI surface by four, makes the `custom` variant a per-install
build, and makes a variant immutable — for isolation a single open repository
does not provide anyway.

## The four variants

| Variant | Features |
|---|---|
| `vibe_coder` | `scan`, `chat`, `compliance` — single superuser, no other accounts |
| `developer` | the above + `multi_user`, `user_groups`, `email`, `mcp`, `admin_authoring` |
| `enterprise` | every feature; `tracing` is *available* but its flag starts OFF |
| `custom` | any dependency-valid subset, chosen in the setup wizard |

## The 13-feature catalog

`scan` is always on (the product floor). The rest are toggleable. Dependency
edges (`X → Y` = X requires Y):

```
chat → scan          user_groups → multi_user
compliance → scan    sso → multi_user        scim → sso
mcp → scan           multi_tenant → multi_user
email                log_stack (container)   tracing (container)
admin_authoring
```

`resolve_dependencies` closes a requested set under these edges;
`prune_unsatisfied` is the disable-direction counterpart (dropping a feature
drops its dependents). Both live in `app/core/features.py`.

## Where state lives

- **`SCCAP_VARIANT`** (in `.env`, written by `setup.sh`) — a seed-once label.
  On first boot the app expands it into `features.*` rows in `system_config`.
- **`COMPOSE_PROFILES`** (in `.env`) — which optional container stacks boot.
- **`features.*` rows** in `system_config`, mirrored into `SystemConfigCache`
  — the live source of truth for app features after first boot. Editing
  `SCCAP_VARIANT` later is inert; the DB rows win.

An install with no `SCCAP_VARIANT` is treated as `enterprise` — the
non-breaking default for deployments predating modular setup.

**Invariant:** a container-backed feature (`log_stack`, `tracing`) may only be
enabled when its profile is in `COMPOSE_PROFILES`. The app logs a WARN at
startup on a mismatch.

## Lifecycle

1. **`setup.sh`** asks for the variant first, writes `SCCAP_VARIANT` +
   `COMPOSE_PROFILES`. For `custom` it asks the per-stack container questions.
2. **Import-time bootstrap** (`main.py`) reads `features.*` over a synchronous
   connection and mounts only the enabled routers.
3. **Lifespan** re-loads authoritatively and seeds-if-empty from the variant.
4. **`/setup`** wizard shows the variant (read-only for presets; a grouped
   feature picker for `custom`) and seeds the chosen set.
5. **Admin → Features** (`/admin/features`, superuser-only) edits app-only
   flags live; container-backed flags are read-only there.

## Changing features after install

- App-only flags: toggle on the admin Features page — effective immediately
  for `require_feature` gates and `GET /features`; a router that was skipped
  at boot needs an app restart to (un)mount.
- Container-backed flags: edit `COMPOSE_PROFILES` and restart the stack.
- Disabling `multi_user` is destructive — it deactivates every non-superuser
  account (data preserved, login blocked) and requires explicit confirmation;
  re-enabling restores exactly those accounts.

## Discovery endpoint

`GET /api/v1/features` is public and unauthenticated. It returns the enabled
set, the install variant, the active compose profiles, and the static
catalog — the route guards, the login page, and the pre-auth setup wizard all
need it before any user exists. It exposes no configuration value or secret.
