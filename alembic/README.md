# SCCAP Alembic baseline

Alembic reads active revisions from `alembic/current_versions`. The previous
122-revision chain remains in `alembic/versions` as an inactive audit archive
and as the only supported route for upgrading a database that predates the
baseline boundary.

## Compatibility boundary

The active root deliberately reuses revision `4d5e6f708192`, the former legacy
head:

- An empty database runs the frozen current-schema baseline on `upgrade head`.
- A database already at `4d5e6f708192` remains at head without DDL or stamping.
- A database below `4d5e6f708192` must use the archived chain to reach that
  revision before deploying this baseline.
- Downgrading through the baseline is unsupported. Restore a verified backup
  or use the archived chain in a controlled recovery environment.

Do not run `alembic stamp` merely to cross this boundary. A stamp would assert
schema compatibility without proving it.

## Frozen schema

`alembic/baselines/2026_08_28_current_schema.sql` is a schema-only PostgreSQL
snapshot. It includes the current tables, constraints, indexes, functions,
triggers, forced tenant RLS policies, the `sccap_runtime` role grants, and the
required default-tenant identity. It excludes deployment data, secrets,
`alembic_version`, and the LangGraph checkpoint tables owned by the
checkpointer. Application startup remains responsible for idempotently seeding
frameworks, agents, and prompt templates.

Fresh managed-PostgreSQL installations must pre-provision `sccap_runtime` when
the migration owner cannot create roles. The baseline creates it idempotently
when the owner has `CREATEROLE`, matching the archived chain's security model.

The root migration pins the snapshot SHA-256 and refuses to execute if it is
edited without explicit review. Future migrations belong in
`alembic/current_versions` and must use `4d5e6f708192` (or the latest active
head) as `down_revision`.

## Release procedure

Before releasing the baseline:

1. Back up every existing database and verify restore.
2. Confirm `alembic current` reports `4d5e6f708192` on every environment.
3. Run `alembic upgrade head`; it should perform no DDL on those environments.
4. Prove an empty PostgreSQL database can run `alembic upgrade head` and that
   its schema matches the frozen snapshot contract.

Historical migrations are immutable. Do not add new revisions to
`alembic/versions`.
