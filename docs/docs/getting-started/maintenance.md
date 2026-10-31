---
sidebar_position: 3
title: Maintenance and Uninstallation
---

# Maintenance and uninstallation

`setup.sh` owns the installation lifecycle: install, upgrade, rollback, teardown and
clean reinstall. Every destructive step names what it deletes and asks you to type the
action; `-y` skips the confirmation prompts.

| Command | What it does | What is deleted | What survives |
|---|---|---|---|
| `./setup.sh` | Install, or re-run the wizard on an existing install | — | Everything |
| `./setup.sh --update` | Pull the current branch, back up the database, rebuild, migrate, health-check | Old images are kept aside for rollback | Data, `.env`, keys, certificates |
| `./setup.sh --rollback` | Return code **and** images to the state before the last `--update` | The failed update's images | Data, `.env`, keys, certificates |
| `./setup.sh --uninstall` | Stop and remove the stack | Containers, networks, the project's containers left by older profiles | **Volumes (data), `.env`, `.secrets/`, `certbot/`** |
| `./setup.sh --purge` | Teardown plus data | The above **plus** data volumes and the images built here | `.env`, `.secrets/`, `certbot/`, and the backup |
| `./setup.sh --factory-reset` | A genuinely clean install | Everything above **plus** `.env`, `.secrets/`, `certbot/` | The backup in `.purge-backups/` |
| `./setup.sh --repair-tls` | Re-create TLS material from `.env` and exit | The broken certificate | Everything else |
| `./setup.sh -h` | Print the same table from the terminal | — | — |

## Reversible teardown

```bash
./setup.sh --uninstall      # stack down, data kept
./setup.sh                  # brings it straight back up
```

This is the safe option when you are rebuilding a host, moving directories, or freeing
memory: the database volume, `.env`, `.secrets/` and the Let's Encrypt state all stay.
Re-running `./setup.sh` reuses them and keeps every non-placeholder secret.

## Data-destroying teardown

```bash
./setup.sh --purge          # data volumes and built images removed
```

A `pg_dumpall` backup is written to `.purge-backups/` **before** anything is dropped, and
the path is printed at the end. `.env`, `.secrets/` and `certbot/` survive, so a
subsequent `./setup.sh` reinstalls against the same configuration and certificate.

```bash
./setup.sh --factory-reset  # purge + delete .env, .secrets/, certbot/
```

Use this when you want the next install to be indistinguishable from a first install —
new encryption key, new session secret, new certificate. It asks you to type
`factory-reset` to confirm.

!!! warning "Back up before purging"

    `--purge` and `--factory-reset` cannot be undone from inside the platform. The
    `pg_dumpall` backup in `.purge-backups/` is the only recovery path; copy it off the
    host if the data matters.

## What teardown actually checks

Teardown does not assume `docker compose down` succeeded:

- it force-removes containers left behind by an older profile generation (for example a
  `pentest-engine` from a previous `COMPOSE_PROFILES`), and the networks they keep busy
  (`Resource is still in use`);
- it exits non-zero if anything belonging to the project survives, so "teardown complete"
  always means it;
- configuration written during a `sudo` run is handed back to the operating user, so a
  later non-root `./setup.sh` no longer fails with `open …/.env: permission denied`;
- `.env` and `.setup-stage` end up owned by the operating user with `0600`/`0700`, while
  container-writable paths (Let's Encrypt state, the pentest signing key) are handed to
  the UIDs the containers run as.

## Upgrading

```bash
./setup.sh --update
```

The update pulls the current branch, writes a database backup, keeps the outgoing images,
rebuilds, starts, waits for the database and API health checks, and applies migrations. If
any stage fails it tells you the rollback command:

```bash
./setup.sh --rollback       # code + images back to the pre-update state
```

If the schema moved forward before the failure, rollback restores the code and images and
tells you to restore the printed backup.

Manual equivalent, when you want to drive each step:

```bash
git pull
python3 scripts/bootstrap_env_secrets.py --env-file .env   # adds new keys, keeps values
docker compose config --quiet                              # validates interpolation
docker compose up -d --build
docker compose exec app alembic upgrade head
```

## Post-upgrade checks

```bash
docker compose ps                                  # every core service Up/healthy
curl -fsS http://localhost/api/v1/system/health    # API healthy
docker compose exec app python -m ruff check src   # optional sanity on the checkout
```

Re-enable any feature your variant does not seed by default under **Admin → Platform**, and
re-sync Semgrep rule sources after an upgrade that changes rule handling
(**Admin → Semgrep Config → Sync Now**).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| UI reports `tls_cert_missing` or "connection closed" | Certificate volume lost or expired | `./setup.sh --repair-tls` |
| `open …/.env: permission denied` | `.env` written by a `sudo` run | Re-run `./setup.sh`; it re-hands ownership |
| `Resource is still in use` during teardown | Containers from an older profile generation | Re-run `./setup.sh --uninstall`; it removes them explicitly |
| Port already in use | Host port conflict | Change `APP_PORT` / `RABBITMQ_PORT` in `.env`, then `docker compose up -d` |
| Database never becomes healthy | Disk full, or a long migration | `docker compose logs db`, free space, re-run `./setup.sh --update` |
| Build fails on a small VPS | Not enough RAM for the frontend build | Add swap (see the installation guide) |

## Removing only what you added

If you enabled an optional stack (log stack, pentesting, tracing) and want it gone without
touching the core installation:

```bash
# drop the profile from .env, then recreate the stack
sed -i 's/^COMPOSE_PROFILES=.*/COMPOSE_PROFILES=/' .env
docker compose up -d --remove-orphans
```

The containers, networks and volumes of that profile are removed; the database, findings
and configuration are untouched.
