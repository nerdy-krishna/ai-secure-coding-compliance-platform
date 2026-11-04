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

## Re-running the installer

`./setup.sh` on an installation that has already been bootstrapped **keeps `.env`
and skips every configuration question** — the administrator account, LLM
configuration and feature flags already exist, and asking for them again was
pointless work.

The state is recorded in `.setup-complete` (timestamp and administrator email, no
secrets), written when the first-run bootstrap succeeds. If the API is running and
reports setup complete but the marker is missing — an install from before the marker
existed — the marker is created on the next run and the questions are skipped from
then on.

Use `./setup.sh --factory-reset` (or `--purge`, which also drops the data volumes)
to start over: both delete the marker, so the next install asks again.

If you need to mark an existing installation as bootstrapped by hand — for example
when the stack is down and the API cannot be asked:

```bash
printf 'completed_at=%s\nadmin_email=%s\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "you@example.com" > .setup-complete
chmod 600 .setup-complete
```

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
| `sh: tsc: not found` during the UI build | npm installed without devDependencies (an inherited `NODE_ENV=production` / `npm_config_omit=dev`), or a `node_modules` leaked into the build context | Remove `secure-code-ui/node_modules` and `dist`, `docker builder prune -f`, pull, rebuild. The build now clears those variables and verifies `tsc` itself |
| `npm error Exit handler never called` | npm crashed — out-of-memory on a small VM, or a corrupt npm cache | `COMPOSE_PARALLEL_LIMIT=1 ./setup.sh` (one image at a time), or `docker compose build ui`; add swap if it repeats. The installer defaults to 2 concurrent builds |

## Which version is running

The profile menu (top right) shows the running build under your email, and **Version**
in the menu opens the details:

| Field | Meaning |
|---|---|
| `0.2.0+5c7d44c6` | release + the commit the image was built from |
| Release | `pyproject.toml` (`app.__version__`) |
| Commit | full SHA, copyable |
| Built at | build time recorded when the image was created |
| Database schema | current alembic revision, so a skipped migration is visible |
| Environment | deployment environment |

The commit changes on **every successful `./setup.sh --update`**, which is the point:
if it has not changed, the update did not reach the running containers. `setup.sh`
passes `SCCAP_BUILD_COMMIT`, `SCCAP_BUILD_TIME` and `SCCAP_BUILD_VERSION` to the image
build on both a fresh install and an update, and records the same values in
`.scratch/deploy-state.json`.

A build made by hand (`docker compose build` with no arguments) shows
`0.2.0 (unversioned build)` — it cannot know its commit, and saying so is better than
inventing one. `--rollback` restores the previous images, so the version reverts with
them.

## Updating an existing installation

```bash
./setup.sh --update          # rebuild only what changed
./setup.sh --update --full   # rebuild every image (slow)
```

`--update` fetches the branch, asks once, tags the running images for rollback,
rebuilds **only the images whose content changed**, restarts, applies migrations and
only reports success once the API answers.

| What changed | What is rebuilt |
|---|---|
| `src/`, `alembic/`, `pyproject.toml`, `poetry.lock`, `Dockerfile`, `docker/`, `scripts/` | `app`, `worker`, and the pentest/patch images when they are part of the deployment |
| `secure-code-ui/` | `ui` only |
| `docker-compose.yml`, `.env`, nginx config | nothing — containers are recreated so the new settings apply |

The database dump is also skipped when no migration file changed *and* the database is
already at head: on a large install `pg_dump` was minutes of the update for nothing.

Timings measured on a 4 GB VM after the cache fixes below:

| Update | Before | Now |
|---|---|---|
| backend code change | 3 m 32 s (app + worker) | **2.5 s** |
| UI change | full rebuild | UI image only |
| compose/env change | full rebuild | no build |

Two causes of the old slowness, both fixed:

- the provenance build args (`SCCAP_BUILD_COMMIT`, …) sat at the top of the base stage,
  so every update changed a layer above the dependency install and invalidated the
  entire build. They are now declared at the **end** of each stage: a changing commit
  costs one small layer;
- the fastembed model warm-up ran *after* the source copy, so touching one Python file
  re-downloaded the model for every image. It now runs above the copy, where it only
  depends on the virtualenv.

The first update after these changes is still a full rebuild — the layers genuinely
changed once. Every update after that is incremental.

`--full` exists for the cases the path mapping cannot see: a changed base image, or a
build whose cache you do not trust.

The decision to deploy is based on **what is deployed**, not on what the checkout
contains: the running API reports the commit it was built from
(`SCCAP_BUILD_COMMIT`), falling back to `.scratch/deploy-state.json`. That distinction
matters — running `git pull` by hand makes the checkout current while the images and
schema are still the old ones, and an update that compared only the checkout used to
report "already up to date" and change nothing.

| Checkout | Deployment | What `--update` does |
|---|---|---|
| target | target | prints "nothing to do" (no restart) |
| target | older | rebuilds, restarts, migrates, and says why |
| target | unknown | deploys, because an unproven match is not a match |
| older | anything | normal update |

`--rollback` returns code and images to the commit that was actually deployed. If you
change tracked files by hand, use the explicit build (`docker compose build … &&
docker compose up -d`), because `--update` hard-resets the checkout to origin.

## Throughput knobs

| Setting | Default | Effect |
|---|---|---|
| `WORKER_ANALYSIS_SLOTS` | 3 | Scans one worker container runs at once (LLM phase) |
| `WORKER_SUBMISSION_SLOTS` | 1 | Pre-LLM pipelines at once |
| `WORKER_PREFETCH_COUNT` | 5 | Messages held in flight per worker |
| `CONCURRENT_LLM_LIMIT` | 50 | Concurrent model calls per reasoning lane, inside one scan |
| `CONCURRENT_SCANNER_LIMIT` | 10 | Concurrent scanner processes per scan |

`docker compose restart worker` applies them. Each analysis slot keeps a full scan
state in memory, so raise it against measured headroom, not hope. Pentests are
unaffected: the engine runs its own container and one run at a time.

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
