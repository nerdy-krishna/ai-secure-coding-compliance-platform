#!/bin/bash
set -e

# setup.sh - Easy Installation Script for SCCAP

echo "=================================================="
echo "   SCCAP - Setup Wizard"
echo "=================================================="
echo ""

# 1. Prerequisites Check
echo "[*] Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    echo "Error: docker could not be found. Please install Docker first."
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo "Error: python3 could not be found. Please install Python 3 first."
    exit 1
fi

# Note: Node.js is intentionally NOT a host prerequisite — the UI is built
# inside the `ui` Docker image, never on the host.

echo "[+] Prerequisites met."
echo ""

# 2. Environment Setup
echo "[*] Setting up environment configuration..."

exec 9>>.env.lock; flock -n 9 || { echo "[!] Another setup.sh is running; exiting."; exit 1; }
if [ ! -f .env ]; then
    echo " -> Copying .env.example to .env..."
    cp .env.example .env
    
    echo " -> Generating secure keys..."
    # ------------------------------------------------------------------
    # Core secrets
    SECRET_KEY=$(python3 scripts/generate_secrets.py random)
    ENCRYPTION_KEY=$(python3 scripts/generate_secrets.py fernet)
    POSTGRES_PASSWORD=$(python3 scripts/generate_secrets.py random)
    RABBITMQ_DEFAULT_PASS=$(python3 scripts/generate_secrets.py random)
    QDRANT_API_KEY=$(python3 scripts/generate_secrets.py random)
    # Grafana (log_stack profile)
    GRAFANA_ADMIN_PASSWORD=$(python3 scripts/generate_secrets.py random)
    # Langfuse / tracing stack secrets
    LANGFUSE_POSTGRES_PASSWORD=$(python3 scripts/generate_secrets.py random)
    CLICKHOUSE_PASSWORD=$(python3 scripts/generate_secrets.py random)
    REDIS_PASSWORD=$(python3 scripts/generate_secrets.py random)
    MINIO_ROOT_PASSWORD=$(python3 scripts/generate_secrets.py random)
    LANGFUSE_ENCRYPTION_KEY=$(openssl rand -hex 32)  # must be exactly 64 hex chars
    LANGFUSE_SALT=$(python3 scripts/generate_secrets.py random)
    NEXTAUTH_SECRET=$(python3 scripts/generate_secrets.py random)
    LANGFUSE_INIT_USER_PASSWORD=$(python3 scripts/generate_secrets.py random)
    # ------------------------------------------------------------------

    # Escape sed replacement-side metacharacters (/, &, \) so that special
    # characters in generated secrets are treated as literals (V01.2.9).
    _esc() { printf '%s\n' "$1" | sed -e 's/[\/&]/\\&/g'; }
    _SECRET_KEY=$(_esc "$SECRET_KEY")
    _ENCRYPTION_KEY=$(_esc "$ENCRYPTION_KEY")
    _POSTGRES_PASSWORD=$(_esc "$POSTGRES_PASSWORD")
    _RABBITMQ_DEFAULT_PASS=$(_esc "$RABBITMQ_DEFAULT_PASS")
    _QDRANT_API_KEY=$(_esc "$QDRANT_API_KEY")
    _GRAFANA_ADMIN_PASSWORD=$(_esc "$GRAFANA_ADMIN_PASSWORD")
    _LANGFUSE_POSTGRES_PASSWORD=$(_esc "$LANGFUSE_POSTGRES_PASSWORD")
    _CLICKHOUSE_PASSWORD=$(_esc "$CLICKHOUSE_PASSWORD")
    _REDIS_PASSWORD=$(_esc "$REDIS_PASSWORD")
    _MINIO_ROOT_PASSWORD=$(_esc "$MINIO_ROOT_PASSWORD")
    _LANGFUSE_ENCRYPTION_KEY=$(_esc "$LANGFUSE_ENCRYPTION_KEY")
    _LANGFUSE_SALT=$(_esc "$LANGFUSE_SALT")
    _NEXTAUTH_SECRET=$(_esc "$NEXTAUTH_SECRET")
    _LANGFUSE_INIT_USER_PASSWORD=$(_esc "$LANGFUSE_INIT_USER_PASSWORD")

    # Use sed based on OS (macOS sed requires empty extension for -i).
    # All REPLACE_ME variables use a regex that matches both bare
    # REPLACE_ME and suffixed forms (e.g. REPLACE_ME_64_HEX_...).
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed_i=(-i '')
    else
        sed_i=(-i)
    fi
    # Core
    sed "${sed_i[@]}" "s/^SECRET_KEY=REPLACE_ME.*$/SECRET_KEY=$_SECRET_KEY/" .env
    sed "${sed_i[@]}" "s/^ENCRYPTION_KEY=REPLACE_ME.*$/ENCRYPTION_KEY=$_ENCRYPTION_KEY/" .env
    sed "${sed_i[@]}" "s/^POSTGRES_PASSWORD=REPLACE_ME.*$/POSTGRES_PASSWORD=$_POSTGRES_PASSWORD/" .env
    sed "${sed_i[@]}" "s/^RABBITMQ_DEFAULT_PASS=REPLACE_ME.*$/RABBITMQ_DEFAULT_PASS=$_RABBITMQ_DEFAULT_PASS/" .env
    sed "${sed_i[@]}" "s|^QDRANT_API_KEY=change-me-qdrant-key|QDRANT_API_KEY=$_QDRANT_API_KEY|" .env
    # Observability / Grafana
    sed "${sed_i[@]}" "s/^GRAFANA_ADMIN_PASSWORD=REPLACE_ME.*$/GRAFANA_ADMIN_PASSWORD=$_GRAFANA_ADMIN_PASSWORD/" .env
    # Langfuse tracing stack
    sed "${sed_i[@]}" "s/^LANGFUSE_POSTGRES_PASSWORD=REPLACE_ME.*$/LANGFUSE_POSTGRES_PASSWORD=$_LANGFUSE_POSTGRES_PASSWORD/" .env
    sed "${sed_i[@]}" "s/^CLICKHOUSE_PASSWORD=REPLACE_ME.*$/CLICKHOUSE_PASSWORD=$_CLICKHOUSE_PASSWORD/" .env
    sed "${sed_i[@]}" "s/^REDIS_PASSWORD=REPLACE_ME.*$/REDIS_PASSWORD=$_REDIS_PASSWORD/" .env
    sed "${sed_i[@]}" "s/^MINIO_ROOT_PASSWORD=REPLACE_ME.*$/MINIO_ROOT_PASSWORD=$_MINIO_ROOT_PASSWORD/" .env
    sed "${sed_i[@]}" "s/^LANGFUSE_ENCRYPTION_KEY=REPLACE_ME.*$/LANGFUSE_ENCRYPTION_KEY=$_LANGFUSE_ENCRYPTION_KEY/" .env
    sed "${sed_i[@]}" "s/^LANGFUSE_SALT=REPLACE_ME.*$/LANGFUSE_SALT=$_LANGFUSE_SALT/" .env
    sed "${sed_i[@]}" "s/^NEXTAUTH_SECRET=REPLACE_ME.*$/NEXTAUTH_SECRET=$_NEXTAUTH_SECRET/" .env
    sed "${sed_i[@]}" "s/^LANGFUSE_INIT_USER_PASSWORD=REPLACE_ME.*$/LANGFUSE_INIT_USER_PASSWORD=$_LANGFUSE_INIT_USER_PASSWORD/" .env

    echo "[+] .env created and configured with new secrets."
else
    echo "[!] .env already exists. Preserving existing secrets."

    # ------------------------------------------------------------------
    # Upgrade fix-ups: detect and repair missing or placeholder secrets
    # in .env files created before the current .env.example template.
    # Three categories:
    #   1. Key missing entirely → generate + append
    #   2. Value is REPLACE_ME* or old placeholder → generate + inline replace
    #   3. Deprecated keys → remove
    # ------------------------------------------------------------------

    # Escape for the replacement side of a sed s/// command.
    _esc() { printf '%s\n' "$1" | sed -e 's/[\/&]/\\&/g'; }
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed_i=(-i '')
    else
        sed_i=(-i)
    fi

    # -- _sccap_upgrade_secret <key> <gen-type> [<old-value-pattern>] ----
    # Ensures KEY has a generated secret. If KEY is missing entirely,
    # appends it. If KEY has an old/placeholder value (matched by
    # old-value-pattern or REPLACE_ME), replaces inline. Otherwise leaves
    # it alone.
    # gen-type: "random" | "fernet" | "hex64" (openssl rand -hex 32)
    _sccap_upgrade_secret() {
        local key="$1" gentype="$2" old_pattern="${3:-}"
        local val esc
        if ! grep -q "^${key}=" .env; then
            # Missing — generate and append.
            case "$gentype" in
                random) val=$(python3 scripts/generate_secrets.py random) ;;
                fernet) val=$(python3 scripts/generate_secrets.py fernet) ;;
                hex64)  val=$(openssl rand -hex 32) ;;
                *) echo "[!] Unknown gen-type $gentype for $key; skipping." >&2; return 1 ;;
            esac
            esc=$(_esc "$val")
            echo "${key}=${val}" >> .env
            echo "   + added ${key}"
            return 0
        fi
        # Present — check if it's a placeholder.
        local need_replace=0
        if [ -n "$old_pattern" ] && grep -q "^${key}=${old_pattern}$" .env; then
            need_replace=1
        elif grep -q "^${key}=REPLACE_ME" .env; then
            need_replace=1
        fi
        if [ "$need_replace" -eq 1 ]; then
            case "$gentype" in
                random) val=$(python3 scripts/generate_secrets.py random) ;;
                fernet) val=$(python3 scripts/generate_secrets.py fernet) ;;
                hex64)  val=$(openssl rand -hex 32) ;;
            esac
            esc=$(_esc "$val")
            sed "${sed_i[@]}" "s|^${key}=.*|${key}=${esc}|" .env
            echo "   ~ replaced placeholder ${key}"
        fi
    }

    # Deprecated keys to purge.
    if grep -q '^RAG_VECTOR_STORE=' .env; then
        echo " -> Removing retired RAG_VECTOR_STORE entry (ADR-008)..."
        sed "${sed_i[@]}" '/^RAG_VECTOR_STORE=/d' .env
    fi

    # Patch all secrets that docker-compose or the app require.
    echo " -> Checking for missing/placeholder secrets..."
    _sccap_upgrade_secret SECRET_KEY random
    _sccap_upgrade_secret ENCRYPTION_KEY fernet
    _sccap_upgrade_secret POSTGRES_PASSWORD random
    _sccap_upgrade_secret RABBITMQ_DEFAULT_PASS random
    _sccap_upgrade_secret QDRANT_API_KEY random 'change-me-qdrant-key'
    _sccap_upgrade_secret GRAFANA_ADMIN_PASSWORD random
    _sccap_upgrade_secret LANGFUSE_POSTGRES_PASSWORD random
    _sccap_upgrade_secret CLICKHOUSE_PASSWORD random
    _sccap_upgrade_secret REDIS_PASSWORD random
    _sccap_upgrade_secret MINIO_ROOT_PASSWORD random
    _sccap_upgrade_secret LANGFUSE_ENCRYPTION_KEY hex64
    _sccap_upgrade_secret LANGFUSE_SALT random
    _sccap_upgrade_secret NEXTAUTH_SECRET random
    _sccap_upgrade_secret LANGFUSE_INIT_USER_PASSWORD random
    # GRAFANA_ADMIN_USER is not a secret but must exist for compose.
    if ! grep -q '^GRAFANA_ADMIN_USER=' .env; then
        echo "GRAFANA_ADMIN_USER=admin" >> .env
        echo "   + added GRAFANA_ADMIN_USER"
    fi
    echo "[+] Secrets audit complete."
fi
flock -u 9

# 2.4. Installation Variant (modular setup)
# ----------------------------------------------------------------------
# Picks which features SCCAP enables. Written to .env as SCCAP_VARIANT (the
# app seeds its feature flags from it on first boot) and COMPOSE_PROFILES
# (which optional container stacks boot). Re-running setup.sh on an existing
# .env that predates modular setup simply adds both keys.
echo ""
echo "[*] Installation Variant:"
echo "  Choose how much of SCCAP to enable. You can change this later."
echo "    1) Vibe coder  — scan + chat + compliance; single superuser"
echo "    2) Developer   — adds multi-user, groups, email, MCP, authoring"
echo "    3) Enterprise  — everything: SSO, SCIM, tenants, log stack"
echo "    4) Custom      — pick the optional container stacks yourself"
echo "  (Upgrading an existing install? Enterprise keeps every feature you have.)"
SCCAP_VARIANT=""
COMPOSE_PROFILES_VALUE=""
while [ -z "$SCCAP_VARIANT" ]; do
    read -p "Your choice (1/2/3/4): " vchoice
    case "$vchoice" in
        1) SCCAP_VARIANT="vibe_coder"; COMPOSE_PROFILES_VALUE="" ;;
        2) SCCAP_VARIANT="developer";  COMPOSE_PROFILES_VALUE="" ;;
        3) SCCAP_VARIANT="enterprise"; COMPOSE_PROFILES_VALUE="log_stack" ;;
        4)
            SCCAP_VARIANT="custom"
            _custom_profiles=""
            read -p "  Enable the log stack — Grafana/Loki dashboards + Fluentd? (y/N): " _ls_choice
            case "$_ls_choice" in
                [Yy]*) _custom_profiles="log_stack" ;;
            esac
            read -p "  Enable Langfuse LLM tracing — 6 extra containers? (y/N): " _tr_choice
            case "$_tr_choice" in
                [Yy]*) _custom_profiles="${_custom_profiles:+$_custom_profiles,}tracing" ;;
            esac
            COMPOSE_PROFILES_VALUE="$_custom_profiles"
            ;;
        *) echo "  Invalid choice. Please enter 1, 2, 3, or 4." ;;
    esac
done
echo "[+] Variant: $SCCAP_VARIANT  (compose profiles: ${COMPOSE_PROFILES_VALUE:-none})"

# Is the log stack active? Drives the host-wide daemon.json prompt below.
case ",${COMPOSE_PROFILES_VALUE}," in
    *,log_stack,*) _LOG_STACK_ON=1 ;;
    *) _LOG_STACK_ON=0 ;;
esac

# Persist SCCAP_VARIANT and COMPOSE_PROFILES to .env (create-or-replace).
_sccap_set_env_kv() {
    local key="$1" val="$2" esc
    esc=$(printf '%s\n' "$val" | sed -e 's/[\/&]/\\&/g')
    if grep -q "^${key}=" .env; then
        if [[ "$OSTYPE" == "darwin"* ]]; then
            sed -i '' "s/^${key}=.*$/${key}=${esc}/" .env
        else
            sed -i "s/^${key}=.*$/${key}=${esc}/" .env
        fi
    else
        echo "${key}=${val}" >> .env
    fi
}
_sccap_set_env_kv "SCCAP_VARIANT" "$SCCAP_VARIANT"
_sccap_set_env_kv "COMPOSE_PROFILES" "$COMPOSE_PROFILES_VALUE"
echo "[+] Wrote SCCAP_VARIANT and COMPOSE_PROFILES to .env."

# 2.5. Deployment Configuration Prompt
echo ""
echo "[*] Deployment Configuration Options:"

STATE=1
DEPLOYMENT_TYPE=""
SSL_ENABLED="false"
SSL_DOMAIN=""

while true; do
    case $STATE in
        1)
            echo ""
            echo "Select Deployment Environment:"
            echo "  1) Local (Testing/Development)"
            echo "  2) Cloud (Production Server)"
            echo "  0) Exit Setup"
            read -p "Your choice (1/2/0): " choice
            if [ -z "$choice" ] && [ "$SCCAP_VARIANT" = "vibe_coder" ]; then
                choice=1
                echo "  (defaulting to Local for the vibe-coder variant)"
            fi
            if [ "$choice" = "1" ]; then
                DEPLOYMENT_TYPE="local"
                SSL_ENABLED="false"
                STATE=4
            elif [ "$choice" = "2" ]; then
                DEPLOYMENT_TYPE="cloud"
                STATE=2
            elif [ "$choice" = "0" ]; then
                echo "Setup cancelled."
                exit 0
            else
                echo "Invalid choice. Please enter 1, 2, or 0."
            fi
            ;;
        2)
            echo ""
            echo "Would you like to auto-provision a free Let's Encrypt SSL Certificate?"
            echo "  1) Yes (I have a valid domain pointing to this server's IP)"
            echo "  2) No (I will access via IP or configure SSL manually)"
            echo "     WARNING: Choosing No exposes your deployment over cleartext HTTP."
            echo "  0) Go Back"
            read -p "Your choice (1/2/0): " choice
            if [ "$choice" = "1" ]; then
                SSL_ENABLED="true"
                STATE=3
            elif [ "$choice" = "2" ]; then
                echo ""
                echo "  [!] SECURITY WARNING: Running a cloud deployment without TLS transmits"
                echo "      all data (including credentials) in cleartext over the public Internet."
                read -p "  To confirm you accept this risk, type YES_I_UNDERSTAND_PLAINTEXT: " ssl_risk_confirm
                if [ "$ssl_risk_confirm" = "YES_I_UNDERSTAND_PLAINTEXT" ]; then
                    SSL_ENABLED="false"
                    STATE=4
                else
                    echo "  Confirmation not accepted. Returning to SSL selection."
                fi
            elif [ "$choice" = "0" ]; then
                STATE=1
            else
                echo "Invalid choice. Please enter 1, 2, or 0."
            fi
            ;;
        3)
            echo ""
            read -p "Please enter your domain name/IP (e.g., example.com or 192.168.1.100) [or type '0' to go back]: " choice
            if [ "$choice" = "0" ]; then
                STATE=2
            elif [ -z "$choice" ]; then
                echo "Domain cannot be blank. Please provide a valid domain or IP."
            elif ! [[ "$choice" =~ ^[A-Za-z0-9]([A-Za-z0-9.\-]*[A-Za-z0-9])?$ ]] && \
                 ! [[ "$choice" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
                echo "Invalid domain or IP. Use only letters, digits, dots, and hyphens."
            else
                SSL_DOMAIN="$choice"
                STATE=4
            fi
            ;;
        4)
            echo ""
            echo "Please confirm your configuration:"
            echo "-----------------------------------"
            if [ "$DEPLOYMENT_TYPE" = "local" ]; then
                echo "Environment: Local Testing"
                echo "SSL Mode:    Disabled (Port 80)"
            else
                echo "Environment: Cloud Deployment"
                if [ "$SSL_ENABLED" = "true" ]; then
                    echo "SSL Mode:    Enabled via Let's Encrypt"
                    echo "Domain:      $SSL_DOMAIN"
                else
                    echo "SSL Mode:    Disabled (Port 80 via IP)"
                fi
            fi
            echo "-----------------------------------"
            echo "  1) Proceed with Setup"
            echo "  0) Go Back to change settings"
            read -p "Your choice (1/0): " choice
            
            if [ "$choice" = "1" ]; then
                break
            elif [ "$choice" = "0" ]; then
                if [ "$DEPLOYMENT_TYPE" = "local" ]; then
                    STATE=1
                elif [ "$SSL_ENABLED" = "false" ]; then
                    STATE=2
                else
                    STATE=3
                fi
            else
                echo "Invalid choice. Please enter 1 or 0."
            fi
            ;;
    esac
done

echo ""
echo "[*] Saving Configuration..."
# Escape sed replacement-side metacharacters for any value written via sed (V01.2.9).
_esc() { printf '%s\n' "$1" | sed -e 's/[\/&]/\\&/g'; }
_DEPLOYMENT_TYPE=$(_esc "$DEPLOYMENT_TYPE")
_SSL_ENABLED=$(_esc "$SSL_ENABLED")
_SSL_DOMAIN=$(_esc "$SSL_DOMAIN")
if grep -q "^DEPLOYMENT_TYPE=" .env; then
    sed -i.bak "s/^DEPLOYMENT_TYPE=.*$/DEPLOYMENT_TYPE=$_DEPLOYMENT_TYPE/" .env
else
    echo "DEPLOYMENT_TYPE=$DEPLOYMENT_TYPE" >> .env
fi

if grep -q "^SSL_ENABLED=" .env; then
    sed -i.bak "s/^SSL_ENABLED=.*$/SSL_ENABLED=$_SSL_ENABLED/" .env
else
    echo "SSL_ENABLED=$SSL_ENABLED" >> .env
fi

if grep -q "^SSL_DOMAIN=" .env; then
    sed -i.bak "s/^SSL_DOMAIN=.*$/SSL_DOMAIN=$_SSL_DOMAIN/" .env
else
    if [ ! -z "$SSL_DOMAIN" ]; then
        echo "SSL_DOMAIN=$SSL_DOMAIN" >> .env
    fi
fi
rm -f .env.bak

# VITE_ALLOWED_HOSTS: used by the Vite dev-server config and passed as a
# Docker build arg. For cloud deploys with a domain, set to that domain;
# otherwise leave empty (localhost is always allowed).
if [ "$DEPLOYMENT_TYPE" = "cloud" ] && [ "$SSL_ENABLED" = "true" ] && [ -n "$SSL_DOMAIN" ]; then
    _VITE_ALLOWED_HOSTS=$(_esc "$SSL_DOMAIN,${SSL_DOMAIN}:443")
else
    _VITE_ALLOWED_HOSTS=""
fi
if grep -q "^VITE_ALLOWED_HOSTS=" .env; then
    sed -i.bak "s/^VITE_ALLOWED_HOSTS=.*$/VITE_ALLOWED_HOSTS=$_VITE_ALLOWED_HOSTS/" .env
else
    echo "VITE_ALLOWED_HOSTS=$_VITE_ALLOWED_HOSTS" >> .env
fi
rm -f .env.bak

echo "[+] Configuration saved."


# 2.7. Docker daemon log defaults (ADR-010 P2)
# ----------------------------------------------------------------------
# Belt-and-suspenders for the per-service `logging:` blocks in
# docker-compose.yml: also set host-wide json-file caps so any container
# an operator runs *outside* compose (e.g. ad-hoc `docker run`) inherits
# the bound. Three-branch root detection (P2-E2): EUID==0 vs sudo vs
# neither. Pre-existing /etc/docker/daemon.json is JSON-merged via
# python3 (P2-E1) — never `>`-overwritten — so operator keys like
# `data-root` or `registry-mirrors` are preserved. Backup written to
# /etc/docker/daemon.json.bak.sccap-<timestamp>.

_sccap_with_root() {
    # Run "$@" as root via the cleanest available channel. Never
    # interpolates user input into a shell string — argv only.
    if [ "$EUID" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        echo "[!] Neither root nor sudo available. As root, run:"
        echo "    $*"
        return 1
    fi
}

_sccap_render_daemon_json() {
    # Read the existing /etc/docker/daemon.json (or {}) and merge our
    # log-driver defaults conservatively: only add `log-driver` /
    # `log-opts` if absent, never clobber an operator-set value.
    # Output to $1 (a temp file).
    local out_path="$1"
    local existing="{}"
    if [ -f /etc/docker/daemon.json ]; then
        existing=$(_sccap_with_root cat /etc/docker/daemon.json) || return 1
    fi
    DAEMON_EXISTING="$existing" python3 - "$out_path" <<'PY'
import json
import os
import sys

raw = os.environ.get("DAEMON_EXISTING", "{}").strip() or "{}"
try:
    cfg = json.loads(raw)
except json.JSONDecodeError:
    print(f"[!] /etc/docker/daemon.json is not valid JSON; refusing to merge.", file=sys.stderr)
    sys.exit(2)
if not isinstance(cfg, dict):
    print("[!] /etc/docker/daemon.json must be a JSON object; refusing to merge.", file=sys.stderr)
    sys.exit(2)

changed = False
if "log-driver" not in cfg:
    cfg["log-driver"] = "json-file"
    changed = True
elif cfg["log-driver"] != "json-file":
    print(f"[!] Existing log-driver={cfg['log-driver']!r} preserved (only json-file is configured by SCCAP).", file=sys.stderr)

opts = cfg.setdefault("log-opts", {})
if not isinstance(opts, dict):
    print("[!] Existing log-opts is not a dict; refusing to merge.", file=sys.stderr)
    sys.exit(2)
for key, value in (("max-size", "50m"), ("max-file", "5")):
    if key not in opts:
        opts[key] = value
        changed = True

with open(sys.argv[1], "w", encoding="utf-8") as fh:
    json.dump(cfg, fh, indent=2, sort_keys=True)
    fh.write("\n")

sys.exit(0 if changed else 100)  # 100 = nothing to do
PY
}

echo ""
if [ "$_LOG_STACK_ON" != "1" ]; then
    echo "[*] Host-wide Docker log rotation: skipped (log stack not enabled for"
    echo "    this variant). Per-compose logging caps still bound SCCAP services."
else
echo "[*] Docker daemon log rotation (ADR-010 — bounded log volume):"
echo "    Sets host-wide json-file defaults (max-size 50m, max-file 5)"
echo "    via /etc/docker/daemon.json. This restarts the Docker daemon"
echo "    and will recreate ALL containers on this host (not just SCCAP)."
read -p "    Apply now? (type YES to confirm, anything else skips): " daemon_confirm
if [ "$daemon_confirm" = "YES" ]; then
    if ! command -v python3 >/dev/null 2>&1; then
        echo "[!] python3 unavailable; cannot merge JSON safely. Skipping."
    else
        _SCCAP_DAEMON_TMP=$(mktemp /tmp/sccap-daemon.json.XXXXXX) || { echo '[!] mktemp failed'; exit 1; }
        chmod 0600 "$_SCCAP_DAEMON_TMP"
        trap 'rm -f "$_SCCAP_DAEMON_TMP"' EXIT
        _sccap_render_status=0
        _sccap_render_daemon_json "$_SCCAP_DAEMON_TMP" || _sccap_render_status=$?
        case "$_sccap_render_status" in
            0)
                # Backup any existing daemon.json before atomic install.
                if _sccap_with_root test -f /etc/docker/daemon.json; then
                    BACKUP_PATH="/etc/docker/daemon.json.bak.sccap-$(date +%s)"
                    if _sccap_with_root cp -a /etc/docker/daemon.json "$BACKUP_PATH"; then
                        echo "    Existing daemon.json backed up to $BACKUP_PATH"
                    else
                        echo "[!] Backup failed; aborting daemon.json change."
                        rm -f "$_SCCAP_DAEMON_TMP"
                        exit 1
                    fi
                fi
                if _sccap_with_root install -m 0644 -o root -g root \
                       "$_SCCAP_DAEMON_TMP" /etc/docker/daemon.json; then
                    rm -f "$_SCCAP_DAEMON_TMP"
                    if [[ "$OSTYPE" == "darwin"* ]]; then
                        echo "[+] daemon.json updated. Restart Docker Desktop manually to apply."
                    else
                        if _sccap_with_root systemctl restart docker; then
                            echo "[+] Docker daemon restarted with new log defaults."
                        else
                            echo "[!] daemon.json updated but systemctl restart docker failed."
                            echo "    Restart docker manually (e.g. 'sudo systemctl restart docker')"
                            echo "    to apply, or restore from $BACKUP_PATH if needed."
                        fi
                    fi
                else
                    rm -f "$_SCCAP_DAEMON_TMP"
                    echo "[!] daemon.json install failed; existing file untouched."
                fi
                ;;
            100)
                echo "[+] daemon.json already had log-driver/log-opts; nothing to do."
                rm -f "$_SCCAP_DAEMON_TMP"
                ;;
            *)
                echo "[!] daemon.json render failed (exit $_sccap_render_status); skipping."
                rm -f "$_SCCAP_DAEMON_TMP"
                ;;
        esac
    fi
else
    echo "    Skipped. Per-compose `logging:` blocks still bound SCCAP services;"
    echo "    only ad-hoc \`docker run\` containers on this host stay unbounded."
fi
fi


# 2. Environment Setup (Cont.)
# CORS Configuration is now handled in the Setup Wizard UI.


# 3. Docker Build and Launch
echo "[*] Launching Docker containers (this may take a few minutes)..."
# We need to ensure the VITE variables are available to the build context
# Sourcing .env is one way, but docker compose reads .env automatically
docker compose up -d --build

echo "[*] Waiting for database to be healthy..."
# Simple wait loop for db container
MAX_RETRIES=30
COUNT=0
until [ "$(docker inspect -f '{{.State.Health.Status}}' sccap_db 2>/dev/null)" == "healthy" ]; do
    if [ $COUNT -gt $MAX_RETRIES ]; then
        echo "Error: Database failed to become healthy in time."
        exit 1
    fi
    printf "."
    sleep 2
    COUNT=$((COUNT+1))
done
echo ""
echo "[+] Database is healthy."
echo ""

# 4. Database Migrations & Initial Data
echo "[*] Applying database migrations..."
docker compose exec app alembic upgrade head

echo "[+] Database initialized. Proceed to the Web UI to create your Admin Superuser."
echo ""

echo "=================================================="
echo "   Setup Complete!"
echo "=================================================="
echo ""
echo "Access the application at:"
if [ "$DEPLOYMENT_TYPE" = "local" ]; then
    echo "   -> http://localhost (Production build via Docker)"
    echo "   -> http://localhost:5173 (If running UI dev server)"
else
    if [ "$SSL_ENABLED" = "true" ]; then
        echo "   -> https://$SSL_DOMAIN"
    else
        echo "Refusing to advertise a cleartext URL for cloud deployments."
        echo "Re-run the wizard with SSL enabled (Let's Encrypt) or use Local mode for development."
        exit 1
    fi
fi
echo ""
echo "Access Grafana at:"
if [ "$DEPLOYMENT_TYPE" = "local" ]; then
    echo "   -> http://localhost:3000"
else
    if [ "$SSL_ENABLED" = "true" ]; then
        echo "   -> https://$SSL_DOMAIN:3000"
    else
        echo "   Grafana not exposed publicly. Tunnel via SSH (-L 3000:localhost:3000) to reach the dashboard."
    fi
fi
echo ""
