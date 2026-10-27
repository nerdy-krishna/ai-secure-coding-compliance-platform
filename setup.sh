#!/bin/bash
set -e

# setup.sh - Easy Installation Script for SCCAP

# ----------------------------------------------------------------------
# Helpers (defined early so prerequisite checks can use them).
# ----------------------------------------------------------------------

# Stage marker for resumable setup: records the step that is about to run so a
# re-run can offer to skip already-completed configuration and retry the step
# that failed.
_SETUP_STAGE_FILE=".setup-stage"
_sccap_stage() { echo "$1" > "$_SETUP_STAGE_FILE"; }

_sccap_with_root() {
    # Run "$@" as root via the cleanest available channel (argv only).
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

_sccap_docker_official_repo() {
    # Add Docker's official apt repository for Ubuntu/Debian and install
    # docker-ce + the Compose plugin. Returns non-zero if download.docker.com
    # is unreachable or apt fails, so the caller can offer alternatives.
    local codename arch
    codename="${VERSION_CODENAME:-}"
    arch="$(dpkg --print-architecture 2>/dev/null || uname -m)"
    [ -n "$codename" ] || codename="stable"
    echo "[*] Adding Docker's official apt repository (https://download.docker.com/linux/${ID})..."
    _sccap_with_root apt-get install -y ca-certificates curl gnupg >/dev/null || return 1
    _sccap_with_root install -m 0755 -d /etc/apt/keyrings || return 1
    local tmp_gpg
    tmp_gpg="$(mktemp /tmp/docker.gpg.XXXXXX)" || return 1
    if ! curl -fsSL "https://download.docker.com/linux/${ID}/gpg" -o "$tmp_gpg"; then
        echo "[!] Could not download Docker's GPG key — download.docker.com is unreachable."
        rm -f "$tmp_gpg"
        return 1
    fi
    if ! _sccap_with_root gpg --dearmor -o /etc/apt/keyrings/docker.gpg "$tmp_gpg" 2>/dev/null; then
        _sccap_with_root install -m 0644 -o root -g root "$tmp_gpg" /etc/apt/keyrings/docker.gpg || { rm -f "$tmp_gpg"; return 1; }
    fi
    rm -f "$tmp_gpg"
    _sccap_with_root chmod a+r /etc/apt/keyrings/docker.gpg || true
    echo "deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${ID} ${codename} stable" \
        | _sccap_with_root tee /etc/apt/sources.list.d/docker.list >/dev/null || return 1
    if ! _sccap_with_root apt-get update -y; then
        echo "[!] apt-get update failed — the Docker repository is unreachable."
        return 1
    fi
    _sccap_with_root apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin || return 1
    _sccap_with_root systemctl enable --now docker 2>/dev/null || true
    return 0
}

_sccap_install_docker_distro() {
    # Distro-packaged Docker (may be older than the official repo).
    echo "[*] Installing Docker from the distro package..."
    case "${ID:-}" in
        ubuntu|debian)
            _sccap_with_root apt-get update -y
            _sccap_with_root apt-get install -y docker.io docker-compose-v2 \
                || _sccap_with_root apt-get install -y docker.io docker-compose-plugin
            ;;
        rhel|centos|fedora|rocky|almalinux|amzn)
            _sccap_with_root dnf install -y docker docker-compose-plugin \
                || _sccap_with_root yum install -y docker docker-compose-plugin
            ;;
        *) return 1 ;;
    esac
    _sccap_with_root systemctl enable --now docker 2>/dev/null || true
    return 0
}

_sccap_platform_guide() {
    # Print manual Docker install guidance for a cloud platform.
    case "$1" in
        azure)
            echo ""
            echo "=== Azure: installing Docker manually ==="
            echo "  1) Convenience script (needs HTTPS 443 egress):"
            echo "       curl -fsSL https://get.docker.com | sudo sh"
            echo "  2) Distro package:"
            echo "       sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2"
            echo "  3) Or re-deploy this VM from an Ubuntu image and allow outbound 443."
            echo "  If download.docker.com is blocked, allow HTTPS 443 in the VM's NSG,"
            echo "  or mirror Docker images/repo through Artifactory/Azure Container Registry."
            ;;
        aws)
            echo ""
            echo "=== AWS: installing Docker manually ==="
            echo "  1) Amazon Linux 2023:"
            echo "       sudo dnf install -y docker && sudo systemctl enable --now docker"
            echo "       sudo dnf install -y docker-compose-plugin"
            echo "  2) Ubuntu: sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2"
            echo "  3) Or launch an ECS-optimized AMI (Docker preinstalled)."
            echo "  If download.docker.com is blocked, allow HTTPS 443 via the security group/NAT."
            ;;
        gcp)
            echo ""
            echo "=== GCP: installing Docker manually ==="
            echo "  1) Easiest: use a Container-Optimized OS VM (Docker preinstalled)."
            echo "  2) Debian/Ubuntu: sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2"
            echo "  3) If download.docker.com is blocked, allow HTTPS 443 egress or use a"
            echo "     private mirror (Artifact Registry / Nexus)."
            ;;
    esac
    echo ""
}

_sccap_docker_fallback_menu() {
    # The official repo was unreachable; offer distro package or platform guidance.
    while true; do
        echo "Choose an alternate Docker installation method:"
        echo "  1) Distro package (docker.io + docker-compose-v2) — simplest, may be older"
        echo "  2) Show manual instructions for Azure"
        echo "  3) Show manual instructions for AWS"
        echo "  4) Show manual instructions for GCP"
        echo "  0) Skip (I will install Docker manually and re-run)"
        read -p "Your choice (1/2/3/4/0): " _dk_choice
        case "$_dk_choice" in
            1) _sccap_install_docker_distro && return 0 ; echo "[!] Distro-package install failed." ;;
            2) _sccap_platform_guide azure ;;
            3) _sccap_platform_guide aws ;;
            4) _sccap_platform_guide gcp ;;
            0) echo "[!] Docker not installed. Install Docker manually, then re-run ./setup.sh."; return 1 ;;
            *) echo "Invalid choice." ;;
        esac
    done
}

_sccap_install_docker() {
    # Install Docker Engine + Compose. Ubuntu/Debian try the official Docker
    # apt repo first (pinned, current); if download.docker.com is unreachable,
    # fall back to the distro package or platform-specific manual guidance.
    echo "[*] Installing Docker Engine + Compose plugin..."
    if ! _sccap_with_root true >/dev/null 2>&1; then
        echo "[!] sudo/root is required to install Docker. Install Docker manually, then re-run."
        return 1
    fi
    if [ -f /etc/os-release ]; then
        . /etc/os-release
    else
        echo "[!] /etc/os-release not found. Install Docker manually, then re-run."
        return 1
    fi
    case "${ID:-}" in
        ubuntu|debian)
            _sccap_docker_official_repo && return 0
            echo ""
            echo "[!] The official Docker repository (download.docker.com) was not reachable."
            echo "    This usually means outbound HTTPS 443 is blocked on this host."
            _sccap_docker_fallback_menu
            return $?
            ;;
        rhel|centos|fedora|rocky|almalinux|amzn)
            if _sccap_install_docker_distro; then
                return 0
            fi
            echo "[!] Distro Docker install failed."
            _sccap_docker_fallback_menu
            return $?
            ;;
        *)
            echo "[!] Unrecognized distro '${ID:-unknown}'. Install Docker manually, then re-run."
            return 1
            ;;
    esac
}

_sccap_ensure_docker() {
    # Docker present, Compose present, socket reachable, and current user in the
    # docker group.  Installs what is missing and re-enters the script with the
    # docker group active when the socket is denied, so no further permission
    # failures occur mid-setup.
    if ! command -v docker >/dev/null 2>&1; then
        _sccap_install_docker || return 1
    fi
    if ! docker compose version >/dev/null 2>&1; then
        echo "[*] Docker Compose plugin missing; installing..."
        _sccap_install_docker || return 1
    fi
    if docker info >/dev/null 2>&1; then
        return 0
    fi
    # Socket denied: almost always the user isn't in the docker group.
    if ! id -nG "$(whoami)" 2>/dev/null | grep -qw docker; then
        echo "[*] Adding '$(whoami)' to the docker group..."
        _sccap_with_root usermod -aG docker "$(whoami)" 2>/dev/null || {
            echo "[!] Could not add '$(whoami)' to the docker group (sudo needed)."
            echo "    Run: sudo usermod -aG docker \$USER   then log out and back in."
            return 1
        }
    fi
    # Re-enter under the docker group. The current shell has not picked up the
    # new group yet; `sg` gives us a one-shot shell that has.
    if [ -z "${_SCCAP_REEXEC:-}" ] && command -v sg >/dev/null 2>&1; then
        export _SCCAP_REEXEC=1
        echo "[*] Re-entering setup with the docker group active..."
        exec sg docker -c "$(printf '%q ' "$0" "$@")"
    fi
    if ! docker info >/dev/null 2>&1; then
        echo "[!] Docker socket is still not accessible after adding the group."
        echo "    Log out and back in, then re-run ./setup.sh (it resumes where it stopped)."
        return 1
    fi
    return 0
}

_sccap_generate_selfsigned() {
    # Generate a self-signed cert and drop it where the nginx entrypoint looks
    # (certbot/conf/live/<domain>/fullchain.pem + privkey.pem). The entrypoint
    # skips certbot whenever that path already exists.
    local domain="$1" dir="certbot/conf/live/$domain"
    mkdir -p "$dir"
    if [ -f "$dir/fullchain.pem" ] && [ -f "$dir/privkey.pem" ]; then
        echo "[*] A certificate already exists for $domain; reusing it."
        return 0
    fi
    if ! command -v openssl >/dev/null 2>&1; then
        echo "[*] openssl missing; installing..."
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            case "${ID:-}" in
                ubuntu|debian) _sccap_with_root apt-get install -y openssl ;;
                rhel|centos|fedora|rocky|almalinux|amzn) _sccap_with_root dnf install -y openssl ;;
            esac
        fi
    fi
    local san
    if [[ "$domain" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
        san="IP:$domain"
    else
        san="DNS:$domain"
    fi
    echo "[*] Generating a self-signed certificate for $domain (365 days)..."
    openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
        -keyout "$dir/privkey.pem" -out "$dir/fullchain.pem" \
        -subj "/CN=$domain" -addext "subjectAltName=$san" 2>/dev/null
    chmod 600 "$dir/privkey.pem"
    echo "[+] Self-signed certificate written under $dir/."
    return 0
}

_sccap_install_own_cert() {
    # Copy an operator-supplied certificate (fullchain + key) into the
    # certbot/conf/live/<domain>/ layout the nginx entrypoint expects.
    local domain="$1" fullchain="$2" key="$3" dir="certbot/conf/live/$domain"
    mkdir -p "$dir"
    cp "$fullchain" "$dir/fullchain.pem" || { echo "[!] Could not copy $fullchain"; return 1; }
    cp "$key" "$dir/privkey.pem" || { echo "[!] Could not copy $key"; return 1; }
    chmod 600 "$dir/privkey.pem"
    echo "[+] Certificate installed under $dir/."
    return 0
}


echo "=================================================="
echo "   SCCAP - Setup Wizard"
echo "=================================================="
echo ""

# 1. Prerequisites Check (auto-install what is missing)
echo "[*] Checking prerequisites..."

# Python is needed by the env-secrets bootstrap and the daemon.json merge.
if ! command -v python3 >/dev/null 2>&1; then
    echo "[*] Python 3 missing; installing..."
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "${ID:-}" in
            ubuntu|debian) _sccap_with_root apt-get update -y && _sccap_with_root apt-get install -y python3 ;;
            rhel|centos|fedora|rocky|almalinux|amzn) _sccap_with_root dnf install -y python3 || _sccap_with_root yum install -y python3 ;;
        esac
    fi
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 could not be found or installed."
    exit 1
fi

# Docker Engine + Compose plugin + docker-group membership.
_sccap_ensure_docker || exit 1

# Note: Node.js is intentionally NOT a host prerequisite — the UI is built
# inside the `ui` Docker image, never on the host.

echo "[+] Prerequisites met."
echo ""

# Resume support: if a previous run stopped at the build/migrate step, offer to
# skip re-configuring and retry that step.
_RESUME=0
if [ -f "$_SETUP_STAGE_FILE" ]; then
    _prev_stage=$(cat "$_SETUP_STAGE_FILE" 2>/dev/null || true)
    case "$_prev_stage" in
        build|migrate)
            echo "[*] A previous setup stopped at the '$_prev_stage' step."
            read -p "    Resume from there (skip re-configuring)? (y/N): " _resume_choice
            case "$_resume_choice" in [Yy]*) _RESUME=1 ;; esac
            ;;
    esac
fi
_sccap_stage config

# 2. Environment Setup
echo "[*] Setting up environment configuration..."

exec 9>>.env.lock; flock -n 9 || { echo "[!] Another setup.sh is running; exiting."; exit 1; }
if [ ! -f .env ]; then
    echo " -> Copying .env.example to .env..."
    cp .env.example .env
    fresh_env=1
else
    echo "[!] .env already exists. Preserving existing secrets."
    fresh_env=0
fi

echo " -> Checking required environment secrets..."
python3 scripts/bootstrap_env_secrets.py --env-file .env
if [ "$fresh_env" -eq 1 ]; then
    echo "[+] .env created and configured with new secrets."
else
    echo "[+] Existing .env upgraded; valid secrets were preserved."
fi
flock -u 9

if [ "$_RESUME" != "1" ]; then
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
# 2.4b. Pentesting (authorized automated security assessment)
# ----------------------------------------------------------------------
# Enables the pentest engagement plane: the controller, runner, tool worker and
# verification coordinator profiles plus the capability flags the working local
# deployment uses. It does NOT install the tool runtimes (nmap/nuclei/zap/
# playwright) - those run via the Kubernetes attach runtime (cloud) or the local
# kind-cluster qualification, see docs/docs/operations/cloud-kubernetes-deployment.md.
_sccap_enable_pentesting() {
    for _flag in \
        PENTEST_FOUNDATION2_ENABLED PENTEST_FOUNDATION3_ENABLED \
        PENTEST_CAPABILITY4_ENABLED PENTEST_CAPABILITY5_ENABLED \
        PENTEST_CAPABILITY6_ENABLED PENTEST_CAPABILITY7_ENABLED \
        PENTEST_CAPABILITY8_SCHEMA_READ PENTEST_CAPABILITY8_ADAPTER_RECONCILE \
        PENTEST_CAPABILITY8_C6_INGRESS_RECONCILE PENTEST_CAPABILITY8_EVENT_V3 \
        PENTEST_CAPABILITY8_SOURCE_PROFILES PENTEST_CAPABILITY8_WHITE_BOX_API \
        PENTEST_CAPABILITY9_API PENTEST_CAPABILITY9_EVENT_V4 \
        PENTEST_CAPABILITY9_PIN_NEW_ATTEMPTS PENTEST_CAPABILITY9_RECONCILE \
        PENTEST_CAPABILITY9_SCHEMA_READ \
        PENTEST_CAPABILITY13_SAFE_API PENTEST_CAPABILITY13_SCHEMA_READ \
        PENTEST_CAPABILITY13_COCKPIT PENTEST_CAPABILITY13_REPORT_BUILDS \
        PENTEST_CAPABILITY13_PROTECTED_EXPORT PENTEST_CAPABILITY13_REDACTED_EXPORT \
        PENTEST_CAPABILITY13_EXPORT_RETENTION PENTEST_CAPABILITY13_INTEGRATIONS \
        PENTEST_CAPABILITY13_RETEST PENTEST_CAPABILITY13_GOVERNANCE_WRITES \
        PENTEST_C67_INGRESS_ENABLED PENTEST_VERIFICATION_COORDINATOR_ENABLED \
        PENTEST_PROJECT_AUTHENTICATION_ENABLED PENTEST_PROJECT_SESSION_REUSE_ENABLED \
        PENTEST_IDENTITY_RUNTIME_ENABLED PENTEST_LOCAL_BLACKBOX_BENCHMARK_ENABLED; do
        _sccap_set_env_kv "$_flag" "true"
    done
    _sccap_set_env_kv "PENTEST_LOCAL_FIXTURE_ORIGINS" "http://juice-shop:3000"
    _sccap_set_env_kv "PENTEST_RUNNER_SUBNET" "172.16.242.0/28"
    # Do NOT guess the protected/private network lists - they are deployment-
    # specific. Leave them empty and warn the operator to set them.
}

echo ""
echo "[*] Pentesting:"
echo "  Authorized automated security assessment (engagement plane, runner,"
echo "  controller, tool worker, verification coordinator)."
read -p "  Enable pentesting? (y/N): " _pentest_choice
case "$_pentest_choice" in
    [Yy]*)
        COMPOSE_PROFILES_VALUE="${COMPOSE_PROFILES_VALUE:+$COMPOSE_PROFILES_VALUE,}pentesting-v3,pentesting-v4,pentesting-v5,pentesting-c67"
        _sccap_enable_pentesting
        _PENTEST_NOTE="Pentesting workers enabled. Tool runtimes (nmap/nuclei/zap/playwright) need the Kubernetes attach runtime or the local kind-cluster qualification; configure PENTEST_PROTECTED_NETWORKS and PENTEST_PRIVATE_NETWORK_PROFILES before running an engagement."
        echo "[+] Pentesting enabled."
        read -p "  Set up a local kind cluster for the pentest tool runtimes (VM install)? (y/N): " _kind_choice
        case "$_kind_choice" in
            [Yy]*)
                _PENTEST_KIND=1
                _PENTEST_NOTE="Pentesting + local kind cluster. The kind cluster is created by scripts/pentesting/setup-kind.sh after the containers start; build/publish the tool-runtime images first (scripts/build-tool-runtimes.sh)."
                echo "[+] Kind cluster will be set up after the containers start."
                ;;
        esac
        ;;
    *) echo "[ ] Pentesting skipped." ;;
esac

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
SSL_MODE=""
SSL_DEV_INSECURE="false"
SSL_CERT_FULLCHAIN=""
SSL_CERT_KEY=""

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
                SSL_MODE="none"
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
            echo "How would you like to secure the application over SSL?"
            echo "  1) Let's Encrypt      (free; needs a public domain pointing to this server)"
            echo "  2) Self-signed        (generated now; good for internal/testing)"
            echo "  3) My own certificate (enterprise / internal CA)"
            echo "  4) No TLS             (HTTP only — only behind a reverse proxy / private network)"
            echo "  0) Go Back"
            read -p "Your choice (1/2/3/4/0): " choice
            case "$choice" in
                1) SSL_MODE="letsencrypt"; SSL_ENABLED="true"; STATE=3 ;;
                2) SSL_MODE="selfsigned"; SSL_ENABLED="true"; STATE=3 ;;
                3) SSL_MODE="own"; SSL_ENABLED="true"; STATE=5 ;;
                4)
                    read -p "  Continue without TLS (HTTP only)? (y/N): " ssl_none_confirm
                    case "$ssl_none_confirm" in
                        [Yy]*) SSL_MODE="none"; SSL_ENABLED="false"; SSL_DEV_INSECURE="true"; STATE=4 ;;
                        *) echo "  Keeping TLS. Returning to SSL selection." ;;
                    esac
                    ;;
                0) STATE=1 ;;
                *) echo "Invalid choice. Please enter 1, 2, 3, 4, or 0." ;;
            esac
            ;;
        3)
            echo ""
            read -p "Please enter your domain name or IP (e.g. example.com or 192.168.1.100) [0 to go back]: " choice
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
        5)
            echo ""
            read -p "Domain name or IP the certificate is issued for [0 to go back]: " choice
            if [ "$choice" = "0" ]; then
                STATE=2
            elif [ -z "$choice" ]; then
                echo "Domain cannot be blank."
            else
                SSL_DOMAIN="$choice"
                echo ""
                read -p "Path to the full-chain certificate file (.pem/.crt): " cert_choice
                read -p "Path to the private key file (.key/.pem): " key_choice
                if [ -z "$cert_choice" ] || [ -z "$key_choice" ]; then
                    echo "Both paths are required."
                elif [ ! -f "$cert_choice" ] || [ ! -f "$key_choice" ]; then
                    echo "One of those files does not exist. Check the paths and try again."
                else
                    SSL_CERT_FULLCHAIN="$cert_choice"
                    SSL_CERT_KEY="$key_choice"
                    STATE=4
                fi
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
                case "$SSL_MODE" in
                    letsencrypt) echo "SSL Mode:    Let's Encrypt ($SSL_DOMAIN)" ;;
                    selfsigned)  echo "SSL Mode:    Self-signed ($SSL_DOMAIN)" ;;
                    own)         echo "SSL Mode:    Own certificate ($SSL_DOMAIN)" ;;
                    none)        echo "SSL Mode:    No TLS (HTTP, port 80)" ;;
                esac
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
                else
                    STATE=2
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

# SSL_MODE and SSL_DEV_INSECURE (new keys; default when absent).
if grep -q "^SSL_MODE=" .env; then
    sed -i.bak "s/^SSL_MODE=.*$/SSL_MODE=$SSL_MODE/" .env
else
    echo "SSL_MODE=$SSL_MODE" >> .env
fi
if grep -q "^SSL_DEV_INSECURE=" .env; then
    sed -i.bak "s/^SSL_DEV_INSECURE=.*$/SSL_DEV_INSECURE=$SSL_DEV_INSECURE/" .env
else
    echo "SSL_DEV_INSECURE=$SSL_DEV_INSECURE" >> .env
fi
rm -f .env.bak

# Prepare the certificate material for the nginx entrypoint.  Letsencrypt is
# fetched by certbot inside the UI container; self-signed is generated here and
# an operator-supplied certificate is copied into the same certbot/conf layout,
# which the entrypoint detects and serves without touching certbot.
if [ "$SSL_ENABLED" = "true" ] && [ -n "$SSL_DOMAIN" ]; then
    case "$SSL_MODE" in
        selfsigned) _sccap_generate_selfsigned "$SSL_DOMAIN" ;;
        own) _sccap_install_own_cert "$SSL_DOMAIN" "$SSL_CERT_FULLCHAIN" "$SSL_CERT_KEY" ;;
    esac
fi

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
# the bound. Pre-existing /etc/docker/daemon.json is JSON-merged via
# python3 (P2-E1) — never `>`-overwritten — so operator keys like
# `data-root` or `registry-mirrors` are preserved. Backup written to
# /etc/docker/daemon.json.bak.sccap-<timestamp>.

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
read -p "    Apply now? (y/N): " daemon_confirm
case "$daemon_confirm" in
    [Yy]*)
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
        ;;
    *)
        echo "    Skipped. Per-compose `logging:` blocks still bound SCCAP services;"
        echo "    only ad-hoc \`docker run\` containers on this host stay unbounded."
        ;;
esac
fi


# 2. Environment Setup (Cont.)
# CORS Configuration is now handled in the Setup Wizard UI.


fi  # resume: skip configuration prompts

# 3. Docker Build and Launch
_sccap_stage build
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
_sccap_stage migrate
echo "[*] Applying database migrations..."
docker compose exec app alembic upgrade head

echo "[+] Database initialized. Proceed to the Web UI to create your Admin Superuser."
echo ""

# 5. Local kind cluster for pentest tool runtimes (optional).
if [ "${_PENTEST_KIND:-0}" = "1" ]; then
    echo "[*] Setting up the local kind cluster for pentest tool runtimes..."
    if [ -x scripts/pentesting/setup-kind.sh ]; then
        bash scripts/pentesting/setup-kind.sh || echo "[!] kind setup failed; re-run scripts/pentesting/setup-kind.sh manually."
    else
        echo "[!] scripts/pentesting/setup-kind.sh not found."
    fi
fi

echo "=================================================="
echo "   Setup Complete!"
echo "=================================================="
echo ""
_sccap_stage done
echo "Access the application at:"
if [ "$DEPLOYMENT_TYPE" = "local" ]; then
    echo "   -> http://localhost (Production build via Docker)"
    echo "   -> http://localhost:5173 (If running UI dev server)"
else
    case "$SSL_MODE" in
        letsencrypt) echo "   -> https://$SSL_DOMAIN" ;;
        selfsigned)  echo "   -> https://$SSL_DOMAIN   (self-signed: browsers will warn until trusted)" ;;
        own)         echo "   -> https://$SSL_DOMAIN" ;;
        none)
            echo "   -> http://${SSL_DOMAIN:-<server-ip>}:80"
            echo "   [!] TLS is disabled; expose this only behind a reverse proxy/private network."
            ;;
    esac
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
if [ -n "${_PENTEST_NOTE:-}" ]; then
    echo ""
    echo "[*] Pentesting note:"
    echo "    $_PENTEST_NOTE"
fi
echo ""
