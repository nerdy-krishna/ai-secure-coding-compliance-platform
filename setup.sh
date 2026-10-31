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
            # docker-buildx: the Dockerfile uses BuildKit-only --mount=cache,
            # and scripts/build-tool-runtimes.sh calls `docker buildx` directly.
            # Ubuntu ships it as a separate package.
            _sccap_with_root apt-get install -y docker.io docker-compose-v2 docker-buildx \
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
    # nginx-https.conf uses `ssl_trusted_certificate .../chain.pem`. certbot
    # writes that file, a self-signed certificate does not - and without it
    # `nginx -t` fails, the UI container exits, and the browser reports
    # "connection closed" with nothing listening on 443.
    cp "$dir/fullchain.pem" "$dir/chain.pem"
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
    # Same reason as the self-signed path: `ssl_trusted_certificate` needs a
    # chain file, and an operator-supplied bundle is the only source we have.
    cp "$fullchain" "$dir/chain.pem" || true
    chmod 600 "$dir/privkey.pem"
    echo "[+] Certificate installed under $dir/."
    return 0
}

_sccap_provision_pentest_secrets() {
    # The better-pentester engine derives no signing/gateway secrets; nothing to provision.
    return 0
}


_sccap_ensure_evidence_bucket() {
    # Evidence writes call ensure_bucket() lazily, but the retention and orphan
    # sweepers list the bucket at startup. On a fresh install the bucket does not
    # exist yet, so those sweepers log NoSuchBucket errors every tick until the
    # first evidence write happens to create it. Create it once, through the
    # application's own store logic (which also enables versioning).
    local enabled
    enabled=$(grep -m1 '^EVIDENCE_STORE_ENABLED=' .env 2>/dev/null | cut -d= -f2-)
    [ "$enabled" = "true" ] || return 0
    # The API is still running its startup seeding right after the migration
    # step, so the first attempt can legitimately fail. Retry for ~90s before
    # giving up (the app also retries lazily on first write).
    local attempt
    for attempt in $(seq 1 15); do
        if docker compose exec -T app python -c "import asyncio; from app.infrastructure.evidence.object_store import EvidenceObjectStore; asyncio.run(EvidenceObjectStore().ensure_bucket())" >/dev/null 2>&1; then
            echo "[+] Evidence bucket ready."
            return 0
        fi
        sleep 6
    done
    echo "[!] Could not create the evidence bucket yet; evidence writes will retry at runtime."
    return 0
}

_sccap_explain_build_failure() {
    # Turn the two failures people actually hit into an instruction, instead of
    # leaving them to scroll a 5,000-line build log.
    local log="$1"
    [ -f "$log" ] || return 0
    if grep -q "changed significantly since poetry.lock was last generated" "$log"; then
        echo ""
        echo "[!] poetry.lock is out of sync with pyproject.toml (the Docker build stops at"
        echo "    'poetry install' because of it). Regenerate the lock, keeping every"
        echo "    existing pin, then re-run this installer:"
        echo ""
        echo "      docker run --rm -v \"$PWD\":/app -w /app python:3.12-slim \\"
        echo "        sh -c 'pip install \"poetry==1.8.3\" && poetry lock --no-update'"
        echo ""
        echo "    Then commit poetry.lock. Do not use a plain 'poetry lock': it re-resolves"
        echo "    every dependency and silently upgrades the runtime."
        return 0
    fi
    if grep -qiE "Killed|out of memory|Cannot allocate memory|exit code: 137" "$log"; then
        echo ""
        echo "[!] The build ran out of memory. Add swap (the installation guide has the"
        echo "    steps for a small VPS) or build on a machine with at least 4 GB free."
        return 0
    fi
    if grep -qiE "Temporary failure in name resolution|Could not resolve host|network is unreachable" "$log"; then
        echo ""
        echo "[!] A download inside the build could not reach the network. Check DNS and"
        echo "    outbound HTTPS, then re-run."
        return 0
    fi
    return 0
}


_sccap_align_fluentd_ownership() {
    # Fluentd runs as `fluent` (uid 100, gid 101) and writes its file buffer into
    # the ./fluentd/log bind mount. A root-owned directory (the checkout, or a
    # dir created by a `sudo` run) makes the worker die with
    # "Permission denied @ dir_s_mkdir - /fluentd/log/buffer" and every log line
    # is lost before it reaches Loki. Bind mounts keep host ownership, so hand
    # the tree to the fluentd user. The image is public and pinned by tag, so the
    # uid is fixed; resolve it from the image when it is already pulled.
    local img uid=100 gid=101
    img=$(docker compose config --images 2>/dev/null | grep -E -- '/fluentd$|fluentd:' | head -1)
    if [ -n "$img" ] && docker image inspect "$img" >/dev/null 2>&1; then
        uid=$(docker run --rm --entrypoint sh "$img" -c 'id -u' 2>/dev/null) || uid=100
        gid=$(docker run --rm --entrypoint sh "$img" -c 'id -g' 2>/dev/null) || gid=101
    fi
    case "$uid" in ''|*[!0-9]*) uid=100 ;; esac
    case "$gid" in ''|*[!0-9]*) gid=101 ;; esac
    mkdir -p fluentd/log/buffer fluentd/log/pos
    _sccap_with_root chown -R "$uid:$gid" fluentd/log 2>/dev/null || true
    _sccap_with_root chmod -R 775 fluentd/log 2>/dev/null || true
    echo "[+] fluentd buffer state owned by the fluentd user ($uid:$gid)."
    return 0
}


_sccap_align_certbot_ownership() {
    # The UI container runs as a non-root user (nginx-app) and certbot writes
    # into the ./certbot/conf bind mount. Bind mounts keep host ownership, so a
    # root-owned tree makes Let's Encrypt issuance and renewal die with
    # EACCES on /etc/letsencrypt/.certbot.lock. Once the UI image exists, hand
    # the tree to that image's user. Best-effort: a failure here is reported by
    # the UI entrypoint, not silently swallowed.
    local img uid gid
    img=$(docker compose config --images 2>/dev/null | grep -E -- '-ui$' | head -1)
    if [ -z "$img" ] || ! docker image inspect "$img" >/dev/null 2>&1; then
        # The compose project name may differ from the checkout directory (e.g. a
        # copy of the tree, or a renamed folder), in which case compose reports
        # images that were never built. Fall back to any local UI image so the
        # certificate handover does not silently do nothing.
        img=$(docker images --format '{{.Repository}}' 2>/dev/null | grep -E -- '-ui$' | head -1)
    fi
    [ -n "$img" ] || return 0
    docker image inspect "$img" >/dev/null 2>&1 || return 0
    uid=$(docker run --rm --entrypoint sh "$img" -c 'id -u' 2>/dev/null) || return 0
    gid=$(docker run --rm --entrypoint sh "$img" -c 'id -g' 2>/dev/null) || return 0
    case "$uid" in ''|*[!0-9]*) return 0 ;; esac
    case "$gid" in ''|*[!0-9]*) return 0 ;; esac
    [ "$uid" = "0" ] && return 0
    mkdir -p certbot/conf certbot/www
    _sccap_with_root chown -R "$uid:$gid" certbot/conf certbot/www || true
    echo "[+] certbot state owned by the UI container user ($uid:$gid)."
    return 0
}


# ----------------------------------------------------------------------
# First-run answers.
#
# These used to be asked twice: once here and again by the browser wizard at
# /setup. The wizard is gone, so the terminal asks everything the platform
# needs and app/cli/terminal_setup.py submits it to the API bootstrap endpoint.
# ----------------------------------------------------------------------
ADMIN_EMAIL=""
ADMIN_PASSWORD=""
LLM_MODE="multi_provider"
LLM_PROVIDER=""
LLM_MODEL=""
LLM_API_KEY=""
CUSTOM_FEATURES=""
GRAFANA_USER=""
GRAFANA_PASSWORD=""

_sccap_password_problem() {
    # Mirror of app/infrastructure/auth/schemas.py plus the context-term check
    # the bootstrap endpoint applies, so a bad password is rejected here rather
    # than after the whole stack has been built.
    _SCCAP_PW="$1" _SCCAP_EMAIL="$2" _SCCAP_DEPLOY="$3" python3 - <<'PYPW'
import os, re, sys
pw = os.environ.get("_SCCAP_PW", "")
email = os.environ.get("_SCCAP_EMAIL", "")
deploy = os.environ.get("_SCCAP_DEPLOY", "")
if len(pw) < 12:
    print("must be at least 12 characters"); raise SystemExit(0)
if len(pw) > 128:
    print("must be at most 128 characters"); raise SystemExit(0)
classes = sum(bool(re.search(p, pw)) for p in (r"[A-Z]", r"[a-z]", r"[0-9]", r"[^A-Za-z0-9]"))
if classes < 2:
    print("must mix at least two of uppercase, lowercase, digits, symbols"); raise SystemExit(0)
for token in ("sccap", "admin", "superuser", email.split("@")[0].lower(), deploy.lower()):
    if token and token in pw.lower():
        print("must not contain the term '%s'" % token); raise SystemExit(0)
print("")
PYPW
}

_sccap_read_masked() {
    # Read one secret line, echoing one '*' per character so the operator can see
    # that typing registered without exposing the value.
    #
    # Falls back to a plain silent read when stdin is not a TTY (an answers file
    # or a pipe), where per-character reading would echo stars into the log.
    local char answer=""
    if [ ! -t 0 ]; then
        IFS= read -r answer
        _SCCAP_ANSWER="$answer"
        return 0
    fi
    printf '%s' "$1"
    stty -echo 2>/dev/null || true
    while IFS= read -r -s -n 1 char; do
        case "$char" in
            "")
                break
                ;;
            $'\x7f'|$'\b')
                if [ -n "$answer" ]; then
                    answer="${answer%?}"
                    printf '\b \b'
                fi
                ;;
            *)
                answer+="$char"
                printf '*'
                ;;
        esac
    done
    stty echo 2>/dev/null || true
    echo
    _SCCAP_ANSWER="$answer"
}

_sccap_grafana_pw_problem() {
    # Grafana accepts any 8+ character secret; returning nothing here means the
    # value satisfies the policy and only the confirmation step is enforced.
    printf ''
}

_sccap_ask_secret() {
    # $1 prompt, $2 minimum length, $3 optional validator (empty = none, which
    # also skips the confirmation prompt; pass a no-op validator to require it)
    local first second problem
    while true; do
        _sccap_read_masked "$1"
        first="$_SCCAP_ANSWER"
        if [ "${#first}" -lt "$2" ]; then
            echo "  [!] Use at least $2 characters."
            continue
        fi
        if [ -n "$3" ]; then
            _sccap_read_masked "  Repeat to confirm: "
            second="$_SCCAP_ANSWER"
            if [ "$first" != "$second" ]; then
                echo "  [!] Values do not match."
                continue
            fi
            problem=$($3 "$first")
            if [ -n "$problem" ]; then
                echo "  [!] Password $problem."
                continue
            fi
        fi
        _SCCAP_ANSWER="$first"
        return 0
    done
}

_sccap_admin_pw_problem() { _sccap_password_problem "$1" "$ADMIN_EMAIL" "$DEPLOYMENT_TYPE"; }

_sccap_platform_bootstrapped() {
    # True when a superuser already exists (the API's setup status). Used on the
    # resume path: a run that died before first-run bootstrap must re-ask for the
    # administrator/LLM answers instead of submitting empty ones.
    docker compose exec -T app python -m app.cli.terminal_setup --check >/dev/null 2>&1
}

_sccap_is_ip() {
    printf '%s' "$1" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
}

_sccap_fix_evidence_endpoint() {
    # Older .env files pinned the compose service name, which CloudServer rejects
    # (its restEndpoints map does not contain it) - so the evidence bucket could
    # never be created and every evidence write failed at runtime.
    [ -f .env ] || return 0
    if grep -q '^EVIDENCE_S3_ENDPOINT=http://evidence-minio:8000' .env; then
        sed -i.bak 's|^EVIDENCE_S3_ENDPOINT=http://evidence-minio:8000|EVIDENCE_S3_ENDPOINT=http://cloudserver-front:8000|' .env
        rm -f .env.bak
        echo "[+] Evidence endpoint updated to the CloudServer alias (cloudserver-front)."
    fi
    return 0
}

_sccap_prepare_tls_material() {
    # Certificate material must exist whenever SSL_ENABLED=true, on a fresh run
    # *and* on a resumed one. It used to be created only in the configuration
    # branch, so resuming after a failure (or after --factory-reset deleted
    # ./certbot) left SSL_ENABLED=true with no certificate; the UI container
    # then tried certbot, which cannot issue for a private IP, and the browser
    # saw "connection closed".
    local enabled mode domain
    enabled=${SSL_ENABLED:-$(grep -m1 '^SSL_ENABLED=' .env 2>/dev/null | cut -d= -f2-)}
    mode=${SSL_MODE:-$(grep -m1 '^SSL_MODE=' .env 2>/dev/null | cut -d= -f2-)}
    domain=${SSL_DOMAIN:-$(grep -m1 '^SSL_DOMAIN=' .env 2>/dev/null | cut -d= -f2-)}
    [ "$enabled" = "true" ] || return 0
    [ -n "$domain" ] || return 0
    case "$mode" in
        selfsigned)
            _sccap_generate_selfsigned "$domain" || return 1
            # Generated as the invoking user (often root): the UI container's
            # UID must own the key or nginx cannot load it.
            _sccap_align_certbot_ownership || true
            ;;
        letsencrypt)
            if _sccap_is_ip "$domain"; then
                echo "[!] Let's Encrypt cannot issue a certificate for the IP $domain."
                echo "    Re-run ./setup.sh and pick 'Self-signed', or supply a public DNS name."
                return 1
            fi
            ;;
        own)
            if [ ! -f "certbot/conf/live/$domain/fullchain.pem" ]; then
                echo "[!] SSL mode is 'own certificate' but no certificate is installed for $domain."
                echo "    Re-run ./setup.sh and supply the fullchain and key files again."
                return 1
            fi
            ;;
    esac
    return 0
}

_SCCAP_DEPLOY_STATE=".scratch/deploy-state.json"

_sccap_git_sha() { git rev-parse HEAD 2>/dev/null || echo ""; }

_sccap_deploy_state_write() {
    # Remember what to go back to: revision, the image tags we overwrote, and the
    # database dump taken just before the upgrade.
    local commit="$1" backup="$2" images_json="$3"
    mkdir -p "$(dirname "$_SCCAP_DEPLOY_STATE")" 2>/dev/null || true
    cat > "$_SCCAP_DEPLOY_STATE" <<EOF
{"previous_commit": "${commit}", "backup": "${backup}", "images": ${images_json:-[]}, "updated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
EOF
    chmod 600 "$_SCCAP_DEPLOY_STATE" 2>/dev/null || true
}

_sccap_project_images_lenient() {
    # Like _sccap_project_images, but also accepts images whose repository does
    # not carry the checkout directory's name (a renamed or copied checkout).
    # Used only where over-matching is harmless - tagging for rollback - never
    # for destructive removal.
    _sccap_project_images
    docker compose config --images 2>/dev/null | sort -u \
        | grep -E -- '-(app|ui|worker|patch-validator|fluentd|disk-monitor|pentest-[a-z0-9-]+)$' \
        || true
}

_sccap_tag_rollback_images() {
    # Tag every image this checkout builds with the *outgoing* commit so a failed
    # upgrade can be reverted without a rebuild.
    local sha="$1" img out="[]"
    for img in $( { _sccap_project_images_lenient; } | sort -u ); do
        docker tag "$img" "${img}:rollback-${sha}" >/dev/null 2>&1 || continue
        out=$(printf '%s' "$out" | sed "s|]$|, \"${img}:rollback-${sha}\"]|; s|\[\]||")
    done
    printf '%s' "$out"
}

_sccap_wait_for_api() {
    local attempts="${1:-60}" i
    for i in $(seq 1 "$attempts"); do
        if docker compose exec -T app python -m app.cli.terminal_setup \
                --api-base http://127.0.0.1:8000 --check >/dev/null 2>&1; then
            return 0
        fi
        sleep 3
    done
    return 1
}

_SCCAP_CONTROL_DIR=".control"

_sccap_install_update_units() {
    # Optional host executor that lets a superuser start an update from the UI.
    # The API can only drop a request file into .control/; this systemd path unit
    # runs scripts/host-update.sh as root, which calls `setup.sh --update`.
    local repo_dir unit_dir
    if [ "$(uname -s)" != "Linux" ] || ! command -v systemctl >/dev/null 2>&1; then
        return 0
    fi
    if [ "$(id -u)" -ne 0 ]; then
        echo "[!] Skipping UI-triggered update service (needs root to install units)."
        echo "    Re-run with sudo to enable 'Update now' in the admin UI."
        return 0
    fi
    repo_dir=$(pwd -P)
    unit_dir=/etc/systemd/system
    # The app container runs as uid 1001 and must be able to create the request.
    mkdir -p "$repo_dir/$_SCCAP_CONTROL_DIR"
    chown 1001:1001 "$repo_dir/$_SCCAP_CONTROL_DIR" 2>/dev/null || true
    chmod 775 "$repo_dir/$_SCCAP_CONTROL_DIR" 2>/dev/null || true

    cat > "$unit_dir/sccap-update.service" <<EOF
[Unit]
Description=SCCAP host-side update runner (invoked from the admin UI)
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Environment=SCCAP_REPO_DIR=$repo_dir
ExecStart=/usr/bin/env bash $repo_dir/scripts/host-update.sh
TimeoutStartSec=3600
Nice=10
EOF

    cat > "$unit_dir/sccap-update.path" <<EOF
[Unit]
Description=Watch for an SCCAP update request from the application

[Path]
PathExists=$repo_dir/$_SCCAP_CONTROL_DIR/update-request
Unit=sccap-update.service

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload 2>/dev/null || true
    if systemctl enable --now sccap-update.path >/dev/null 2>&1; then
        echo "[+] UI-triggered updates enabled (sccap-update.path)."
    else
        echo "[!] Could not enable sccap-update.path; UI updates will report unavailable."
        echo "    Terminal equivalent: ./setup.sh --update"
    fi
    return 0
}

_sccap_install_pentest_runtimes() {
    # The better-pentester engine image already carries every scanner; nothing to install.
    return 0
}


_sccap_run_update() {
    command -v git >/dev/null 2>&1 || { echo "[!] git is required for --update."; return 1; }
    [ -f .env ] || { echo "[!] No .env here; run this from the install directory."; return 1; }
    [ -d .git ] || { echo "[!] This is not a git checkout; --update needs one."; return 1; }
    git rev-parse --abbrev-ref --symbolic-full-name '@{u}' >/dev/null 2>&1 || {
        echo "[!] Current branch has no upstream; set one or update manually."; return 1
    }

    local branch previous target backup
    branch=$(git rev-parse --abbrev-ref HEAD)
    previous=$(_sccap_git_sha)
    echo "[*] Updating branch '$branch' (currently ${previous:0:8})"
    git fetch --quiet origin || { echo "[!] git fetch failed."; return 1; }
    target=$(git rev-parse "origin/$branch")
    if [ "$target" = "$previous" ]; then
        echo "[+] Already up to date at ${previous:0:8}."
        return 0
    fi
    echo "    ${previous:0:8} -> ${target:0:8}"
    git log --oneline "${previous}..${target}" | head -10 | sed 's/^/      /'

    if ! _sccap_confirm "Apply this update? The stack restarts and the database is migrated." "update"; then
        echo "Aborted."
        return 1
    fi

    # 1. database backup before anything changes
    _PURGE_BACKUP_DIR="${SCCAP_BACKUP_DIR:-.deploy-backups}"
    echo "[*] Backing up the database..."
    _sccap_backup_database
    backup=$(ls -1t "$_PURGE_BACKUP_DIR"/pre-purge-*.sql 2>/dev/null | head -1)
    [ -n "$backup" ] && echo "    $backup"

    # 2. keep the outgoing images so --rollback needs no rebuild
    echo "[*] Tagging the current images for rollback..."
    local images
    images=$(_sccap_tag_rollback_images "$previous")
    _sccap_deploy_state_write "$previous" "$backup" "$images"

    # 3. move the checkout, prepare env, rebuild, restart
    git reset --hard "$target" --quiet || { echo "[!] git reset failed."; return 1; }
    _sccap_prepare_tls_material || return 1
    _sccap_fix_evidence_endpoint
    _sccap_fix_ownership
    echo "[*] Building images at ${target:0:8}..."
    local build_log=".build-${target:0:8}.log"
    if ! docker compose build \
        --build-arg "SCCAP_BUILD_COMMIT=$target" \
        --build-arg "SCCAP_BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)" 2>&1 | tee "$build_log"; then
        _sccap_explain_build_failure "$build_log"
        echo "[!] Build failed; full log: $build_log"
        echo "    Roll back with ./setup.sh --rollback"
        return 1
    fi
    _sccap_align_certbot_ownership
    _sccap_align_fluentd_ownership
    docker compose up -d || { echo "[!] Start failed; run ./setup.sh --rollback"; return 1; }
    # The broker applies the pentest users' passwords from .env only when its
    # container starts (rabbitmq/init.sh change_password). If an update rotates
    # those secrets, an untouched broker keeps the old ones and every pentest
    # consumer is refused with ACCESS_REFUSED - the controller then sits
    # "connected=false" and assessments never advance past decision.committed.
    echo "[*] Re-applying broker credentials..."
    docker compose up -d --no-build --force-recreate rabbitmq >/dev/null 2>&1 || true

    # 4. wait for the database, then migrate
    local count=0
    until [ "$(docker inspect -f '{{.State.Health.Status}}' sccap_db 2>/dev/null)" = "healthy" ]; do
        count=$((count + 1))
        if [ "$count" -gt 60 ]; then
            echo "[!] Database did not become healthy; run ./setup.sh --rollback"
            return 1
        fi
        sleep 2
    done
    echo "[*] Applying migrations..."
    if ! docker compose exec -T app alembic upgrade head; then
        echo "[!] Migration failed. The database backup is: ${backup:-none}"
        echo "    Run ./setup.sh --rollback (code+images), then restore the backup if needed."
        return 1
    fi

    # 5. health gate: the API must answer before we call this a success
    echo "[*] Waiting for the API to become healthy..."
    if ! _sccap_wait_for_api 60; then
        echo "[!] API did not come up healthy; run ./setup.sh --rollback"
        return 1
    fi

    _sccap_fix_ownership
    _sccap_install_update_units
    echo ""
    echo "[+] Update applied: ${previous:0:8} -> ${target:0:8}"
    echo "    Database backup: ${backup:-none}"
    echo "    Code + images rollback: ./setup.sh --rollback"
    return 0
}

_sccap_run_rollback() {
    [ -f "$_SCCAP_DEPLOY_STATE" ] || {
        echo "[!] No deploy state ($_SCCAP_DEPLOY_STATE); nothing to roll back to."
        return 1
    }
    local previous backup images
    previous=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("previous_commit",""))' "$_SCCAP_DEPLOY_STATE")
    backup=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("backup","") or "")' "$_SCCAP_DEPLOY_STATE")
    images=$(python3 -c 'import json,sys;print(" ".join(json.load(open(sys.argv[1])).get("images",[])))' "$_SCCAP_DEPLOY_STATE")
    [ -n "$previous" ] || { echo "[!] Deploy state has no previous commit."; return 1; }

    echo "[*] Rolling back code and images to ${previous:0:8}"
    if ! _sccap_confirm "Roll back the application? Migrations are NOT reversed." "rollback"; then
        echo "Aborted."
        return 1
    fi
    git reset --hard "$previous" --quiet || { echo "[!] git reset failed."; return 1; }
    local tagged
    for tagged in $images; do
        local original="${tagged%%:rollback-*}"
        docker tag "$tagged" "$original" >/dev/null 2>&1 \
            && echo "    restored $original"
    done
    docker compose up -d --no-build || { echo "[!] Failed to restart on the old images."; return 1; }
    _sccap_wait_for_api 40 || echo "[!] API did not come back healthy."
    echo ""
    echo "[+] Rolled back to ${previous:0:8}."
    echo "    Migrations were not reversed: if the newer release added schema, the"
    echo "    older code runs against it (usually harmless, additive). To restore"
    echo "    data as well:  docker compose exec -T db psql -U postgres -d secure_coding_platform \\"
    echo "                      < ${backup:-<backup file>}"
    return 0
}

_sccap_ask_first_run() {
    # Only asked on a fresh configuration run (skipped when resuming/upgrading).
    echo ""
    echo "[*] Administrator account (this is the UI login)"
    while true; do
        read -p "  Admin email: " ADMIN_EMAIL
        if python3 -c 'import re,sys; sys.exit(0 if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", sys.argv[1]) else 1)' "$ADMIN_EMAIL"; then
            break
        fi
        echo "  [!] Enter a valid email address."
    done
    _sccap_ask_secret "  Admin password (12+ chars, 2+ character types): " 12 _sccap_admin_pw_problem
    ADMIN_PASSWORD="$_SCCAP_ANSWER"

    echo ""
    echo "[*] LLM provider (used for every scan and the advisor)"
    echo "    1) OpenAI        2) Anthropic     3) Google     4) DeepSeek     5) xAI"
    while true; do
        read -p "  Provider (1-5) [1]: " _llm_choice
        case "${_llm_choice:-1}" in
            1|"") LLM_PROVIDER=openai ;;
            2) LLM_PROVIDER=anthropic ;;
            3) LLM_PROVIDER=google ;;
            4) LLM_PROVIDER=deepseek ;;
            5) LLM_PROVIDER=xai ;;
            *) echo "  Invalid choice."; continue ;;
        esac
        break
    done

    echo ""
    echo "  Optimization mode:"
    echo "    1) multi-provider      portable prompts, any provider (default)"
    echo "    2) anthropic-optimized prompt caching + tuned variants (Anthropic only)"
    while true; do
        read -p "  Mode (1/2) [1]: " _mode_choice
        case "${_mode_choice:-1}" in
            1|"") LLM_MODE=multi_provider; break ;;
            2)
                if [ "$LLM_PROVIDER" != "anthropic" ]; then
                    echo "  [!] anthropic-optimized requires the Anthropic provider."
                    continue
                fi
                LLM_MODE=anthropic_optimized; break ;;
            *) echo "  Invalid choice." ;;
        esac
    done

    case "$LLM_PROVIDER" in
        openai) _llm_default_model=gpt-4o ;;
        anthropic) _llm_default_model=claude-sonnet-4-5 ;;
        google) _llm_default_model=gemini-2.5-pro ;;
        deepseek) _llm_default_model=deepseek-chat ;;
        xai) _llm_default_model=grok-4 ;;
    esac
    while true; do
        read -p "  Model [$_llm_default_model]: " LLM_MODEL
        LLM_MODEL=${LLM_MODEL:-$_llm_default_model}
        case "$LLM_MODEL" in
            sk-*|sk_*|AIza*|xai-*|gsk_*|hf_*)
                echo "  [!] That looks like an API key, not a model name (e.g. gpt-4o,"
                echo "      claude-sonnet-4-5, gemini-2.5-pro, deepseek-flash). API keys are"
                echo "      asked for in the next question."
                continue
                ;;
        esac
        if [ "${#LLM_MODEL}" -gt 128 ] || ! printf '%s' "$LLM_MODEL" | grep -qE '^[A-Za-z0-9._:/-]+$'; then
            echo "  [!] Model names may contain letters, digits and . _ : / - only."
            continue
        fi
        break
    done
    echo "  -> provider: $LLM_PROVIDER · model: $LLM_MODEL"

    _sccap_ask_secret "  $LLM_PROVIDER API key: " 8
    LLM_API_KEY="$_SCCAP_ANSWER"

    if [ "$SCCAP_VARIANT" = "custom" ]; then
        echo ""
        echo "[*] Custom variant: choose the features to enable (y/N each)"
        CUSTOM_FEATURES=""
        for _feat in scan chat compliance mcp multi_user user_groups multi_tenant sso scim email log_stack tracing admin_authoring; do
            read -p "  Enable $_feat? (y/N): " _feat_choice
            case "$_feat_choice" in
                [Yy]*) CUSTOM_FEATURES="${CUSTOM_FEATURES:+$CUSTOM_FEATURES,}$_feat" ;;
            esac
        done
    fi

    if [ "$_LOG_STACK_ON" = "1" ]; then
        echo ""
        echo "[*] Grafana administrator (served at /grafana/ after setup)"
        read -p "  Grafana username [admin]: " GRAFANA_USER
        GRAFANA_USER=${GRAFANA_USER:-admin}
        _sccap_ask_secret "  Grafana password (8+ chars): " 8 _sccap_grafana_pw_problem
        GRAFANA_PASSWORD="$_SCCAP_ANSWER"
    fi
}

_sccap_write_grafana_credentials() {
    [ -n "$GRAFANA_USER" ] && [ -n "$GRAFANA_PASSWORD" ] || return 0
    for _kv in "GRAFANA_ADMIN_USER=$GRAFANA_USER" "GRAFANA_ADMIN_PASSWORD=$GRAFANA_PASSWORD"; do
        _key=${_kv%%=*}
        _val=${_kv#*=}
        _escaped=$(printf '%s\n' "$_val" | sed -e 's/[\/&]/\\&/g')
        if grep -q "^${_key}=" .env; then
            sed -i.bak "s|^${_key}=.*$|${_key}=${_escaped}|" .env
        else
            echo "${_key}=${_val}" >> .env
        fi
    done
    rm -f .env.bak
    echo "[+] Grafana credentials saved to .env."
}

_sccap_run_terminal_setup() {
    # Submit the first-run answers to the API bootstrap endpoint through the
    # container-side client. Idempotent: a completed install is left untouched.
    local args=(
        --api-base http://127.0.0.1:8000
        --wait-seconds 120
        --admin-email "$ADMIN_EMAIL"
        --deployment-type "$DEPLOYMENT_TYPE"
        --llm-mode "$LLM_MODE"
        --llm-provider "$LLM_PROVIDER"
        --llm-model "$LLM_MODEL"
    )
    if [ "$DEPLOYMENT_TYPE" = "cloud" ] && [ -n "$SSL_DOMAIN" ]; then
        if [ "$SSL_ENABLED" = "true" ]; then
            args+=(--frontend-url "https://$SSL_DOMAIN")
        else
            args+=(--frontend-url "http://$SSL_DOMAIN")
        fi
    fi
    [ -n "$CUSTOM_FEATURES" ] && args+=(--features "$CUSTOM_FEATURES")

    # Secrets travel as container env vars, never as argv.
    docker compose exec -T \
        -e SCCAP_SETUP_ADMIN_PASSWORD="$ADMIN_PASSWORD" \
        -e SCCAP_SETUP_LLM_API_KEY="$LLM_API_KEY" \
        app python -m app.cli.terminal_setup "${args[@]}"
}

# ----------------------------------------------------------------------
# Operator flags, teardown (uninstall/purge/factory reset) and ownership.
# ----------------------------------------------------------------------
_SCCAP_MODE="install"        # install | uninstall
_SCCAP_PURGE=0
_SCCAP_FACTORY_RESET=0
_SCCAP_ASSUME_YES=0
_SCCAP_REINSTALL=0
_PURGE_BACKUP_DIR="${SCCAP_BACKUP_DIR:-.purge-backups}"

_sccap_usage() {
    cat <<'USAGE'
SCCAP setup

  ./setup.sh                     Install, upgrade or re-run the setup wizard.
  ./setup.sh --uninstall         Stop and remove the stack. Volumes, data,
                                 .env, keys and certificates are kept.
  ./setup.sh --purge             Also drop data volumes and remove the images
                                 built here. Keeps .env/.secrets/certbot.
                                 A pg_dumpall backup is written first.
  ./setup.sh --factory-reset     Purge plus delete .env, .secrets and certbot
                                 state. This is a clean install.
  ./setup.sh --update            Pull the current branch, back up the database,
                                 rebuild, migrate and health-check in place.
  ./setup.sh --rollback          Return code + images to the previous --update.
  ./setup.sh --repair-tls        Re-create the TLS material from .env and exit.
                                 Use when the UI container reports
                                 tls_cert_missing / "connection closed".
  -y, --yes                      Skip the interactive confirmations.
  -h, --help                     Show this help.

An interactive run on an existing installation offers the same choices.
USAGE
}

_sccap_parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --uninstall)     _SCCAP_MODE="uninstall" ;;
            --purge)         _SCCAP_MODE="uninstall"; _SCCAP_PURGE=1 ;;
            --factory-reset) _SCCAP_MODE="uninstall"; _SCCAP_PURGE=1; _SCCAP_FACTORY_RESET=1 ;;
            --repair-tls)    _SCCAP_MODE="repair-tls" ;;
            --update)        _SCCAP_MODE="update" ;;
            --rollback)      _SCCAP_MODE="rollback" ;;
            -y|--yes)        _SCCAP_ASSUME_YES=1 ;;
            -h|--help)       _sccap_usage; exit 0 ;;
            *)
                echo "[!] Unknown option: $1" >&2
                _sccap_usage >&2
                exit 2
                ;;
        esac
        shift
    done
}

_sccap_confirm() {
    # $1 = question, $2 = exact phrase the operator must type.
    local answer
    if [ "$_SCCAP_ASSUME_YES" = "1" ]; then
        echo "[+] $1 (auto-confirmed by --yes)"
        return 0
    fi
    read -r -p "$1 Type '$2' to confirm: " answer
    [ "$answer" = "$2" ]
}

_sccap_project_images() {
    # Only the images this checkout builds; never postgres/rabbitmq/etc.
    local prefix
    prefix="$(basename "$PWD")"
    docker compose config --images 2>/dev/null | sort -u | while read -r img; do
        [ -n "$img" ] || continue
        case "$img" in
            "$prefix"*) printf '%s\n' "$img" ;;
        esac
    done
}

_sccap_backup_database() {
    # Best effort: an operator purging volumes should still be able to roll back.
    local db_id dump
    db_id=$(docker compose ps -q db 2>/dev/null || true)
    [ -n "$db_id" ] || { echo "    No running database container; skipping backup."; return 0; }
    mkdir -p "$_PURGE_BACKUP_DIR" 2>/dev/null || true
    # The dump contains every row and role in the deployment: keep it private.
    chmod 700 "$_PURGE_BACKUP_DIR" 2>/dev/null || true
    dump="$_PURGE_BACKUP_DIR/pre-purge-$(date -u +%Y%m%dT%H%M%SZ).sql"
    if docker compose exec -T db sh -c 'pg_dumpall -U "$POSTGRES_USER"' >"$dump" 2>/dev/null; then
        chmod 600 "$dump" 2>/dev/null || true
        echo "    Database backup: $dump"
    else
        rm -f "$dump"
        echo "    [!] Could not dump the database; continuing anyway."
    fi
    return 0
}

_sccap_project_name() {
    # Compose project name, used to find leftovers `down` cannot see.
    local name=""
    name=$(docker compose config --format json 2>/dev/null \
        | python3 -c 'import json,sys; print(json.load(sys.stdin).get("name",""))' 2>/dev/null \
        || true)
    if [ -z "$name" ]; then
        name=$(basename "$PWD" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_-]//g')
    fi
    printf '%s\n' "$name"
}

_sccap_force_remove_leftovers() {
    # `docker compose down` only removes what *this* compose file declares. A
    # stack started with an overlay or a different profile generation leaves
    # containers behind that keep networks busy, and compose then reports
    # "Resource is still in use" while exiting 0 - so the installer claimed a
    # clean teardown while containers were still running.
    local project="$1" include_data="$2" removed=0 cid net vol
    local containers networks volumes

    containers=$(docker ps -aq --filter "label=com.docker.compose.project=$project" 2>/dev/null || true)
    for cid in $containers; do
        if docker rm -f "$cid" >/dev/null 2>&1; then removed=$((removed + 1)); fi
    done

    # Networks are matched by label *and* by name prefix: a network created by
    # an older compose generation may carry the name but not the label.
    # Every candidate must belong to this project: either by compose label or by
    # the `<project>_` name prefix compose gives its networks. The prefix check
    # keeps a broad `docker network ls` from ever offering a system network
    # (bridge/host/none) for removal.
    networks=$( { docker network ls --filter "label=com.docker.compose.project=$project" --format '{{.Name}}' 2>/dev/null || true
                  docker network ls --format '{{.Name}}' 2>/dev/null | grep -E "^${project}_" || true
                } | grep -E "^${project}_" | sort -u )
    for net in $networks; do
        for cid in $(docker network inspect "$net" --format '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null || true); do
            docker network disconnect -f "$net" "$cid" >/dev/null 2>&1 || true
        done
        if docker network rm "$net" >/dev/null 2>&1; then removed=$((removed + 1)); fi
    done

    if [ "$include_data" = "1" ]; then
        volumes=$( { docker volume ls --filter "label=com.docker.compose.project=$project" -q 2>/dev/null || true
                     docker volume ls -q 2>/dev/null | grep -E "^${project}_" || true
                   } | grep -E "^${project}_" | sort -u )
        for vol in $volumes; do
            if docker volume rm -f "$vol" >/dev/null 2>&1; then removed=$((removed + 1)); fi
        done
    fi

    [ "$removed" -gt 0 ] && echo "    Force-removed $removed leftover container/network/volume resource(s)."
    return 0
}

_sccap_report_leftovers() {
    local project="$1" remaining
    remaining=$( { docker ps -aq --filter "label=com.docker.compose.project=$project" 2>/dev/null || true
                   docker network ls --format '{{.Name}}' 2>/dev/null | grep -E "^${project}_" || true
                 } | grep -vc '^$' || true)
    if [ "${remaining:-0}" -gt 0 ]; then
        echo "[!] $remaining resource(s) still belong to project '$project':"
        docker ps -a --filter "label=com.docker.compose.project=$project" \
            --format '      container {{.Names}} ({{.Status}})' 2>/dev/null | head -10
        docker network ls --format '{{.Name}}' 2>/dev/null \
            | grep -E "^${project}_" | sed 's/^/      network /' | head -10
        return 1
    fi
    return 0
}

_sccap_teardown() {
    # $1 = uninstall | purge | factory-reset
    local level="$1" img

    if ! command -v docker >/dev/null 2>&1; then
        echo "[!] docker is not installed; nothing to remove with compose."
    elif [ ! -f .env ]; then
        echo "[!] No .env in $PWD; compose state cannot be addressed from here."
    else
        echo "[*] Stopping the stack..."
        docker compose down --remove-orphans || true
        if [ "$level" != "uninstall" ]; then
            echo "[*] Backing up the database before removing volumes..."
            _sccap_backup_database
            echo "[*] Removing data volumes..."
            docker compose down --volumes --remove-orphans || true
            echo "[*] Removing images built from this checkout..."
            for img in $(_sccap_project_images); do
                docker image rm -f "$img" >/dev/null 2>&1 || true
            done
        fi
    fi

    # Anything compose could not see (overlay/profile leftovers, stopped
    # containers holding a network) is removed here, so "teardown complete"
    # means nothing of this project is left running.
    local project leftover_data
    project=$(_sccap_project_name)
    if [ "$level" = "uninstall" ]; then
        leftover_data=0
    else
        leftover_data=1
    fi
    if command -v docker >/dev/null 2>&1; then
        echo "[*] Removing leftover containers and networks..."
        _sccap_force_remove_leftovers "$project" "$leftover_data"
    fi

    if [ "$level" = "factory-reset" ]; then
        echo "[*] Removing configuration and key material..."
        rm -f .env .env.lock "$_SETUP_STAGE_FILE"
        rm -rf .secrets
        rm -rf certbot
    fi

    echo ""
    echo "[+] Teardown complete ($level)."
    case "$level" in
        uninstall)
            echo "    Kept: data volumes, .env, .secrets/, certbot/"
            echo "    Re-run ./setup.sh to bring the stack back up."
            ;;
        purge)
            echo "    Kept: .env, .secrets/, certbot/ (so a reinstall reuses them)"
            echo "    Removed: data volumes and project images"
            if [ -d "$_PURGE_BACKUP_DIR" ]; then
                echo "    Database backups: $_PURGE_BACKUP_DIR/"
            fi
            ;;
        factory-reset)
            echo "    Removed: stack, data volumes, images, .env, .secrets/, certbot/"
            echo "    ./setup.sh now performs a clean install (fresh certificate)."
            ;;
    esac
    if command -v docker >/dev/null 2>&1; then
        _sccap_report_leftovers "$project" || return 1
    fi
    return 0
}

_sccap_assert_env_readable() {
    # A previous `sudo ./setup.sh` leaves .env root-owned (0600). The next run as
    # the deploying user then fails deep inside `docker compose up` with an
    # opaque "open .env: permission denied". Detect it up front and repair it.
    [ -f .env ] || return 0
    [ -r .env ] && return 0
    if [ "$(id -u)" -eq 0 ]; then
        return 0
    fi
    if command -v sudo >/dev/null 2>&1 && sudo -n chown "$(id -u):$(id -g)" .env 2>/dev/null; then
        echo "[+] Repaired .env ownership (it was root-owned from an earlier sudo run)."
        return 0
    fi
    echo "[!] .env exists but is not readable by $(id -un)."
    echo "    It was written by an earlier 'sudo ./setup.sh'. Fix with:"
    echo "      sudo chown $(id -un):$(id -gn) .env"
    echo "    or re-run this script with sudo."
    return 1
}

_sccap_tune_tcp_congestion() {
    # Measured on a Hetzner VM serving a browser ~1s RTT away: cubic collapsed
    # to ~9 KB/s on /grafana's multi-megabyte assets, which read as "the page
    # never loads". BBR holds the window open on lossy paths. Best effort and
    # host-wide, so it is skipped wherever the kernel cannot provide it.
    [ "$(uname -s)" = "Linux" ] || return 0
    if ! sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
        _sccap_with_root modprobe tcp_bbr >/dev/null 2>&1 || return 0
    fi
    if sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
        _sccap_with_root sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true
        printf '%s\n' 'net.ipv4.tcp_congestion_control=bbr' \
            | _sccap_with_root tee /etc/sysctl.d/99-sccap-network.conf >/dev/null 2>&1 || true
        echo "[+] TCP congestion control: BBR (persisted in /etc/sysctl.d/99-sccap-network.conf)."
    fi
    return 0
}

_sccap_fix_ownership() {
    # setup.sh runs as root (directly or via sudo) while the operator and the
    # containers do not. Files created here therefore end up root-owned and the
    # operator cannot read .env or edit the checkout afterwards. Hand back only
    # what the human needs; container-writable paths keep their container UID
    # (certbot -> UI image user, pentest signing key -> tool worker user).
    local operator="${SUDO_USER:-}" repo_group
    [ "$(id -u)" -eq 0 ] || return 0

    if [ -z "$operator" ] || [ "$operator" = "root" ]; then
        # Running straight as root: nothing to hand back, but keep the state
        # private and make sure the container-writable paths exist.
        chmod 600 .env 2>/dev/null || true
        mkdir -p .secrets 2>/dev/null || true
        chmod 700 .secrets 2>/dev/null || true
        return 0
    fi

    repo_group=$(id -gn "$operator" 2>/dev/null || echo "$operator")
    # .purge-backups is written by root during a --purge teardown; hand it back
    # as well so the operator can read the dump they were told about.
    for path in .env .env.lock "$_SETUP_STAGE_FILE" "$_PURGE_BACKUP_DIR"; do
        [ -e "$path" ] || continue
        chown "$operator:$repo_group" "$path" 2>/dev/null || true
    done
    chmod 600 .env 2>/dev/null || true

    # .secrets stays private to the operator; the key file inside belongs to the
    # tool worker (uid 1001) so the supervisor accepts it.
    if [ -d .secrets ]; then
        chown "$operator:$repo_group" .secrets 2>/dev/null || true
        chmod 700 .secrets 2>/dev/null || true
    fi

    # The checkout itself was likely cloned as root; a non-root operator cannot
    # even `git pull`. Report it instead of silently taking over the tree.
    if [ -d .git ] && [ "$(stat -c '%u' .git 2>/dev/null || echo 0)" -eq 0 ]; then
        echo "[!] This checkout is owned by root; '$operator' cannot update it."
        echo "    Fix with: sudo chown -R $operator:$repo_group $(pwd)"
    fi
    return 0
}

_sccap_existing_install_menu() {
    # Offer continue/reinstall/uninstall/purge/factory-reset when there is
    # already an installation in this directory.
    local containers choice
    [ -f .env ] || return 0
    containers=$(docker compose ps -q 2>/dev/null | wc -l | tr -d ' ')
    [ "${containers:-0}" -gt 0 ] || return 0

    echo ""
    echo "[*] Existing installation detected ($containers container(s) in $PWD)."
    echo "    1) Continue      keep data and configuration, upgrade/re-run setup (default)"
    echo "    2) Reinstall     stop the stack, keep data, rebuild and start again"
    echo "    3) Uninstall     stop and remove the stack, keep data and configuration"
    echo "    4) Purge         remove the stack AND data volumes (keeps .env/keys/certs)"
    echo "    5) Factory reset purge AND delete .env, keys and certificates"
    read -r -p "    Your choice (1/2/3/4/5) [1]: " choice
    case "${choice:-1}" in
        1) : ;;
        2) _SCCAP_REINSTALL=1 ;;
        3) _SCCAP_MODE="uninstall" ;;
        4) _SCCAP_MODE="uninstall"; _SCCAP_PURGE=1 ;;
        5) _SCCAP_MODE="uninstall"; _SCCAP_PURGE=1; _SCCAP_FACTORY_RESET=1 ;;
        *) echo "    Unrecognised choice; continuing with the existing installation." ;;
    esac
    echo ""
}

_sccap_run_repair_tls() {
    # Repair path for an install whose TLS material is missing or was never
    # created (a resumed run used to skip the certificate step entirely).
    if [ ! -f .env ]; then
        echo "[!] No .env here; run ./setup.sh from the install directory."
        return 1
    fi
    if ! _sccap_prepare_tls_material; then
        return 1
    fi
    # A key generated under sudo is 0600 root:root, but nginx inside the UI
    # container runs as its own UID and cannot read it ("cannot load certificate
    # key ... Permission denied"). Hand the tree over exactly as the install
    # flow does after the build.
    _sccap_align_certbot_ownership || true
    local domain
    domain=$(grep -m1 '^SSL_DOMAIN=' .env | cut -d= -f2-)
    if [ -f "certbot/conf/live/${domain}/fullchain.pem" ]; then
        if [ -f "certbot/conf/live/${domain}/privkey.pem" ] \
                && [ "$(stat -c '%a' "certbot/conf/live/${domain}/privkey.pem" 2>/dev/null)" = "600" ] \
                && [ ! -r "certbot/conf/live/${domain}/privkey.pem" ]; then
            echo "[!] The private key is not readable by $(id -un); the UI runs as another UID."
        fi
        echo "[+] Certificate present for ${domain}."
    else
        echo "[!] No certificate was created; check SSL_ENABLED/SSL_MODE/SSL_DOMAIN in .env."
        return 1
    fi
    echo "    Apply it with: docker compose up -d --no-build --force-recreate ui"
    return 0
}

_sccap_run_teardown_mode() {
    local level="uninstall"
    if [ "$_SCCAP_FACTORY_RESET" = "1" ]; then
        level="factory-reset"
    elif [ "$_SCCAP_PURGE" = "1" ]; then
        level="purge"
    fi
    case "$level" in
        uninstall)
            _sccap_confirm "This stops and removes the SCCAP containers. Data volumes, .env and certificates are kept." "uninstall" || { echo "Aborted."; exit 1; }
            ;;
        purge)
            _sccap_confirm "This stops the stack, removes DATA VOLUMES and deletes the images built here. A database backup is taken first." "purge" || { echo "Aborted."; exit 1; }
            ;;
        factory-reset)
            _sccap_confirm "This removes the stack, ALL data volumes, .env, signing keys and certificates. This cannot be undone." "factory-reset" || { echo "Aborted."; exit 1; }
            ;;
    esac
    if ! _sccap_teardown "$level"; then
        echo "[!] Teardown finished with resources still present (see above)."
        echo "    Retry with: docker ps -a --filter label=com.docker.compose.project=$(_sccap_project_name)"
        rm -f "$_SETUP_STAGE_FILE" 2>/dev/null || true
        exit 1
    fi
    rm -f "$_SETUP_STAGE_FILE" 2>/dev/null || true
    exit 0
}

_sccap_parse_args "$@"

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

_sccap_assert_env_readable || exit 1

# Non-interactive teardown (--uninstall/--purge/--factory-reset) needs docker
# but nothing else from the install flow.
if [ "$_SCCAP_MODE" = "repair-tls" ]; then
    _sccap_run_repair_tls || exit 1
    exit 0
fi

if [ "$_SCCAP_MODE" = "update" ]; then
    _sccap_assert_env_readable || exit 1
    _sccap_run_update || exit 1
    exit 0
fi

if [ "$_SCCAP_MODE" = "rollback" ]; then
    _sccap_assert_env_readable || exit 1
    _sccap_run_rollback || exit 1
    exit 0
fi

if [ "$_SCCAP_MODE" = "uninstall" ]; then
    _sccap_run_teardown_mode
fi

# Interactive alternative: detect an existing installation and let the operator
# continue, reinstall, uninstall, purge or factory-reset.
_sccap_existing_install_menu
if [ "$_SCCAP_MODE" = "uninstall" ]; then
    _sccap_run_teardown_mode
fi
if [ "$_SCCAP_REINSTALL" = "1" ]; then
    echo "[*] Reinstall requested: stopping the stack (data volumes kept)..."
    docker compose down --remove-orphans || true
    echo ""
fi

# Hand config state back to the operating user before we rewrite it.
_sccap_fix_ownership
_sccap_tune_tcp_congestion

# Resume support: if a previous run stopped at the build/migrate step, offer to
# skip re-configuring and retry that step. A reinstall always skips the
# questionnaire: the answer file on disk is already the desired configuration.
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
if [ "$_SCCAP_REINSTALL" = "1" ] && [ -f .env ]; then
    _RESUME=1
fi

# A resume skips the questionnaire, but if the earlier run died before first-run
# bootstrap the platform still has no superuser - ask for the answers then.
if [ "$_RESUME" = "1" ] && [ -f .env ] && ! _sccap_platform_bootstrapped; then
    echo "[*] This installation has not been bootstrapped yet; asking for the"
    echo "    administrator and LLM details now."
    # The questionnaire normally sets these; restore them from .env so the
    # custom-feature and Grafana questions still fire on this path.
    SCCAP_VARIANT=${SCCAP_VARIANT:-$(grep -m1 '^SCCAP_VARIANT=' .env 2>/dev/null | cut -d= -f2-)}
    case ",$(grep -m1 '^COMPOSE_PROFILES=' .env 2>/dev/null | cut -d= -f2-)," in
        *,log_stack,*) _LOG_STACK_ON=1 ;;
    esac
    _sccap_ask_first_run
fi
_sccap_stage config

# On resume the configuration prompts are skipped, so read the persisted values
# back into the shell variables the final summary and URL output depend on, and
# keep the HTTP opt-in consistent with the chosen TLS mode.
if [ "$_RESUME" = "1" ]; then
    _sccap_env_val() { grep -E "^${1}=" .env 2>/dev/null | head -1 | cut -d= -f2- | tr -d '\"'; }
    DEPLOYMENT_TYPE=$(_sccap_env_val DEPLOYMENT_TYPE)
    DEPLOYMENT_TYPE=${DEPLOYMENT_TYPE:-cloud}
    SSL_ENABLED=$(_sccap_env_val SSL_ENABLED)
    SSL_MODE=$(_sccap_env_val SSL_MODE)
    SSL_DOMAIN=$(_sccap_env_val SSL_DOMAIN)
    SSL_DEV_INSECURE=$(_sccap_env_val SSL_DEV_INSECURE)
    # When TLS is off, the UI's nginx refuses to serve HTTP unless the operator
    # has explicitly opted in.  Older installs chose "No TLS" but predate the
    # SSL_DEV_INSECURE key, so reconcile it here rather than leave the UI
    # failing closed.
    if [ "$SSL_ENABLED" != "true" ]; then
        SSL_MODE=${SSL_MODE:-none}
        SSL_DEV_INSECURE=true
        if grep -q '^SSL_DEV_INSECURE=' .env; then
            sed -i.bak 's/^SSL_DEV_INSECURE=.*/SSL_DEV_INSECURE=true/' .env && rm -f .env.bak
        else
            echo 'SSL_DEV_INSECURE=true' >> .env
        fi
    fi
fi

# 2. Environment Setup
echo "[*] Setting up environment configuration..."

# Serialise concurrent setup runs. `flock` is util-linux and absent on macOS
# and some minimal images; degrade to a warning instead of refusing to install.
if command -v flock >/dev/null 2>&1; then
    exec 9>>.env.lock
    flock -n 9 || { echo "[!] Another setup.sh is running; exiting."; exit 1; }
else
    echo "[!] flock not available; skipping the concurrent-setup lock."
    exec 9>>.env.lock
fi
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
# 2.4b. Pentesting (authorized automated security assessment)
# ----------------------------------------------------------------------
# Enables the pentest engagement plane: the controller, runner, tool worker and
# verification coordinator profiles plus the capability flags the working local
# deployment uses. It does NOT install the tool runtimes (nmap/nuclei/zap/
# playwright) - those run via the Kubernetes attach runtime (cloud) or the local
# kind-cluster qualification, see docs/docs/operations/cloud-kubernetes-deployment.md.
_sccap_enable_pentesting() {
    # The better-pentester engine needs no capability flags.
    return 0
}


echo ""
echo "[*] Pentesting:"
echo "  Autonomous black/gray/white-box penetration testing (nmap, nuclei, ZAP,"
echo "  sqlmap, ffuf, hydra, whatweb, testssl, hashcat, Chromium)."
read -p "  Enable pentesting? (y/N): " _pentest_choice
case "$_pentest_choice" in
    [Yy]*)
        COMPOSE_PROFILES_VALUE="${COMPOSE_PROFILES_VALUE:+$COMPOSE_PROFILES_VALUE,}pentesting-v5"
        _PENTEST_NOTE="Pentesting enabled. The pentest-engine container runs every scanner locally; no Kubernetes or kind cluster is required."
        echo "[+] Pentesting enabled."
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
            elif [ "$SSL_MODE" = "letsencrypt" ] && _sccap_is_ip "$choice"; then
                echo "  [!] Let's Encrypt cannot issue certificates for IP addresses"
                echo "      (a private IP like $choice will always fail)."
                echo "      Choose Self-signed for an IP, or enter a public DNS name."
                STATE=2
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
# Everything the browser wizard used to ask for is collected here, in the
# terminal, before any container is built.
if [ "$_RESUME" != "1" ]; then
    _sccap_ask_first_run
fi

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

# ----------------------------------------------------------------------
# Grafana URL. The log stack is published under /grafana/ on the application
# host (see secure-code-ui/nginx-{http,https}.conf), so operators never need a
# second hostname or direct access to port 3000. Computed outside the interview
# so resuming an older install still picks it up.
# ----------------------------------------------------------------------
case ",$(grep -m1 '^COMPOSE_PROFILES=' .env 2>/dev/null | cut -d= -f2-)," in
    *,log_stack,*) _LOG_STACK_ON=1 ;;
    *) _LOG_STACK_ON="${_LOG_STACK_ON:-0}" ;;
esac
if [ "$_LOG_STACK_ON" = "1" ]; then
    if [ "$SSL_ENABLED" = "true" ] && [ -n "$SSL_DOMAIN" ]; then
        _GRAFANA_ROOT_URL="https://$SSL_DOMAIN/grafana/"
    else
        _GRAFANA_ROOT_URL="http://${SSL_DOMAIN:-localhost}/grafana/"
    fi
    _GRAFANA_SUB_PATH="true"
else
    _GRAFANA_ROOT_URL="http://localhost:3000/"
    _GRAFANA_SUB_PATH="false"
fi
for _kv in "GRAFANA_ROOT_URL=$_GRAFANA_ROOT_URL" "GRAFANA_SERVE_FROM_SUB_PATH=$_GRAFANA_SUB_PATH"; do
    _key="${_kv%%=*}"
    _val="${_kv#*=}"
    if grep -q "^${_key}=" .env; then
        sed -i.bak "s|^${_key}=.*$|${_key}=${_val}|" .env
    else
        echo "${_key}=${_val}" >> .env
    fi
done
_sccap_write_grafana_credentials

# Certificate material for this run (fresh or resumed) before anything starts.
_sccap_prepare_tls_material || exit 1
_sccap_fix_evidence_endpoint

# 3. Docker Build and Launch
_sccap_stage build
echo "[*] Launching Docker containers (this may take a few minutes)..."
# We need to ensure the VITE variables are available to the build context
# Sourcing .env is one way, but docker compose reads .env automatically
docker compose build
_sccap_align_certbot_ownership
_sccap_align_fluentd_ownership
docker compose up -d

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
# The API image runs `alembic upgrade head` from its entrypoint: exactly one
# API-owned process migrates. Racing a second Alembic process here is what a
# fresh install hits -- both try to create alembic_version and one dies with
# `duplicate key value violates unique constraint "pg_type_typname_nsp_index"`,
# aborting setup midway. Wait for the API owned migration to reach head and
# only take over if it never gets there.
_migrated=0
for _ in $(seq 1 100); do
    if docker compose exec -T app alembic current --check-heads >/dev/null 2>&1; then
        _migrated=1
        break
    fi
    sleep 3
done
if [ "$_migrated" != "1" ]; then
    echo "[!] API-owned migrations did not reach head; running them explicitly..."
    docker compose exec -T app alembic upgrade head
fi

_sccap_ensure_evidence_bucket

# 4b. First-run bootstrap (superuser, LLM config, feature flags)
_sccap_stage setup
echo "[*] Creating the administrator account and LLM configuration..."
if _sccap_run_terminal_setup; then
    echo "[+] Platform setup complete."
else
    echo "[!] First-run bootstrap failed; re-run ./setup.sh once the API is healthy."
    echo "    Details: docker compose logs --tail=50 app"
fi

echo "[+] Database initialized. Proceed to the Web UI to create your Admin Superuser."
echo ""

echo "=================================================="
echo "   Setup Complete!"
echo "=================================================="
echo ""
_sccap_stage done
# Final ownership pass: everything setup.sh just wrote belongs to the operator
# (config) or the container UIDs (certbot state, tool-worker key).
_sccap_fix_ownership
_sccap_align_certbot_ownership
_sccap_align_fluentd_ownership
_sccap_install_update_units
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
if [ "$_LOG_STACK_ON" = "1" ]; then
    echo "   -> ${_GRAFANA_ROOT_URL:-http://localhost:3000/}   (proxied by the UI container)"
    echo "   -> http://localhost:3000 (loopback only; use SSH -L 3000:127.0.0.1:3000 as a fallback)"
else
    echo "   Log stack not enabled (COMPOSE_PROFILES has no log_stack); nothing to serve."
fi
if [ -n "${_PENTEST_NOTE:-}" ]; then
    echo ""
    echo "[*] Pentesting note:"
    echo "    $_PENTEST_NOTE"
fi
echo ""
