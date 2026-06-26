#!/bin/sh

DOMAIN="${SSL_DOMAIN}"
ENABLED="${SSL_ENABLED:-false}"
EMAIL="${SSL_EMAIL:-admin@${SSL_DOMAIN:-localhost}}"

# --- Input validation ---
# V01.2.5 / V02.2.1 / V01.3.3 / V15.2.5: allow-list SSL_DOMAIN to DNS hostname chars only
# (1-253 chars, each label [a-zA-Z0-9-], dots allowed as separators).
# Reject anything outside [a-zA-Z0-9.-] and enforce non-empty when SSL is on.
validate_domain() {
    case "$1" in
        ''|*[!a-zA-Z0-9.-]*)
            echo "ERROR: SSL_DOMAIN must match [a-zA-Z0-9.-]+ (got: '$1')"
            exit 1
            ;;
    esac
    # Enforce max length (RFC 1035 limit)
    if [ "${#1}" -gt 253 ]; then
        echo "ERROR: SSL_DOMAIN exceeds 253 characters"
        exit 1
    fi
}

# V01.3.3: validate SSL_EMAIL format (basic structural check)
validate_email() {
    case "$1" in
        *@*.*)  ;;   # must contain @ and a dot after it
        *)
            echo "ERROR: SSL_EMAIL must look like user@domain.tld (got: '$1')"
            exit 1
            ;;
    esac
    if [ "${#1}" -gt 320 ]; then
        echo "ERROR: SSL_EMAIL exceeds 320 characters"
        exit 1
    fi
}

# Helper: render nginx-https.conf by substituting __SSL_DOMAIN__ with the real domain.
# V01.3.7: validate rendered config with nginx -t before proceeding.
render_https_conf() {
    sed "s|__SSL_DOMAIN__|${DOMAIN}|g" /etc/nginx/nginx-https.conf > /etc/nginx/conf.d/default.conf
    if ! nginx -t -c /etc/nginx/conf.d/default.conf 2>/dev/null; then
        echo "ERROR: rendered nginx config failed validation (nginx -t). Aborting."
        exit 1
    fi
}

# 1. Skip SSL Process if Disabled
if [ "$ENABLED" != "true" ]; then
    # V12.2.1 / V12.3.1: HTTP-only mode must be explicitly opted into via SSL_DEV_INSECURE=true.
    # Fail-closed in production to prevent silent unencrypted serving.
    if [ "${SSL_DEV_INSECURE:-false}" != "true" ]; then
        echo "ERROR security_event=tls_disabled SSL_ENABLED is '$ENABLED' and SSL_DEV_INSECURE is not set."
        echo "Set SSL_DEV_INSECURE=true to explicitly opt in to HTTP-only mode for local development."
        exit 1
    fi
    echo "WARN security_event=tls_disabled mode=http_only SSL_DEV_INSECURE=true is set. Running Nginx on Port 80 only."
    cp /etc/nginx/nginx-http.conf /etc/nginx/conf.d/default.conf
    exit 0
fi

# 2. Validate SSL_DOMAIN is provided and safe when SSL is enabled
if [ -z "$DOMAIN" ]; then
    # V12.2.1: fail-closed rather than silently falling back to HTTP
    echo "ERROR: SSL_ENABLED is true, but no SSL_DOMAIN was provided. Aborting."
    exit 1
fi

# Run allow-list validation now that we know domain is non-empty
validate_domain "$DOMAIN"
validate_email "$EMAIL"

echo "Checking SSL certificates for $DOMAIN..."

# Ensure certbot directories are writable (belt-and-suspenders with Dockerfile).
# On some filesystems, chown inside the container doesn't survive volume mounts
# or the USER switch, so we create them here as the running user if possible.
mkdir -p /var/log/letsencrypt /var/lib/letsencrypt 2>/dev/null || true

# V15.4.2: serialise cert acquisition with a lock to prevent TOCTOU races when
# multiple replicas share the same ./certbot/conf volume.
# Only one replica enters the bootstrap path at a time.
(
flock -e 200
if [ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    echo "No SSL certificate found. Bootstrapping HTTP-only configuration to answer ACME challenges..."
    cp /etc/nginx/nginx-http.conf /etc/nginx/conf.d/default.conf

    # Start Nginx in background to respond to ACME challenges
    echo "Starting temporary Nginx layer..."
    nginx -g "daemon off;" &
    NGINX_PID=$!

    # Wait for Nginx to boot
    sleep 3

    echo "Requesting Let's Encrypt certificate for $DOMAIN..."
    certbot certonly --webroot -w /usr/share/nginx/html -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL"

    # Stop temporary Nginx
    kill $NGINX_PID
    wait $NGINX_PID 2>/dev/null

    if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
        echo "Certificate successfully generated! Switching to HTTPS configuration."
        render_https_conf
    else
        # V12.2.1 / V12.3.1: fail-closed on certbot failure rather than silently serving HTTP
        echo "ERROR security_event=tls_cert_failed: certbot failed to obtain a certificate for $DOMAIN. Aborting."
        echo "Set SSL_DEV_INSECURE=true to allow HTTP-only fallback for local development."
        exit 1
    fi
else
    echo "SSL certificate found! Booting directly in HTTPS mode."
    render_https_conf
fi
) 200>/tmp/sccap-cert.lock

# V02.3.2 / V13.1.3: bounded failure counter with backoff in the renewal loop.
# V15.4.3: flock -n so concurrent replicas skip rather than racing on certbot renew.
# V15.4.1: capture PID and trap SIGTERM/INT so the subshell is reaped on container shutdown.
(
    RENEW_FAILS=0
    RENEW_BACKOFF=3600  # start at 1 h on failure
    while true; do
        sleep 12h
        if flock -n /tmp/sccap-renew.lock certbot renew --quiet --post-hook "nginx -s reload"; then
            RENEW_FAILS=0
            RENEW_BACKOFF=3600
        else
            RENEW_FAILS=$((RENEW_FAILS + 1))
            echo "WARN security_event=cert_renew_failed consecutive_failures=$RENEW_FAILS"
            if [ "$RENEW_FAILS" -ge 5 ]; then
                echo "ERROR security_event=cert_renew_backoff backing off ${RENEW_BACKOFF}s after $RENEW_FAILS failures"
                sleep "$RENEW_BACKOFF"
                RENEW_BACKOFF=$((RENEW_BACKOFF * 2))
                if [ "$RENEW_BACKOFF" -gt 86400 ]; then
                    RENEW_BACKOFF=86400  # cap at 24 h
                fi
                RENEW_FAILS=0
            fi
        fi
    done
) &
RENEWAL_PID=$!

# V15.4.1: forward SIGTERM/INT to the renewal subshell so it is reaped cleanly
# when the container init sends the shutdown signal.
trap "kill $RENEWAL_PID 2>/dev/null" TERM INT EXIT

# The main Nginx process will start after this entrypoint script finishes.
exit 0

