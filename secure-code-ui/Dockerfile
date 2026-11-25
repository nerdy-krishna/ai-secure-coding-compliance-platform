# syntax=docker/dockerfile:1.7
#
# UI image: Vite build in node:20-alpine, served by nginx:alpine.
# Certbot stays in-image for now — a future refactor can split it into a
# dedicated sidecar sharing the ./certbot/conf and ./certbot/www volumes,
# which would keep the UI image free of Python/certbot runtime weight.
# Tracked as a Phase G polish item.

# ---------- build --------------------------------------------------------
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies for the build.
#
# `tsc` and vite live in devDependencies. NODE_ENV=production, npm_config_omit or a
# cached layer from an earlier build can each drop them, and `--include=dev` alone
# does not win because npm gives --omit precedence over --include. The variables
# are cleared for the install, and docker-build-install.sh verifies the result
# instead of trusting it. Changing this command also changes the layer cache key,
# so a poisoned npm ci layer is never silently reused.
COPY package.json package-lock.json docker-build-install.sh ./
RUN --mount=type=cache,target=/root/.npm \
    env -u NODE_ENV -u npm_config_omit -u npm_config_production -u npm_config_only \
    sh ./docker-build-install.sh

COPY . .

ARG VITE_API_BASE_URL
ARG VITE_ALLOWED_HOSTS

RUN VITE_API_BASE_URL=${VITE_API_BASE_URL} VITE_ALLOWED_HOSTS=${VITE_ALLOWED_HOSTS} npm run build

# ---------- serve --------------------------------------------------------
FROM nginx:alpine

# Build provenance, at the end of the stage so a new commit does not invalidate the
# dependency layers above. Until this existed, the only version in the deployment was the
# API's: the UI could be an update behind and still show the newest commit next to the user's
# name, because that number came from /api/v1/system/version. Now the UI carries its own stamp
# and publishes it as /version.json, so a stale bundle is visible instead of plausible.
ARG SCCAP_BUILD_COMMIT=""
ARG SCCAP_BUILD_TIME=""
ARG SCCAP_BUILD_VERSION=""
ENV SCCAP_BUILD_COMMIT=${SCCAP_BUILD_COMMIT} \
    SCCAP_BUILD_TIME=${SCCAP_BUILD_TIME} \
    SCCAP_BUILD_VERSION=${SCCAP_BUILD_VERSION}

# certbot handles initial Let's Encrypt issuance + periodic renewal. When
# SSL_ENABLED=false (the local-dev default) certbot is installed but never
# invoked by the entrypoint.
RUN apk add --no-cache certbot

COPY --from=builder /app/dist /usr/share/nginx/html

# The stamp the browser can read. Written after the bundle copy, and generated from the build
# args, so it always describes the files next to it.
RUN printf '{"commit":"%s","built_at":"%s","version":"%s"}\n' \
        "$SCCAP_BUILD_COMMIT" "$SCCAP_BUILD_TIME" "$SCCAP_BUILD_VERSION" \
        > /usr/share/nginx/html/version.json

# Phase A consolidated nginx-https.conf with an __SSL_DOMAIN__ placeholder
# that the entrypoint substitutes at runtime; the unused nginx.conf from
# the old setup was deleted.
COPY nginx.conf /etc/nginx/nginx.conf
COPY nginx-http.conf /etc/nginx/nginx-http.conf
COPY nginx-https.conf /etc/nginx/nginx-https.conf

# Exercise the same assembled HTTP configuration used by local/runtime startup.
# This catches duplicate http-context declarations and invalid server fragments
# while the image is being built rather than after deployment. The runtime
# placeholders (__NGINX_RESOLVER__, __SSL_DOMAIN__) are substituted here with
# syntax-valid stand-ins so `nginx -t` validates the structure, not the values.
RUN sed -e 's|__NGINX_RESOLVER__|127.0.0.11|g' -e 's|__SSL_DOMAIN__|example.invalid|g' \
        -e 's|__BACKEND_HOST__|app|g' -e 's|__GRAFANA_HOST__|grafana|g' \
        /etc/nginx/nginx-http.conf > /etc/nginx/conf.d/default.conf \
    && nginx -t

COPY nginx-entrypoint.sh /docker-entrypoint.d/99-ssl-setup.sh
RUN chmod +x /docker-entrypoint.d/99-ssl-setup.sh

RUN addgroup -S nginx-app && adduser -S -G nginx-app nginx-app \
    && chown -R nginx-app:nginx-app /usr/share/nginx/html /var/cache/nginx /var/log/nginx /etc/nginx \
    && touch /var/run/nginx.pid && chown nginx-app:nginx-app /var/run/nginx.pid \
    && mkdir -p /etc/letsencrypt /var/log/letsencrypt /var/lib/letsencrypt \
    && chown -R nginx-app:nginx-app /etc/letsencrypt /var/log/letsencrypt /var/lib/letsencrypt
USER nginx-app

EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]
