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

# Install deps first for layer-cache stability.
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci

COPY . .

ARG VITE_API_BASE_URL
ARG VITE_ALLOWED_HOSTS

RUN VITE_API_BASE_URL=${VITE_API_BASE_URL} VITE_ALLOWED_HOSTS=${VITE_ALLOWED_HOSTS} npm run build

# ---------- serve --------------------------------------------------------
FROM nginx:alpine

# certbot handles initial Let's Encrypt issuance + periodic renewal. When
# SSL_ENABLED=false (the local-dev default) certbot is installed but never
# invoked by the entrypoint.
RUN apk add --no-cache certbot

COPY --from=builder /app/dist /usr/share/nginx/html

# Phase A consolidated nginx-https.conf with an __SSL_DOMAIN__ placeholder
# that the entrypoint substitutes at runtime; the unused nginx.conf from
# the old setup was deleted.
COPY nginx.conf /etc/nginx/nginx.conf
COPY nginx-http.conf /etc/nginx/nginx-http.conf
COPY nginx-https.conf /etc/nginx/nginx-https.conf

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
