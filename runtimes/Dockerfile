# syntax=docker/dockerfile:1
#
# SCCAP pentest tool-runtime images.
#
# Build a specific runtime with `docker build -f runtimes/Dockerfile --target <runtime>`.
# Targets: python, authorization, graphql, realtime (pure Python — share one image),
#          nmap, nuclei, zap, playwright.
#
# Each runtime runs one /opt/sccap-tool-runtimes/<name> entrypoint under
# `--kubernetes-attach-v1`. The chart pins every image by digest, so publish
# with `scripts/build-tool-runtimes.sh` which records the digests.

FROM python:3.12-slim-bookworm AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app/src \
    PATH="/app/.venv/bin:$PATH"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libpq5 curl \
    && rm -rf /var/lib/apt/lists/*

ARG APP_USER=appuser
ARG APP_UID=1001
ARG APP_GID=1001
RUN groupadd --gid ${APP_GID} ${APP_USER} \
    && useradd --uid ${APP_UID} --gid ${APP_GID} --create-home --shell /bin/bash ${APP_USER}

WORKDIR /app
RUN mkdir -p /app/.venv /app/.cache /opt/sccap-tool-runtimes /opt/sccap-tools \
    && chown -R ${APP_USER}:${APP_USER} /app /opt/sccap-tool-runtimes /opt/sccap-tools

# Core Python dependencies only (no worker/torch group). Playwright is added in
# its own target below.
COPY pyproject.toml poetry.lock ./
RUN python -m venv /app/.venv \
    && /app/.venv/bin/pip install --no-cache-dir poetry==1.8.3 \
    && /app/.venv/bin/poetry install --no-interaction --no-ansi --no-root --without dev

# ---------- runtime-base: app source + entrypoints ----------
FROM base AS runtime-base
COPY src/ /app/src/
COPY runtimes/bin/ /opt/sccap-tool-runtimes/
RUN chmod 0755 /opt/sccap-tool-runtimes/* \
    && chown -R ${APP_USER}:${APP_USER} /app/src /opt/sccap-tool-runtimes
USER ${APP_USER}

# ---------- pure-Python runtimes (authorization / graphql / realtime) ----------
FROM runtime-base AS python
CMD ["/opt/sccap-tool-runtimes/authorization-readonly", "--kubernetes-attach-v1"]

# ---------- nmap ----------
FROM runtime-base AS nmap
USER root
RUN apt-get update && apt-get install -y --no-install-recommends nmap \
    && ln -s /usr/bin/nmap /opt/sccap-tools/nmap \
    && rm -rf /var/lib/apt/lists/*
USER ${APP_USER}
CMD ["/opt/sccap-tool-runtimes/nmap-connect", "--kubernetes-attach-v1"]

# ---------- nuclei ----------
FROM runtime-base AS nuclei
USER root
# Pinned release; the SHA is supplied by the build script (never fabricated).
ARG NUCLEI_VERSION=3.3.8
ARG NUCLEI_SHA256
ARG TARGETARCH
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) NUCLEI_ARCH="amd64" ;; \
        arm64) NUCLEI_ARCH="arm64" ;; \
        *) echo "Unsupported nuclei arch: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NUCLEI_ARCH}.zip"; \
    echo "${NUCLEI_SHA256}  /tmp/nuclei.zip" | sha256sum --check --strict; \
    unzip -o /tmp/nuclei.zip -d /opt/sccap-tools/; \
    chmod 0755 /opt/sccap-tools/nuclei; \
    rm /tmp/nuclei.zip
USER ${APP_USER}
CMD ["/opt/sccap-tool-runtimes/nuclei-observe", "--kubernetes-attach-v1"]

# ---------- zap ----------
FROM runtime-base AS zap
USER root
# OWASP ZAP cross-platform release, pinned by version + SHA from the build script.
ARG ZAP_VERSION=2.16.0
ARG ZAP_SHA256
RUN set -eux; \
    curl -fsSL -o /tmp/zap.tar.gz \
        "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz"; \
    echo "${ZAP_SHA256}  /tmp/zap.tar.gz" | sha256sum --check --strict; \
    mkdir -p /zap; \
    tar -xzf /tmp/zap.tar.gz -C /zap --strip-components=1; \
    rm /tmp/zap.tar.gz
USER ${APP_USER}
CMD ["/opt/sccap-tool-runtimes/zap-passive", "--kubernetes-attach-v1"]

# ---------- playwright ----------
FROM runtime-base AS playwright
USER root
ARG PLAYWRIGHT_VERSION=1.52.0
RUN /app/.venv/bin/pip install --no-cache-dir "playwright==${PLAYWRIGHT_VERSION}" \
    && /app/.venv/bin/playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/* /root/.cache
USER ${APP_USER}
CMD ["/opt/sccap-tool-runtimes/playwright-observe", "--kubernetes-attach-v1"]
