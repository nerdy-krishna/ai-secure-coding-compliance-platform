# syntax=docker/dockerfile:1.7
#
# Unified multi-stage Dockerfile for the Python services (API + worker).
# Build a specific service with `docker build --target api` or `--target worker`.
# docker-compose.yml drives both targets from this one file.
#
# Stage layout:
#   base           → runtime OS, non-root user, minimal apt (libpq5, ca-certs)
#   poetry-base    → base + build-essential + poetry (shared by both builders)
#   api-builder    → poetry-base + `poetry install --without dev` (no worker
#                    group) → lean venv without tree-sitter (worker-only)
#   worker-builder → poetry-base + `poetry install --without dev --with worker`
#                    → adds the tree-sitter AST stack on top of the API deps
#   api            → base + api venv + source + git binary (GitPython)
#   worker         → base + worker venv + source (no git)
#   patch-validator → networkless allowlisted compiler/test sandbox
#
# The dep split keeps tree-sitter + tree-sitter-languages off the API
# image. Non-root (uid 1001) everywhere. BuildKit cache mounts on
# pip/poetry keep rebuilds fast.
#
# Embedder note: `sentence-transformers/all-MiniLM-L6-v2` is loaded
# at runtime via `fastembed.TextEmbedding(...)` (ADR-008). The model
# weights are downloaded once at build time by the warmup `RUN`s in
# the api + worker final stages and cached at
# `FASTEMBED_CACHE_PATH=/opt/fastembed-cache`, so runtime never
# touches HuggingFace and the image works in air-gapped deployments.

# ---------- base ---------------------------------------------------------
FROM python:3.12-slim-bookworm AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app/src \
    PATH="/app/.venv/bin:$PATH" \
    FASTEMBED_CACHE_PATH=/opt/fastembed-cache

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libpq5 \
        # Runtime libraries required by python3-saml (lxml + xmlsec1 bindings).
        # python3-saml needs libxmlsec1 + libxmlsec1-openssl for canonicalization
        # and signature validation; without these the SAML SP layer fails on
        # import. See threat-model M3 (SAML hardening).
        libxmlsec1 \
        libxmlsec1-openssl \
        libxml2 \
    && rm -rf /var/lib/apt/lists/*

ARG APP_USER=appuser
ARG APP_UID=1001
ARG APP_GID=1001
RUN groupadd --gid ${APP_GID} ${APP_USER} \
    && useradd --uid ${APP_UID} --gid ${APP_GID} --create-home --shell /bin/bash ${APP_USER}

WORKDIR /app
RUN mkdir -p /app/.venv /app/.cache /opt/fastembed-cache \
    && chown -R ${APP_USER}:${APP_USER} /app /opt/fastembed-cache

# ---------- poetry-base --------------------------------------------------
# Shared base for both builders. Has build-essential (for any wheels that
# need to compile) and poetry itself. The only thing both builders do is
# copy lock + pyproject and run a tailored `poetry install`.
FROM base AS poetry-base

ENV POETRY_VERSION=1.8.3 \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_VIRTUALENVS_CREATE=true

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        # Build deps for python3-saml + lxml: pkg-config + headers for
        # libxmlsec1 / libxml2 are required when building the xmlsec
        # Python bindings against the runtime libraries pulled in by
        # the base stage.
        pkg-config \
        libxmlsec1-dev \
        libxml2-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN --mount=type=cache,target=/root/.cache/pip \
    pip install "poetry==${POETRY_VERSION}"

USER appuser
COPY --chown=appuser:appuser pyproject.toml poetry.lock ./

# ---------- api-builder --------------------------------------------------
# Installs only core runtime deps (no dev group, no optional worker group).
# The worker group is `optional = true` in pyproject.toml so plain
# `poetry install` skips it by default; `--without dev` just drops the
# dev tools.
#
FROM poetry-base AS api-builder

RUN --mount=type=cache,target=/home/appuser/.cache/pypoetry,uid=1001,gid=1001 \
    --mount=type=cache,target=/home/appuser/.cache/pip,uid=1001,gid=1001 \
    poetry install --no-interaction --no-ansi --no-root --without dev

# ---------- worker-builder -----------------------------------------------
# Installs core + the worker group (torch, sentence-transformers, tree-sitter).
FROM poetry-base AS worker-builder

RUN --mount=type=cache,target=/home/appuser/.cache/pypoetry,uid=1001,gid=1001 \
    --mount=type=cache,target=/home/appuser/.cache/pip,uid=1001,gid=1001 \
    poetry install --no-interaction --no-ansi --no-root --without dev --with worker

# ---------- api ----------------------------------------------------------
FROM base AS api

ARG TARGETARCH

# git is needed by GitPython for the repo-clone submission path in
# scan_service.create_scan_from_git, and for the semgrep rule ingestion
# sync which clones rule repos via GitPython in BackgroundTasks.
#
# libpango / libpangoft2 are WeasyPrint's runtime system dependencies
# (#70) — the PDF findings-report generator renders via WeasyPrint on
# the API process. fonts-dejavu-core gives the PDF a predictable
# fallback font so text renders consistently in air-gapped deployments.
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        git \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# --- Semgrep (API) ---
# Needed for `semgrep --validate` in the rule-ingestion sync path.
# Same isolated-venv approach as the worker stage (rich version conflict).
RUN set -eux; \
    python -m venv /opt/semgrep-venv; \
    /opt/semgrep-venv/bin/pip install --no-cache-dir "setuptools<81" "semgrep==1.95.0"; \
    ln -s /opt/semgrep-venv/bin/semgrep /usr/local/bin/semgrep; \
    ln -s /opt/semgrep-venv/bin/pysemgrep /usr/local/bin/pysemgrep

# Gitleaks candidates are quality-gated synchronously by the authenticated
# foundry review API. Keep this binary identical to the worker's pinned build;
# an API image without it must fail closed rather than approve mocked metrics.
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) GITLEAKS_ARCH="x64"; GITLEAKS_SHA256="5bc41815076e6ed6ef8fbecc9d9b75bcae31f39029ceb55da08086315316e3ba" ;; \
        arm64) GITLEAKS_ARCH="arm64"; GITLEAKS_SHA256="654c935542c89f565aabe7bf7c6c500830f116c114f0aeb509d2460c1ac2e6da" ;; \
        *) echo "Unsupported Gitleaks target architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/gitleaks.tar.gz \
        "https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_${GITLEAKS_ARCH}.tar.gz"; \
    echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tar.gz" | sha256sum --check --strict; \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks; \
    chmod 0755 /usr/local/bin/gitleaks; \
    rm /tmp/gitleaks.tar.gz
USER appuser

COPY --chown=appuser:appuser --from=api-builder /app/.venv /app/.venv
COPY --chown=appuser:appuser ./src /app/src
COPY --chown=appuser:appuser ./alembic /app/alembic
COPY --chown=appuser:appuser alembic.ini /app/alembic.ini
COPY --chown=appuser:appuser docker/app-entrypoint.sh /app/app-entrypoint.sh

# Pre-warm the fastembed model cache so air-gapped / restricted-egress
# deployments don't reach out to HuggingFace on first scan. Cache lives
# under FASTEMBED_CACHE_PATH (set in base stage). Threat-model G7 +
# mitigation 7.
RUN python -c "from fastembed import TextEmbedding, SparseTextEmbedding; list(TextEmbedding('sentence-transformers/all-MiniLM-L6-v2').embed(['warmup'])); list(SparseTextEmbedding('Qdrant/bm25').embed(['warmup']))"

RUN chmod +x /app/app-entrypoint.sh
ENV SCCAP_MIGRATION_ROLE=wait
EXPOSE 8000
ENTRYPOINT ["/app/app-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# ---------- worker -------------------------------------------------------
FROM base AS worker

ARG TARGETARCH

# SAST scanner binaries used by app.infrastructure.scanners runners.
# Installed under root, then dropped to appuser. Versions + SHA256 are
# pinned per .agent/devsecops_playbook.md §9 (supply chain).
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        # Gitleaks shells out to `git` (even when scanning a non-git
        # tree, for working-tree status); without it on $PATH it
        # fails fast with `exec: "git": executable file not found`
        # and the whole secret-scan pass returns 0 findings silently.
        git \
    && rm -rf /var/lib/apt/lists/*

# --- Gitleaks v8.21.2 ---
# https://github.com/gitleaks/gitleaks/releases/tag/v8.21.2
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) GITLEAKS_ARCH="x64"; GITLEAKS_SHA256="5bc41815076e6ed6ef8fbecc9d9b75bcae31f39029ceb55da08086315316e3ba" ;; \
        arm64) GITLEAKS_ARCH="arm64"; GITLEAKS_SHA256="654c935542c89f565aabe7bf7c6c500830f116c114f0aeb509d2460c1ac2e6da" ;; \
        *) echo "Unsupported Gitleaks target architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/gitleaks.tar.gz \
        "https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_${GITLEAKS_ARCH}.tar.gz"; \
    echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tar.gz" | sha256sum --check --strict; \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks; \
    chmod 0755 /usr/local/bin/gitleaks; \
    rm /tmp/gitleaks.tar.gz

# --- Bundled Gitleaks config ---
# Pinned by SHA at build time; rebuild required to bump. Semgrep rules are
# selected from Postgres and materialized per scan; no Semgrep pack is bundled.
RUN set -eux; \
    mkdir -p /app/scanners/configs; \
    curl -fsSL -o /app/scanners/configs/gitleaks.toml \
        "https://raw.githubusercontent.com/gitleaks/gitleaks/v8.21.2/config/gitleaks.toml"; \
    echo "2ce9d818ed5aac0d9a36638a317284bd733c26d5069c980829335183397430bb  /app/scanners/configs/gitleaks.toml" | sha256sum --check --strict

# --- Semgrep ---
# Isolated venv at /opt/semgrep-venv because Semgrep pins rich<13.6 while
# fastmcp ^3.2.4 needs rich>=13.9.4 — they cannot coexist in the main
# /app/.venv. The runner finds the binary via shutil.which / explicit path.
RUN set -eux; \
    python -m venv /opt/semgrep-venv; \
    # `setuptools` provides pkg_resources, which Semgrep 1.95.0's
    # opentelemetry-instrumentation transitive dep imports at module
    # load time. Python 3.12 venvs no longer install setuptools by
    # default; without it Semgrep crashes with
    # `ModuleNotFoundError: No module named 'pkg_resources'` before
    # it can emit any results.
    # Pin setuptools <81 — setuptools 81 deprecated pkg_resources
    # and 82+ removed it entirely. Semgrep's
    # opentelemetry-instrumentation transitive dep still imports it
    # at module load, so a fresh `pip install setuptools` (which
    # picks the latest) breaks Semgrep with
    # `ModuleNotFoundError: pkg_resources`. Reassess when Semgrep
    # bumps its tracing deps off pkg_resources.
    /opt/semgrep-venv/bin/pip install --no-cache-dir "setuptools<81" "semgrep==1.95.0"; \
    ln -s /opt/semgrep-venv/bin/semgrep /usr/local/bin/semgrep; \
    # Semgrep's CLI shells out to `pysemgrep` (its Python sub-binary)
    # via execvp, which needs the binary on $PATH. Without this
    # symlink the runner exits with `Unix_error: No such file or
    # directory execvp pysemgrep` and stdout is empty; the worker
    # logs `scanner=semgrep rc=2 stdout_bytes=0` and the whole
    # Semgrep pass produces 0 findings.
    ln -s /opt/semgrep-venv/bin/pysemgrep /usr/local/bin/pysemgrep

# --- OSV-Scanner v2.3.5 ---
# https://github.com/google/osv-scanner/releases/tag/v2.3.5
# Single Go binary; SHA256-pinned. The runner at
# `app.infrastructure.scanners.osv_runner` invokes this via
# subprocess for §3.6 / ADR-009 dependency-CVE detection + CycloneDX
# BOM emission. The vulnerability DB is pre-warmed below so air-gapped
# / restricted-egress deployments don't reach api.osv.dev at runtime.
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) OSV_ARCH="amd64"; OSV_SHA256="bb30c580afe5e757d3e959f4afd08a4795ea505ef84c46962b9a738aa573b41b" ;; \
        arm64) OSV_ARCH="arm64"; OSV_SHA256="fa46ad2b3954db5d5335303d45de921613393285d9a93c140b63b40e35e9ce50" ;; \
        *) echo "Unsupported OSV-Scanner target architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /usr/local/bin/osv-scanner \
        "https://github.com/google/osv-scanner/releases/download/v2.3.5/osv-scanner_linux_${OSV_ARCH}"; \
    echo "${OSV_SHA256}  /usr/local/bin/osv-scanner" | sha256sum --check --strict; \
    chmod 0755 /usr/local/bin/osv-scanner

USER appuser

COPY --chown=appuser:appuser --from=worker-builder /app/.venv /app/.venv
COPY --chown=appuser:appuser ./src /app/src
COPY --chown=appuser:appuser ./alembic /app/alembic
COPY --chown=appuser:appuser alembic.ini /app/alembic.ini
COPY --chown=appuser:appuser docker/app-entrypoint.sh /app/app-entrypoint.sh

# Pre-warm the fastembed model cache (same as the api stage). Worker
# performs the bulk of the embedder work during scans; baking the
# cache here keeps first-scan latency consistent.
RUN python -c "from fastembed import TextEmbedding, SparseTextEmbedding; list(TextEmbedding('sentence-transformers/all-MiniLM-L6-v2').embed(['warmup'])); list(SparseTextEmbedding('Qdrant/bm25').embed(['warmup']))"

# OSV vulnerability matching currently uses the live OSV API. We do not claim
# an offline snapshot: the earlier empty-directory "warm-up" created no
# verifiable advisory cache. Per-scan provenance therefore marks OSV advisory
# coverage degraded until a dated offline database is downloaded, hashed, and
# invoked explicitly with OSV-Scanner's offline flags.

RUN chmod +x /app/app-entrypoint.sh
ENV SCCAP_MIGRATION_ROLE=wait
ENTRYPOINT ["/app/app-entrypoint.sh"]
CMD ["python", "-m", "app.workers.consumer"]

# ---------- Capability 5 tool supervisor / scope relay -----------------
# Deliberately excludes the general SAST binaries and model cache from the
# unified worker image. Adapter runtimes are separate digest-pinned workloads;
# this image owns only RabbitMQ notification reconciliation, narrow gateway
# calls, runtime supervision, evidence collection, and result signing.
FROM base AS tool-supervisor

COPY --chown=appuser:appuser --from=api-builder /app/.venv /app/.venv
COPY --chown=appuser:appuser ./src /app/src

USER root
RUN install -d -o appuser -g appuser -m 0700 /work \
    && install -d -o root -g root -m 0755 /opt/sccap-tool-runtimes \
    && printf '%s\n' '#!/bin/sh' 'exec python -m app.infrastructure.pentesting.tool_worker.adapter_processes.playwright_process "$@"' > /opt/sccap-tool-runtimes/playwright-observe \
    && printf '%s\n' '#!/bin/sh' 'exec python -m app.infrastructure.pentesting.tool_worker.adapter_processes.zap_process "$@"' > /opt/sccap-tool-runtimes/zap-passive \
    && printf '%s\n' '#!/bin/sh' 'exec python -m app.infrastructure.pentesting.tool_worker.adapter_processes.nuclei "$@"' > /opt/sccap-tool-runtimes/nuclei-observe \
    && printf '%s\n' '#!/bin/sh' 'exec python -m app.infrastructure.pentesting.tool_worker.adapter_processes.nmap "$@"' > /opt/sccap-tool-runtimes/nmap-connect \
    && chmod 0555 /opt/sccap-tool-runtimes/*
USER appuser

CMD ["python", "-m", "app.infrastructure.pentesting.tool_worker.main"]

# ---------- Capability 5 immutable adapter runtimes -------------------
# These images contain one fixed adapter and its helper only.  They are built
# during release, scanned/signed by digest, and never download tools or updates
# while an assessment is running.  Kubernetes still supplies the invocation
# solely through authenticated pods/attach; these entrypoints accept no target
# or tool configuration from argv or environment.

FROM mcr.microsoft.com/playwright@sha256:dcc5531e97840b9b5e794f2814476b21571c5124a3fca2267d73041f56e7580e AS pentest-adapter-playwright

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    PATH="/app/.venv/bin:$PATH"
USER root
COPY --from=base /usr/local /usr/local
COPY --from=api-builder /app/.venv /app/.venv
RUN /app/.venv/bin/python -m ensurepip \
    && /app/.venv/bin/python -m pip install --no-cache-dir "playwright==1.62.0" \
    && install -d -o pwuser -g pwuser -m 0700 /work \
    && install -d -o root -g root -m 0755 /opt/sccap-tools /opt/sccap-tool-runtimes \
    && printf '%s\n' '#!/bin/sh' 'exec python -m app.infrastructure.pentesting.tool_adapters.runtime_helpers.playwright.main "$@"' > /opt/sccap-tools/playwright-chromium-driver \
    && printf '%s\n' '#!/bin/sh' 'exec python -m app.infrastructure.pentesting.tool_worker.adapter_processes.playwright_process "$@"' > /opt/sccap-tool-runtimes/playwright-observe \
    && chmod 0555 /opt/sccap-tools/playwright-chromium-driver /opt/sccap-tool-runtimes/playwright-observe
COPY --chown=root:root ./src /app/src
WORKDIR /work
USER pwuser
ENTRYPOINT ["/opt/sccap-tool-runtimes/playwright-observe"]
CMD ["--kubernetes-attach-v1"]

FROM ghcr.io/zaproxy/zaproxy@sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef AS pentest-adapter-zap

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    PATH="/app/.venv/bin:$PATH"
USER root
COPY --from=base /usr/local /usr/local
COPY --from=api-builder /app/.venv /app/.venv
RUN install -d -o zap -g zap -m 0700 /work \
    && install -d -o root -g root -m 0755 /opt/sccap-tools /opt/sccap-tool-runtimes \
    && find /zap/plugin -maxdepth 1 -type f \
        ! -name 'Readme.txt' \
        ! -name 'callhome-release-0.23.0.zap' \
        ! -name 'network-beta-0.29.0.zap' \
        ! -name 'commonlib-release-1.43.0.zap' \
        ! -name 'pscan-alpha-0.6.0.zap' \
        ! -name 'pscanrules-release-75.zap' \
        -delete \
    && printf '%s\n' '#!/bin/sh' 'exec python -m app.infrastructure.pentesting.tool_adapters.runtime_helpers.zap "$@"' > /opt/sccap-tools/zap-passive-driver \
    && printf '%s\n' '#!/bin/sh' 'exec python -m app.infrastructure.pentesting.tool_worker.adapter_processes.zap_process "$@"' > /opt/sccap-tool-runtimes/zap-passive \
    && chmod 0555 /opt/sccap-tools/zap-passive-driver /opt/sccap-tool-runtimes/zap-passive
COPY --chown=root:root ./src /app/src
WORKDIR /work
USER zap
ENTRYPOINT ["/opt/sccap-tool-runtimes/zap-passive"]
CMD ["--kubernetes-attach-v1"]

FROM projectdiscovery/nuclei@sha256:aeb5ea2db32a252b8135707d2ad0e89b90e19a18ea7816d38759bc51efb46b97 AS pentest-nuclei-binary

FROM base AS pentest-adapter-nuclei

COPY --chown=appuser:appuser --from=api-builder /app/.venv /app/.venv
COPY --from=pentest-nuclei-binary /usr/local/bin/nuclei /opt/sccap-tools/nuclei
COPY --chown=appuser:appuser ./src /app/src
USER root
RUN install -d -o appuser -g appuser -m 0700 /work \
    && install -d -o root -g root -m 0555 /opt/sccap-nuclei-bundles /opt/sccap-nuclei-trust /opt/sccap-tool-runtimes \
    && printf '%s\n' '3.4.10' > /opt/sccap-tools/nuclei.version \
    && printf '%s\n' '#!/bin/sh' 'exec python -m app.infrastructure.pentesting.tool_worker.adapter_processes.nuclei "$@"' > /opt/sccap-tool-runtimes/nuclei-observe \
    && chmod 0444 /opt/sccap-tools/nuclei.version \
    && chmod 0555 /opt/sccap-tools/nuclei /opt/sccap-tool-runtimes/nuclei-observe
WORKDIR /work
USER appuser
ENTRYPOINT ["/opt/sccap-tool-runtimes/nuclei-observe"]
CMD ["--kubernetes-attach-v1"]

FROM python@sha256:09f7da3bc104798d0afb40bc08d23ab2da20a76130cec1f2ef170848f5d85217 AS pentest-adapter-nmap

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    PATH="/app/.venv/bin:$PATH"
RUN apt-get update \
    && apt-get install -y --no-install-recommends "nmap=7.95+dfsg-3" \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1001 appuser \
    && useradd --uid 1001 --gid 1001 --create-home --shell /usr/sbin/nologin appuser
COPY --from=api-builder /app/.venv /app/.venv
COPY --chown=appuser:appuser ./src /app/src
RUN install -d -o appuser -g appuser -m 0700 /work \
    && install -d -o root -g root -m 0755 /opt/sccap-tools /opt/sccap-tool-runtimes \
    && ln -s /usr/bin/nmap /opt/sccap-tools/nmap \
    && ln -s /usr/share/nmap /opt/sccap-tools/nmap-data \
    && printf '%s\n' '#!/bin/sh' 'exec python -m app.infrastructure.pentesting.tool_worker.adapter_processes.nmap "$@"' > /opt/sccap-tool-runtimes/nmap-connect \
    && chmod 0555 /opt/sccap-tool-runtimes/nmap-connect
WORKDIR /work
USER appuser
ENTRYPOINT ["/opt/sccap-tool-runtimes/nmap-connect"]
CMD ["--kubernetes-attach-v1"]

# ---------- development-only local benchmark worker -------------------
# The ordinary production worker image does not contain target scanners.
# This successor is selected only by docker-compose.pentesting-local.yml.
FROM worker AS worker-pentest-local

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        "nmap=7.93+dfsg1-1" \
        default-jre-headless \
        fonts-liberation \
        libasound2 \
        libatk-bridge2.0-0 \
        libatk1.0-0 \
        libatspi2.0-0 \
        libcairo2 \
        libcups2 \
        libdbus-1-3 \
        libdrm2 \
        libgbm1 \
        libglib2.0-0 \
        libnspr4 \
        libnss3 \
        libpango-1.0-0 \
        libx11-6 \
        libxcb1 \
        libxcomposite1 \
        libxdamage1 \
        libxext6 \
        libxfixes3 \
        libxkbcommon0 \
        libxrandr2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=pentest-nuclei-binary /usr/local/bin/nuclei /opt/sccap-tools/nuclei
COPY --from=pentest-adapter-playwright /ms-playwright /ms-playwright
COPY --from=pentest-adapter-playwright /app/.venv/lib/python3.12/site-packages/playwright /app/.venv/lib/python3.12/site-packages/playwright
COPY --from=pentest-adapter-playwright /app/.venv/lib/python3.12/site-packages/pyee /app/.venv/lib/python3.12/site-packages/pyee
COPY --from=pentest-adapter-playwright /app/.venv/lib/python3.12/site-packages/greenlet /app/.venv/lib/python3.12/site-packages/greenlet
COPY --from=pentest-adapter-zap /zap /zap
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN chmod -R a+rX /ms-playwright /zap \
    && chmod 0555 /opt/sccap-tools/nuclei /usr/bin/nmap /zap/zap.sh
USER appuser

# ---------- patch validator ----------------------------------------------
# Deliberately contains no SCCAP application, configuration, or credentials.
# Compose gives it no network namespace and only a bounded shared job spool.
FROM python:3.12-slim-bookworm AS patch-validator

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        golang-go \
        nodejs \
        node-typescript \
        openjdk-17-jdk-headless \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1001 validationclient \
    && groupadd --gid 1002 validator \
    && useradd --uid 1002 --gid 1002 --create-home --shell /usr/sbin/nologin validator \
    && pip install --no-cache-dir "pytest==8.3.5" \
    && mkdir -p /opt/sccap-validation /jobs \
    && chown root:validationclient /jobs \
    && chmod 0770 /jobs

COPY --chown=root:root src/app/shared/lib/validation_sandbox_runner.py /opt/sccap-validation/runner.py

# The small spool daemon retains uid 0 only so it can keep /jobs private and
# drop each validation command to uid/gid 1002. Compose grants only the
# capabilities needed for that drop and cleanup of child-owned temp files.
USER root
ENV SCCAP_VALIDATION_JOB_DIR=/jobs \
    SCCAP_VALIDATION_CHILD_UID=1002 \
    SCCAP_VALIDATION_CHILD_GID=1002 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "-I", "/opt/sccap-validation/runner.py"]
