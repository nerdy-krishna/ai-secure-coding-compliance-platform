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
# `INSTALL_DEV_DEPS` (F15b follow-up): set to `true` at build time to
# include dev deps (pytest, pytest-asyncio, etc.) in the venv. Useful
# for CI / local pytest runs inside the container; the production
# image stays slim by leaving the default `false`.
FROM poetry-base AS api-builder
ARG INSTALL_DEV_DEPS=false

RUN --mount=type=cache,target=/home/appuser/.cache/pypoetry,uid=1001,gid=1001 \
    --mount=type=cache,target=/home/appuser/.cache/pip,uid=1001,gid=1001 \
    if [ "${INSTALL_DEV_DEPS}" = "true" ]; then \
        poetry install --no-interaction --no-ansi --no-root --with test ; \
    else \
        poetry install --no-interaction --no-ansi --no-root --without dev ; \
    fi

# ---------- worker-builder -----------------------------------------------
# Installs core + the worker group (torch, sentence-transformers, tree-sitter).
FROM poetry-base AS worker-builder

RUN --mount=type=cache,target=/home/appuser/.cache/pypoetry,uid=1001,gid=1001 \
    --mount=type=cache,target=/home/appuser/.cache/pip,uid=1001,gid=1001 \
    poetry install --no-interaction --no-ansi --no-root --without dev --with worker

# ---------- api ----------------------------------------------------------
FROM base AS api

# git is needed by GitPython for the repo-clone submission path in
# scan_service.create_scan_from_git, and for the semgrep rule ingestion
# sync which clones rule repos via GitPython in BackgroundTasks.
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# --- Semgrep (API) ---
# Needed for `semgrep --validate` in the rule-ingestion sync path.
# Same isolated-venv approach as the worker stage (rich version conflict).
RUN set -eux; \
    python -m venv /opt/semgrep-venv; \
    /opt/semgrep-venv/bin/pip install --no-cache-dir "setuptools<81" "semgrep==1.95.0"; \
    ln -s /opt/semgrep-venv/bin/semgrep /usr/local/bin/semgrep; \
    ln -s /opt/semgrep-venv/bin/pysemgrep /usr/local/bin/pysemgrep
USER appuser

COPY --chown=appuser:appuser --from=api-builder /app/.venv /app/.venv
COPY --chown=appuser:appuser ./src /app/src
COPY --chown=appuser:appuser ./alembic /app/alembic
COPY --chown=appuser:appuser alembic.ini /app/alembic.ini

# Pre-warm the fastembed model cache so air-gapped / restricted-egress
# deployments don't reach out to HuggingFace on first scan. Cache lives
# under FASTEMBED_CACHE_PATH (set in base stage). Threat-model G7 +
# mitigation 7.
RUN python -c "from fastembed import TextEmbedding, SparseTextEmbedding; list(TextEmbedding('sentence-transformers/all-MiniLM-L6-v2').embed(['warmup'])); list(SparseTextEmbedding('Qdrant/bm25').embed(['warmup']))"

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# ---------- worker -------------------------------------------------------
FROM base AS worker

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
    curl -fsSL -o /tmp/gitleaks.tar.gz \
        "https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz"; \
    echo "5bc41815076e6ed6ef8fbecc9d9b75bcae31f39029ceb55da08086315316e3ba  /tmp/gitleaks.tar.gz" | sha256sum --check --strict; \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks; \
    chmod 0755 /usr/local/bin/gitleaks; \
    rm /tmp/gitleaks.tar.gz

# --- Bundled scanner configs ---
# Pinned by SHA at build time; rebuild required to bump.
RUN set -eux; \
    mkdir -p /app/scanners/configs/semgrep; \
    curl -fsSL -o /app/scanners/configs/gitleaks.toml \
        "https://raw.githubusercontent.com/gitleaks/gitleaks/v8.21.2/config/gitleaks.toml"; \
    echo "2ce9d818ed5aac0d9a36638a317284bd733c26d5069c980829335183397430bb  /app/scanners/configs/gitleaks.toml" | sha256sum --check --strict; \
    curl -fsSL -o /app/scanners/configs/semgrep/security-audit.yml \
        "https://semgrep.dev/c/p/security-audit"; \
    echo "fdc7027973176abe71f6b1fc8739ef88a4c411735c380cfce4f731df9644e47a  /app/scanners/configs/semgrep/security-audit.yml" | sha256sum --check --strict

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
    curl -fsSL -o /usr/local/bin/osv-scanner \
        "https://github.com/google/osv-scanner/releases/download/v2.3.5/osv-scanner_linux_amd64"; \
    echo "bb30c580afe5e757d3e959f4afd08a4795ea505ef84c46962b9a738aa573b41b  /usr/local/bin/osv-scanner" | sha256sum --check --strict; \
    chmod 0755 /usr/local/bin/osv-scanner

USER appuser

COPY --chown=appuser:appuser --from=worker-builder /app/.venv /app/.venv
COPY --chown=appuser:appuser ./src /app/src

# Pre-warm the fastembed model cache (same as the api stage). Worker
# performs the bulk of the embedder work during scans; baking the
# cache here keeps first-scan latency consistent.
RUN python -c "from fastembed import TextEmbedding, SparseTextEmbedding; list(TextEmbedding('sentence-transformers/all-MiniLM-L6-v2').embed(['warmup'])); list(SparseTextEmbedding('Qdrant/bm25').embed(['warmup']))"

# Pre-warm the OSV-Scanner vulnerability DB so first-scan latency is
# consistent and air-gapped deployments don't reach api.osv.dev at
# runtime. The empty-dir invocation triggers a DB sync; the cache
# lands at $HOME/.cache/osv-scanner. Failures are tolerated so a
# transient build-time network hiccup doesn't break the image —
# runtime will then re-sync on first scan if needed.
RUN set -eux; \
    mkdir -p /tmp/osv-warmup; \
    osv-scanner scan source --recursive /tmp/osv-warmup 2>/dev/null || true; \
    rmdir /tmp/osv-warmup || true

CMD ["python", "-m", "app.workers.consumer"]
