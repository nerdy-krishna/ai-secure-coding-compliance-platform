#!/bin/sh
# Install the UI's build dependencies inside the image, and prove the result.
#
# Two independent things have broken this build on real machines:
#
#  1. npm skipping devDependencies. `tsc` and vite live there, and
#     NODE_ENV=production / npm_config_omit=dev make npm omit them regardless of
#     --include=dev (npm gives --omit precedence). The Dockerfile clears those
#     variables; this script verifies the outcome.
#
#  2. npm crashing mid-install ("Exit handler never called!") and leaving a tree
#     with the packages unpacked but no bin links. The install looks complete,
#     yet node_modules/.bin/tsc does not exist. That is usually out-of-memory on a
#     small VM, or an npm cache left corrupt by an earlier crash.
#
# So: install, then repair rather than re-download (rebuild the links, then link
# the two binaries directly), then retry from scratch with a private cache and
# reduced concurrency, and only then fail — with the diagnostics that say which
# of the two happened.
set -eu

log() { echo "[install] $*"; }

# The binaries `npm run build` and the quality gates invoke.
bins_ok() {
    [ -x node_modules/.bin/tsc ] && [ -x node_modules/.bin/vite ]
}

packages_present() {
    [ -d node_modules/typescript ] && [ -d node_modules/vite ]
}

# Re-create the two bin links npm would have made, from the unpacked packages.
link_bins() {
    mkdir -p node_modules/.bin
    if [ ! -x node_modules/.bin/tsc ] && [ -f node_modules/typescript/bin/tsc ]; then
        ln -sf ../typescript/bin/tsc node_modules/.bin/tsc
        log "linked node_modules/.bin/tsc"
    fi
    if [ ! -x node_modules/.bin/vite ] && [ -f node_modules/vite/bin/vite.js ]; then
        ln -sf ../vite/bin/vite.js node_modules/.bin/vite
        log "linked node_modules/.bin/vite"
    fi
}

# Best-effort repair: ask npm to rebuild the links, then link them ourselves.
repair() {
    log "toolchain unusable; repairing bin links"
    npm rebuild --no-audit --no-fund >/dev/null 2>&1 || true
    link_bins
}

install() {
    if ! npm ci --include=dev --no-audit --no-fund --no-progress; then
        log "npm ci failed; trying npm install"
        npm install --include=dev --no-audit --no-fund --no-progress || true
    fi
}

log "npm ci (cache: ${npm_config_cache:-default})"
install

if bins_ok; then
    log "$(ls node_modules | wc -l) packages, toolchain present"
    exit 0
fi

# A crashed install leaves the packages but no links. Repair first — it costs a
# second and avoids re-downloading 180 packages.
if packages_present; then
    repair
    if bins_ok; then
        log "$(ls node_modules | wc -l) packages, toolchain present (repaired)"
        exit 0
    fi
fi

# Still unusable: start from nothing with a private cache (the shared one may be
# corrupt from the crash) and fewer concurrent sockets for a small VM.
log "retrying from scratch with a private cache"
rm -rf node_modules
npm_config_cache=$(mktemp -d /tmp/npm-cache.XXXXXX)
export npm_config_cache
npm_config_maxsockets=3
export npm_config_maxsockets
npm_config_fetch_retries=2
export npm_config_fetch_retries

install

if bins_ok; then
    log "$(ls node_modules | wc -l) packages, toolchain present (fresh cache)"
    exit 0
fi

if packages_present; then
    repair
    if bins_ok; then
        log "toolchain present after repair (fresh cache)"
        exit 0
    fi
fi

echo "ERROR: the build toolchain is still unusable after three attempts."
echo "--- diagnostics ---------------------------------------------"
echo "node $(node --version) / npm $(npm --version)"
echo "NODE_ENV=${NODE_ENV:-<unset>}  omit=$(npm config get omit 2>/dev/null || echo '?')"
echo "production=$(npm config get production 2>/dev/null || echo '?')"
echo "installed packages: $(ls node_modules 2>/dev/null | wc -l)"
echo "typescript present: $(test -d node_modules/typescript && echo yes || echo no)"
echo "vite present: $(test -d node_modules/vite && echo yes || echo no)"
echo "bin directory:"
ls -1 node_modules/.bin 2>/dev/null | head -20 || echo "  (missing)"
echo "--------------------------------------------------------------"
echo "If npm printed 'Exit handler never called', it crashed rather than"
echo "misconfigured: give the builder more memory (swap, or build one service at"
echo "a time: docker compose build ui) and rebuild."
exit 1
