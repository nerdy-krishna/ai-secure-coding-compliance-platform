#!/bin/sh
# Install the UI's build dependencies inside the image.
#
# `tsc` and vite live in devDependencies. Three things can silently drop them:
# NODE_ENV=production (npm treats it as --omit=dev), npm_config_omit /
# npm_config_production in the build environment, or a cached layer produced by a
# build where one of those was set. `--include=dev` alone does not win — npm gives
# --omit precedence over --include — so the Dockerfile clears those variables for
# this script, and the script verifies the result instead of trusting it.
set -eu

if ! npm ci --include=dev --no-audit --no-fund; then
    echo "[install] npm ci failed; falling back to npm install"
    npm install --include=dev --no-audit --no-fund
fi

if [ -x node_modules/.bin/tsc ]; then
    echo "[install] $(ls node_modules | wc -l) packages, tsc present"
    exit 0
fi

echo "ERROR: node_modules/.bin/tsc is missing after the install."
echo "--- diagnostics ---------------------------------------------"
echo "NODE_ENV=${NODE_ENV:-<unset>}"
echo "omit=$(npm config get omit 2>/dev/null || echo '?')"
echo "production=$(npm config get production 2>/dev/null || echo '?')"
echo "installed packages: $(ls node_modules 2>/dev/null | wc -l)"
echo "typescript present: $(test -d node_modules/typescript && echo yes || echo no)"
echo "--------------------------------------------------------------"
echo "The install skipped devDependencies. Unset NODE_ENV / npm_config_omit in the"
echo "environment that runs docker compose build, then rebuild."
exit 1
