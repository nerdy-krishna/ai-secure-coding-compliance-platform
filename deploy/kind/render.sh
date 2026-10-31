#!/usr/bin/env bash
# Render the kind deployment from the local .env and apply it.
#
#   ./deploy/kind/render.sh          # create/refresh the Secret and apply
#   ./deploy/kind/render.sh --delete # remove everything from the cluster
#
# The Secret is built from .env with the Compose hostnames swapped for the
# in-cluster service names, so the cluster runs the same credentials, models and
# admin account as the Compose installation.
set -euo pipefail
cd "$(dirname "$0")/../.."

CTX=${KUBE_CONTEXT:-kind-sccap}
NS=sccap

if [ "${1:-}" = "--delete" ]; then
    kubectl --context "$CTX" delete namespace "$NS" --ignore-not-found
    exit 0
fi

[ -f .env ] || { echo "[!] .env not found; run ./setup.sh first." >&2; exit 1; }

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
python3 - "$tmp" <<'PY'
import pathlib, sys
out = pathlib.Path(sys.argv[1])
kv = {}
for line in pathlib.Path(".env").read_text().splitlines():
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    key, _, value = line.partition("=")
    kv[key.strip()] = value.strip()
# In-cluster names replace the Compose hostnames; the parts that only make sense
# on a Compose network are switched off.
kv.update({
    "POSTGRES_HOST": "postgres",
    "POSTGRES_HOST_ALEMBIC": "postgres",
    "RABBITMQ_HOST": "rabbitmq",
    "RABBITMQ_URL": "",
    "QDRANT_HOST": "qdrant",
    "COMPOSE_PROFILES": "",
})
# EVIDENCE_* points at the Compose-only MinIO; the cluster has no object store.
for key in ("RABBITMQ_URL", "EVIDENCE_S3_ENDPOINT", "COMPOSE_PROFILES"):
    kv.pop(key, None)
kv["EVIDENCE_STORE_ENABLED"] = "false"
out.write_text("\n".join(f"{k}={v}" for k, v in sorted(kv.items())) + "\n")
PY

kubectl --context "$CTX" create namespace "$NS" --dry-run=client -o yaml | kubectl --context "$CTX" apply -f - >/dev/null
kubectl --context "$CTX" -n "$NS" delete secret sccap-env --ignore-not-found >/dev/null
kubectl --context "$CTX" -n "$NS" create secret generic sccap-env --from-env-file="$tmp" >/dev/null
echo "[+] Secret sccap-env written ($(grep -c . "$tmp") keys)"

# Order matters: backing services first, then migrations+API, then worker and UI.
kubectl --context "$CTX" apply -f deploy/kind/20-infrastructure.yaml
kubectl --context "$CTX" -n "$NS" rollout status statefulset/postgres --timeout=180s
kubectl --context "$CTX" -n "$NS" rollout status statefulset/rabbitmq --timeout=180s
kubectl --context "$CTX" -n "$NS" rollout status statefulset/qdrant --timeout=180s
kubectl --context "$CTX" apply -f deploy/kind/30-app.yaml
kubectl --context "$CTX" -n "$NS" rollout status deployment/api --timeout=300s
kubectl --context "$CTX" -n "$NS" rollout status deployment/worker --timeout=180s
kubectl --context "$CTX" -n "$NS" rollout status deployment/ui --timeout=120s

cat <<'TXT'

[+] SCCAP is running on kind

    UI   http://localhost:8080
    API  http://localhost:8001/api/v1/setup/status

    kubectl --context kind-sccap -n sccap get pods
TXT
