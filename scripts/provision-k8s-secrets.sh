#!/usr/bin/env bash
# Provision the Kubernetes Secrets the SCCAP Helm chart reads by name.
#
# The chart uses envFrom/secretKeyRef against the secret names in
# deploy/helm/sccap/values.yaml (runtime.*). This script creates them from
# environment variables or a sourced .env file. Keys not set are skipped, so a
# secret is created even when it is partially populated; fill every key a given
# pod consumes before enabling that workload.
#
# Usage:
#   cp .env.example .env.provision && $EDITOR .env.provision
#   set -a; source .env.provision; set +a
#   bash scripts/provision-k8s-secrets.sh [-n NAMESPACE]
#
# Secrets are intentionally NOT committed as manifests: secret material must
# never land in rendered YAML. Prefer External Secrets / a CSI driver over this
# script for real clusters.

set -euo pipefail
NAMESPACE="${1:--n sccap}"; shift 2>/dev/null || true
NSFLAG="-n ${NAMESPACE#-n }"

# name -> "space-separated env keys". Least-privilege split follows values.yaml:
# never point a scanner/report secret at api/llm/unified material.
declare -A SECRETS=(
  [sccap-api-runtime]="SECRET_KEY ENCRYPTION_KEY ALLOWED_ORIGINS API_BASE_URL FRONTEND_BASE_URL TRUSTED_PROXY_CIDRS POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB POSTGRES_HOST POSTGRES_PORT ASYNC_DATABASE_URL ALEMBIC_DATABASE_URL RABBITMQ_URL RABBITMQ_DEFAULT_USER RABBITMQ_DEFAULT_PASS QDRANT_HOST QDRANT_PORT QDRANT_API_KEY SMTP_HOST SMTP_PORT SMTP_USER SMTP_PASSWORD SMTP_FROM LANGFUSE_ENABLED LANGFUSE_HOST LANGFUSE_PUBLIC_KEY LANGFUSE_SECRET_KEY"
  [sccap-scanner-runtime]="POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB POSTGRES_HOST POSTGRES_PORT ASYNC_DATABASE_URL ALEMBIC_DATABASE_URL RABBITMQ_URL RABBITMQ_DEFAULT_USER RABBITMQ_DEFAULT_PASS QDRANT_HOST QDRANT_PORT QDRANT_API_KEY EVIDENCE_STORE_ENABLED EVIDENCE_S3_ENDPOINT EVIDENCE_S3_REGION EVIDENCE_S3_BUCKET EVIDENCE_S3_ACCESS_KEY_ID EVIDENCE_S3_SECRET_ACCESS_KEY EVIDENCE_S3_FORCE_PATH_STYLE EVIDENCE_KEY_PROVIDER EVIDENCE_KMS_KEY_ID EVIDENCE_KMS_PREVIOUS_KEY_IDS"
  [sccap-llm-runtime]="SECRET_KEY ENCRYPTION_KEY POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB POSTGRES_HOST POSTGRES_PORT ASYNC_DATABASE_URL RABBITMQ_URL RABBITMQ_DEFAULT_USER RABBITMQ_DEFAULT_PASS QDRANT_HOST QDRANT_PORT QDRANT_API_KEY"
  [sccap-report-runtime]="POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB POSTGRES_HOST POSTGRES_PORT ASYNC_DATABASE_URL RABBITMQ_URL RABBITMQ_DEFAULT_USER RABBITMQ_DEFAULT_PASS EVIDENCE_STORE_ENABLED EVIDENCE_S3_ENDPOINT EVIDENCE_S3_REGION EVIDENCE_S3_BUCKET EVIDENCE_S3_ACCESS_KEY_ID EVIDENCE_S3_SECRET_ACCESS_KEY"
  [sccap-migration-runtime]="ALEMBIC_DATABASE_URL ASYNC_DATABASE_URL POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB POSTGRES_HOST POSTGRES_PORT"
  [sccap-unified-runtime]="ASYNC_DATABASE_URL RABBITMQ_URL QDRANT_HOST QDRANT_PORT QDRANT_API_KEY"
  [sccap-pentest-runner-v3-runtime]="RABBITMQ_URL ASYNC_DATABASE_URL"
  [sccap-pentest-controller-runtime]="POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB ASYNC_DATABASE_URL RABBITMQ_URL RABBITMQ_PENTEST_CONTROLLER_URL SECRET_KEY ENCRYPTION_KEY"
  [sccap-pentest-tool-worker-runtime]="RABBITMQ_URL PENTEST_TOOL_GATEWAY_TOKEN"
  [sccap-pentest-verification-runtime]="RABBITMQ_URL ASYNC_DATABASE_URL"
  [sccap-pentest-c67-pipeline-runtime]="ASYNC_DATABASE_URL PENTEST_VERIFICATION_LOCATOR_SIGNING_SEED"
  [sccap-pentest-session-broker-runtime]="RABBITMQ_URL ASYNC_DATABASE_URL"
)

for secret in "${!SECRETS[@]}"; do
  args=()
  for key in ${SECRETS[$secret]}; do
    if [[ -n "${!key:-}" ]]; then
      args+=(--from-literal="$key=${!key}")
    fi
  done
  if [[ ${#args[@]} -eq 0 ]]; then
    echo "skip $secret (no keys set)"
    continue
  fi
  kubectl create secret generic "$secret" "${args[@]}" $NSFLAG \
    --dry-run=client -o yaml | kubectl apply -f -
  echo "provisioned $secret ($((${#args[@]}/2)) keys)"
done
