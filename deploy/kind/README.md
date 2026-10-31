# SCCAP on kind (local Kubernetes)

Runs the current SCCAP stack in a throwaway `kind` cluster: Postgres, RabbitMQ and
Qdrant as StatefulSets, plus the API, worker and UI from the locally built images.

```bash
# 1. Build the images and load them into the node
docker compose build
docker tag secure_coding_platform-app:latest    sccap/api:kind
docker tag secure_coding_platform-worker:latest sccap/worker:kind
docker tag secure_coding_platform-ui:latest     sccap/ui:kind
kind load docker-image sccap/api:kind sccap/worker:kind sccap/ui:kind --name sccap

# 2. Create the cluster (UI on :8080, API on :8001)
kind create cluster --name sccap --config deploy/kind/kind-config.yaml

# 3. Render the Secret from .env and apply everything
./deploy/kind/render.sh
```

Then:

| Surface | URL |
|---|---|
| UI | <http://localhost:8080> |
| API | <http://localhost:8001/api/v1/setup/status> |
| Postgres / RabbitMQ / Qdrant | in-cluster `postgres:5432`, `rabbitmq:5672`, `qdrant:6333` |

`render.sh` builds the `sccap-env` Secret from the repository `.env` with the
Compose hostnames replaced by the service names, so the cluster runs the same
credentials, models and admin account as the Compose installation. A first-run
cluster still needs the setup call; from the API pod:

```bash
kubectl --context kind-sccap -n sccap exec -i deploy/api -- env \
  SCCAP_SETUP_ADMIN_PASSWORD='…' SCCAP_SETUP_LLM_API_KEY='…' \
  python -m app.cli.terminal_setup --api-base http://127.0.0.1:8000 \
    --admin-email you@example.com --deployment-type local \
    --llm-mode multi_provider --llm-provider deepseek --llm-model deepseek-flash
```

## What is not here

- **The production Helm chart** (`deploy/helm/sccap`) still describes the retired
  pentest-v1 stack (controller, runner-v3, session broker, verification
  coordinator), has no UI deployment, and expects external managed Postgres,
  RabbitMQ and Qdrant. It needs a rewrite before it can deploy the current
  architecture.
- **The log stack** (Fluentd → Loki → Grafana) is Compose-only; the UI's
  `/grafana/` link therefore returns 502 in kind.
- **The pentest engine** is not deployed: it needs Chromium and raw-socket
  capabilities that a kind pod does not give you by default.

Tear down with `./deploy/kind/render.sh --delete` (namespace only) or
`kind delete cluster --name sccap`.
