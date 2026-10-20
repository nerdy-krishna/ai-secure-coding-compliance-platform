# Cloud Kubernetes deployment (AKS / EKS)

SCCAP ships a production-oriented Helm chart at `deploy/helm/sccap`. It deploys
the stateless application plane — API, worker pools, pentesting controller,
runner, verification coordinator, telemetry — against externally provisioned
stateful dependencies. This document is the runbook for installing it on Azure
Kubernetes Service (AKS) or Amazon EKS.

The chart is **not** a full-stack recipe: Postgres, RabbitMQ, Qdrant and the
object store are deliberately out-of-chart so each can be a managed service or
an operator you already run. The chart only binds to them.

## What the chart deploys

| Workload | Purpose | Default |
|---|---|---|
| `api` | FastAPI service (ClusterIP, port 8000) | on, 2 replicas |
| `workerPools.scanner/llm/report/unified` | RabbitMQ consumers, KEDA-scaled | scanner/llm/report on |
| `pentestController`, `runnerV3`, `pentestVerification`, `pentestC67Pipeline`, `pentestSessionBroker` | pentest execution plane | off (enable per engagement) |
| `otel-collector` | OTLP telemetry sidecar | on |
| `migration-job` | runs `alembic upgrade head` before the app | on |

Everything is `seccompProfile: RuntimeDefault`, `runAsNonRoot`, read-only
root filesystem, with per-workload ServiceAccounts and NetworkPolicies.

## Prerequisites

- `kubectl`, `helm` (≥ 3), and `az` (AKS) or `aws` (EKS) CLI.
- A container registry your cluster can pull from (ACR / ECR / GHCR).
- A KEDA installation (the worker pools autoscale on RabbitMQ depth).
- The four stateful dependencies reachable from the cluster.

## 1. Stateful dependencies

The chart's NetworkPolicy allows egress to these ports; provision them first.

| Dependency | Port | Managed option |
|---|---|---|
| PostgreSQL 16+ | 5432 | Azure Database for PostgreSQL Flexible Server / Amazon RDS |
| RabbitMQ 3.12+ (AMQP + TLS) | 5672/5671 | Azure Service Bus is *not* RabbitMQ — use the RabbitMQ Cluster Operator or Aiven/CloudAMQP on both clouds |
| Qdrant | 6333 | Qdrant Cloud / self-hosted |
| Object store (S3-compatible) | 443 | Azure Blob + Azurite API / Amazon S3 |

Enable TLS on Postgres and RabbitMQ. The chart's KEDA scaler queries
`rabbitmq:15692` by default — set `autoscaling.keda.rabbitmqPrometheusAddress`
to your RabbitMQ's Prometheus endpoint, or deploy RabbitMQ in the same
namespace with that service name.

## 2. Images

Publish the application images and the pentest tool-pack runtimes to a registry
your cluster can pull from, then reference them in `values.yaml`.

Published images live on Docker Hub (public repos), built for linux/amd64:

```yaml
images:
  api:    {repository: docker.io/nerdykrishna/sccap-api,    tag: "v1.0.0"}
  worker: {repository: docker.io/nerdykrishna/sccap-worker, tag: "v1.0.0"}
```

The chart's `pentestToolPack.runtimes` already carries the exact
`repository@sha256` digests for the six tool-runtime images. Rebuild/push with
`scripts/build-tool-runtimes.sh` (docker login first) and
`.github/workflows/tool-runtime-release.yml`.

pentestToolPack:
  enabled: true
  runtimes:
    authorization: {image: your-registry/pentest-tool-authorization@sha256:...}
    playwright:    {image: your-registry/pentest-tool-playwright@sha256:...}
    zap:           {image: your-registry/pentest-tool-zap@sha256:...}
    nuclei:        {image: your-registry/pentest-tool-nuclei@sha256:...}
    nmap:          {image: your-registry/pentest-tool-nmap@sha256:...}
    # graphql, realtime likewise
```

The tool-pack runtimes are invoked with `--kubernetes-attach-v1`, so on a cloud
cluster they run as pods against the cluster API — no nested kind cluster is
required. Pin them by digest, not tag.

## 3. Secrets

The chart reads configuration from Kubernetes Secrets by name; it does **not**
create or template them (so no secret material lands in rendered manifests).
Create one Secret per privilege boundary listed in
`deploy/helm/sccap/values.yaml` under `runtime`:

```bash
kubectl create secret generic sccap-api-runtime \
  --from-literal=POSTGRES_USER=... \
  --from-literal=POSTGRES_PASSWORD=... \
  --from-literal=DATABASE_URL=postgresql+asyncpg://... \
  --from-literal=SECRET_KEY=... \
  --from-literal=ENCRYPTION_KEY=... \
  # ... every key the api pod consumes
```

Do the same for `sccap-scanner-runtime`, `sccap-llm-runtime`,
`sccap-report-runtime`, `sccap-migration-runtime`, and (when enabled) the
`pentest*` runtime secrets. Keep scanner and report secrets disjoint from the
API/LLM secrets — the pod boundary enforces least privilege.

Recommended: drive these with External Secrets Operator or the Azure Key Vault /
AWS Secrets Manager CSI providers rather than hand-maintained `kubectl create`.
A starting point that creates every secret the chart names is committed at
`scripts/provision-k8s-secrets.sh` (source a populated `.env` first).

## 4. Install on AKS

```bash
az group create -n sccap-rg -l eastus
az aks create -g sccap-rg -n sccap-aks \
  --node-count 3 --node-vm-size Standard_D4s_v5 \
  --enable-oidc-issuer --enable-workload-identity
az aks get-credentials -g sccap-rg -n sccap-aks

helm repo add kedacore https://kedacore.github.io/charts
helm install keda kedacore/keda -n keda --create-namespace

# Ingress: either nginx or AGIC
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm install ingress-nginx ingress-nginx/ingress-nginx -n ingress-nginx --create-namespace

helm install sccap deploy/helm/sccap -n sccap \
  --set images.api.repository=myacr.azurecr.io/sccap-api \
  --set images.worker.repository=myacr.azurecr.io/sccap-worker \
  --set api.ingress.enabled=true \
  --set api.ingress.className=nginx \
  --set api.ingress.host=sccap.example.com \
  --set autoscaling.keda.rabbitmqPrometheusAddress=http://rabbitmq.sccap:15692
```

For Application Gateway Ingress Controller instead of nginx, set
`api.ingress.className=azure-application-gateway` and add the AGIC annotations
under `api.ingress.annotations`.

## 5. Install on EKS

```bash
aws eks create-cluster --name sccap-eks --region us-east-1 \
  --role-arn arn:aws:iam::123456789012:role/eks-cluster-role \
  --resources-vpc-config subnetIds=...,securityGroupIds=...
aws eks create-nodegroup --cluster-name sccap-eks --nodegroup-name workers \
  --node-role arn:aws:iam::123456789012:role/eks-node-role --subnets ... \
  --instance-types m6i.xlarge
aws eks update-kubeconfig --name sccap-eks --region us-east-1

helm install keda kedacore/keda -n keda --create-namespace

# AWS Load Balancer Controller (ALB)
# https://docs.aws.amazon.com/eks/latest/userguide/aws-load-balancer-controller.html

helm install sccap deploy/helm/sccap -n sccap \
  --set images.api.repository=123456789012.dkr.ecr.us-east-1.amazonaws.com/sccap-api \
  --set images.worker.repository=123456789012.dkr.ecr.us-east-1.amazonaws.com/sccap-worker \
  --set api.ingress.enabled=true \
  --set api.ingress.className=alb \
  --set 'api.ingress.annotations.alb\.ingress\.kubernetes\.io/scheme=internet-facing' \
  --set 'api.ingress.annotations.alb\.ingress\.kubernetes\.io/target-type=ip' \
  --set api.ingress.host=sccap.example.com
```

## 6. Verify

```bash
kubectl -n sccap get pods        # all Running, no CrashLoopBackOff
kubectl -n sccap logs job/$(kubectl -n sccap get job -o name | grep migration)
kubectl -n sccap get ingress     # ADDRESS populated
curl https://sccap.example.com/health   # 200
```

Run a smoke engagement against an authorized target before any real work, and
check the API readiness endpoints. If the pentest pods stay `Pending`, it is
usually a missing secret or an unqualified tool-pack image digest — both are
intentional fail-closed states, not chart defects.

## Not yet turnkey

- The pentest tool-pack runtime images (authorization, playwright, zap, nuclei,
  nmap, graphql, realtime) have no committed Dockerfiles and no build workflow;
  only the `api` and `worker` images are published by the signed release
  pipeline. These are release-pipeline artifacts to be sourced and pinned by
  digest before `pentestToolPack.enabled=true`.
- The identity-runtime `awsApiPort` / `taskPublicKeys` bindings are not
  committed defaults.
- The pentest tool-pack `--kubernetes-attach-v1` path has been exercised against
  a local kind cluster, not yet a managed cluster.
