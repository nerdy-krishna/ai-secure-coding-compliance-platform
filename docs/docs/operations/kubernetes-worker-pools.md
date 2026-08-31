# Kubernetes worker pools

SCCAP production supports Kubernetes 1.30+ through the versioned Helm chart at
`deploy/helm/sccap`. Docker Compose remains the supported development and
single-node evaluation target.

## Prerequisites

- Kubernetes 1.30 or newer and Helm 3.
- PostgreSQL 16, RabbitMQ 3.12+, Qdrant, and the private evidence object store.
- KEDA CRDs when `autoscaling.keda.enabled=true`.
- Prometheus Operator CRDs when `monitoring.prometheusRule.enabled=true`.
- RabbitMQ Prometheus detailed metrics enabled for
  `rabbitmq_detailed_queue_head_message_timestamp`.
- Separately managed core Secrets named by `runtime.apiSecret`,
  `scannerSecret`, `llmSecret`, `reportSecret`, `unifiedSecret`, and
  `migrationSecret`. Enabled Pentesting components also require their own
  `runnerV3Secret`, `pentestControllerSecret`, `pentestToolWorkerSecret`,
  `pentestVerificationSecret`, and `pentestSessionBrokerSecret`. Never put
  secret values in Helm values or reuse a broader Secret for a
  least-privilege pool.

Put non-secret connection names, ports, queue names, feature flags, and public
URLs in `runtime.existingConfigMap`. Secret projections are:

| Secret | Required secret classes | Explicitly excluded |
| --- | --- | --- |
| API | DB/Rabbit credentials, `SECRET_KEY`, `ENCRYPTION_KEY`, API-side evidence/KMS and configured SMTP/integration credentials | worker-only scanner/runtime credentials |
| scanner | DB/Rabbit credentials and settings-required SCCAP keys; scanner/advisory credentials only when configured | LLM/provider, SMTP, integration delivery credentials |
| LLM | DB/Rabbit credentials, settings-required SCCAP keys, provider-config decryption and evidence/KMS credentials | SMTP and scanner-source credentials |
| report | DB/Rabbit credentials, settings-required SCCAP keys, evidence/KMS credentials | LLM/provider, SMTP, scanner-source credentials |
| unified | union required by all worker workloads; use only for compatibility/bridge | API-only SMTP/integration credentials |
| migration | `ALEMBIC_DATABASE_URL` only | RabbitMQ, auth, provider, evidence, SMTP, integration credentials |
| Pentesting runner V3 | only its execution queue, gateway authentication and required runtime configuration | controller, tool-worker, identity, broker, KMS and verifier authority |
| Pentesting controller | its database, bounded controller queue and optional configured controller model reference | target, adapter, identity-runtime, broker, KMS and verifier-queue authority |
| Pentesting tool worker | its tool queue, gateway token, task-verification keys and result-signing seed | database, identity secret material, Session Broker database role, STS and verifier-queue authority |
| Pentesting verification | C6 database role, `pentest_verification_queue_v1` credential and locator-verification keys | API auth, target routes, evidence-store credentials, identity secrets, broker, KMS and model authority |
| Pentesting Session Broker | its narrow C7 database role only; TLS keys, projected TokenReview/STS tokens and pinned trust bundles use dedicated mounts | API/user auth, general queue, target, finding, severity, coverage and verifier authority |

LLM provider keys are normally encrypted database configuration and therefore
do not belong in any pod environment. If a deployment adds an environment-only
provider credential, project it only into the LLM and unified Secrets. Missing
required settings fail pod startup; do not solve that by sharing a superset
Secret.

The identity-runtime Pod does not use a release-wide runtime Secret. Its
one-Execution A16 private key is generated in process, and its bounded service
account tokens are explicit read-only projected volumes. The Session Broker,
not the identity Pod, owns the single STS exchange. Identity-aware Pentesting
components remain disabled until the complete Capability 6/7 qualification
matrix passes.

Render and validate before each release:

```bash
helm lint deploy/helm/sccap
helm template sccap deploy/helm/sccap --namespace sccap > /tmp/sccap.yaml
kubectl apply --dry-run=server -f /tmp/sccap.yaml
```

Install with an immutable application tag; the schema rejects `latest`:

```bash
helm upgrade --install sccap deploy/helm/sccap \
  --namespace sccap --create-namespace \
  --set images.api.repository=registry.example/sccap-api \
  --set images.api.tag=1.0.0 \
  --set images.worker.repository=registry.example/sccap-worker \
  --set images.worker.tag=1.0.0
```

The migration hook runs `alembic upgrade head` before API/worker rollout. The
deployments override the image entrypoint, so ordinary pods never race schema
migrations.

Build and publish the Dockerfile's `api` and `worker` targets under the two
immutable image references. The API image stays lean; scanner libraries and
binaries live only in the worker image used by every worker pool.

The chart creates component-scoped NetworkPolicies. Workers accept no ingress;
API ingress is limited to the configured ingress-controller namespace plus
same-namespace probes; the collector accepts OTLP only from SCCAP namespace
pods. Egress defaults to same-namespace services, DNS, and HTTPS for components
that need external endpoints. Add managed database/broker/vector/object-store
CIDRs and exact ports under `networkPolicy.externalInfrastructure`; the chart
does not grant unrestricted cross-namespace egress.

## Pool contract

| Pool | Queue | Default min/max | Prefetch | Work profile |
| --- | --- | --- | --- | --- |
| scanner | `code_submission_queue` | 1/20 | 1 | CPU, memory, ephemeral workspace |
| LLM | `analysis_approved_queue` | 1/50 | 3 | provider latency, DB connections |
| report | `report_export_queue` | 1/10 | 2 | CPU/memory/export workspace |
| unified | all three | 1 fixed | 5 | compatibility/bridge |

Unified compatibility also retains a three-workflow ceiling and serializes
submission workflows. Split pool prefetch is explicit and does not change that
default.

KEDA uses both queue length and oldest-message age. Age is calculated from the
RabbitMQ queue-head timestamp, returning zero for an empty queue. Scale-down
has a 60-second stabilization window and removes at most 25% of replicas per
minute. Minimum replicas remain one so an unavailable metrics backend cannot
scale a pool to zero.

## Durable report handoff

Split scanner-started workflows set a state flag. After `save_results`,
`report_handoff` inserts exactly one `report-handoff:<attempt-id>` outbox row
and parks its internal checkpoint. The outbox sweeper publishes it. A report or
unified worker compares the durable tenant, scan, attempt, outbox, node,
interrupt, and checkpoint identity before issuing `Command(resume=...)`.

If delivery precedes checkpoint visibility, the worker waits for a bounded
interval and rejects the message for redelivery without marking the scan
failed. A crash before ACK similarly leaves work for redelivery. Duplicate
node execution observes the original outbox row. This handoff never appears as
a user approval and cannot be driven through an approval API.

Old states without the split flag execute `save_results -> report_handoff
(no-op) -> save_final_report`; this is the straight-through N-1 path.

## Drain and disruption

Every worker pod has a 600-second termination grace period. `preStop` writes a
private drain marker and waits up to 570 seconds. The consumer stops new
deliveries first, finishes active work when possible, then cancels remaining
tasks so the RabbitMQ connection closes with those deliveries unacknowledged.
LangGraph checkpoints and the outbox remain authoritative.

Request and wait for an explicit drain:

```bash
kubectl -n sccap exec deploy/sccap-sccap-worker-llm -- \
  python -m app.workers.drain --wait --timeout 570
```

Pod disruption budgets retain at least one API, pool, and collector replica.
Rolling updates use `maxUnavailable: 0`, topology spreading, and bounded scale
down. Do not force-delete a worker unless the broker connection has closed or
you accept waiting for RabbitMQ consumer recovery.

## N-1 rollout and rollback

Roll forward in this order:

1. Back up PostgreSQL and verify outbox/checkpointer health.
2. Run the chart's expand/schema-first migration hook. Migrations must remain
   readable by N-1 code until a later contract release.
3. Deploy at least one **current-version unified** worker. It is the bridge for
   both old straight-through messages and new report handoffs.
4. Deploy current API and split pools; watch unpublished outbox rows, all queue
   depths/ages, and terminal success.
5. Drain N-1 workers. Keep the unified bridge until every N-1 in-flight thread
   and report handoff is complete.
6. Contract old schema only in a later release after the N-1 window closes.

Rollback in this order:

1. Stop new current-version scanner deliveries and restore a current-version
   unified bridge if none is running.
2. Drain split scanner/LLM pods. Let the report pool or bridge finish every
   `report_export_queue` delivery and every parked `report_handoff` checkpoint.
3. Verify all three queues, unpublished outbox intents, and active current
   workflow checkpoints are empty/stable.
4. Roll API and ordinary workers back to N-1.

Never run `alembic downgrade`, purge a queue, delete checkpointer rows, or mark
an outbox row published by hand. If a full rollback cannot meet step 3, keep
the current unified bridge alongside the N-1 API until it drains current work.
