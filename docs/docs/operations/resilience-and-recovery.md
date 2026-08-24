# Resilience, capacity, and recovery proof

Task 24 is a release-evidence gate, not a claim that a unit test proves production
capacity. The repository provides deterministic workload archives, a complete
failure/recovery contract, and a fail-closed evidence validator. Operators must
run the cluster exercises against declared production sizing and retain the raw
metrics, traces, Kubernetes events, backup timestamps, and governance manifests.
Do not mark a field `true` without a durable evidence reference.

## What is proved where

| Evidence | Deterministic repository check | External exercise required |
| --- | --- | --- |
| Exact workload sizes and matrix | fixture generator and contract tests | upload/run all profiles at production sizing |
| SLO arithmetic and thresholds | evidence validator | Prometheus/trace samples from the run |
| Queue/storage bounds, OOM, fairness | evidence validator | broker, storage, pod, and per-tenant progress observations |
| Failure behavior | required scenario catalog | controlled dependency/node/network injection |
| RPO/RTO | threshold validator | timestamped backup, failover, and restore exercise |
| RLS, digest, outbox, coverage, resume | required recovery checks | isolated Task 22 restore and probes |

Repository tests are contract evidence only. They are not load, chaos, backup,
or disaster-recovery results. A release has no Task 24 capacity or DR proof until
`validate_evidence` accepts externally collected evidence.

## Approved workload and targets

Run every deterministic profile at 1, 10, and 50 concurrent tenants:

| Profile | Files per tenant | Uncompressed source per tenant |
| --- | ---: | ---: |
| small | 100 | 5 MiB |
| representative | 2,000 | 100 MiB |
| maximum | 5,000 | 200 MiB |

The representative 10-tenant run must meet the Task 21 objectives: accepted
submission/outbox persistence p95 below 2 seconds, queue-to-start p95 below 5
minutes, approval resume p95 below 60 seconds, SSE freshness p95 below 5 seconds,
and at least 99% terminal success after excluding policy/user blocks.

Every maximum-profile run must have zero process and pod OOM kills; queue peak
must remain below the declared broker bound and return to its pre-run depth after
drain; storage growth must remain below the predeclared budget; every tenant must
make progress; and the Jain fairness index over tenant progress must be at least
0.90. The 50-tenant run is the declared saturation case. These are release gates,
not recommended sizing numbers. Record the exact
Helm values, node types, replica limits, DB/broker/object/vector sizing, immutable
image digests, chart version, and Git commit in every run.

Use deterministic scanner and provider fixtures for the nine repeatable capacity
runs. Run a separate live-provider smoke with a positive dollar cap, provider
rate-limit agreement, and the actual usage-ledger cost. Never route 50-tenant
maximum traffic to a live provider merely to satisfy the fixture matrix.

## Generate fixtures

Run the generator inside the API image so source limits and Python behavior match
the deployed release. The output is deterministic, valid comment-only Python,
ZIP_STORED, and contains the exact uncompressed bytes in the table.

```bash
mkdir -p /absolute/private/resilience-evidence
docker compose run --rm --no-deps \
  --entrypoint python \
  -v /absolute/private/resilience-evidence:/private-evidence \
  app \
  /app/scripts/resilience/generate_workload.py representative \
  /private-evidence/representative.zip \
  --manifest /private-evidence/representative.manifest.json
```

Generate `small.zip`, `representative.zip`, and `maximum.zip` once per release.
Store them in a private, access-logged evidence location. The generator refuses
an implicit overwrite; `--force` is only for an intentional fixture replacement.
Verify the manifest file count, uncompressed byte count, archive digest, and
content-stream digest before the run.

The generic repository does not provision tenant credentials or auto-approve
security gates. The environment's load driver must use one least-privilege
`scan:submit`/self-approval/read principal per tenant and exercise the public API:

1. submit the archive to `POST /api/v1/scans` and time through the successful
   response plus durable outbox observation;
2. consume SSE through a scan-bound stream token and retain freshness samples;
3. approve each of the prescan, profiling, and analysis gates with its returned
   gate ID, version, evidence hash, and a unique idempotency key;
4. redeliver a measured subset of outbox/queue events and prove no duplicate
   effect;
5. download at least one result/report/scanner-evidence artifact per tenant and
   verify its persisted digest;
6. drain queues and record final depth/storage as well as per-tenant completed
   progress units.

Never put bearer tokens, source, prompts, responses, or object-store credentials
in load-tool output. Use opaque tenant/run IDs and the Task 21 metadata-only OTel
allowlist. Approval latency is derived from the durable approval request timestamp
to the first resumed workflow event; it must not be guessed from client wall time.

## Capacity evidence collection

Capture raw observations, not screenshots alone:

- `sccap.api.accepted_submission.duration`, `sccap.queue.to_start`,
  `sccap.sse.freshness`, and `sccap.workflow.terminal` samples;
- approval request and resumed-event timestamps joined by tenant, scan, attempt,
  and gate identity;
- RabbitMQ depth, queue-head age, declared max length, rejected publishes, ACKed
  deliveries, and redeliveries for all three queues;
- KEDA desired/ready replicas, pod restarts/reasons, container working-set/limit,
  node memory pressure, and termination events;
- PostgreSQL connections/latency/storage, evidence-object bytes/versions, Qdrant
  collection bytes/points, and ephemeral workspace high-water marks;
- each tenant's completed workflow units over the same saturation interval;
- report/evidence download counts and digest-verification outcomes.

Calculate percentiles from the raw interval samples using nearest rank. Preserve
the query text, time window, scrape interval, and raw export under each run's
`evidence_ref`. Declare queue capacity and storage-growth budget before starting;
raising either after the observation invalidates the run.

## Failure matrix

Use `deploy/resilience/scenario-catalog.json` as the machine-readable inventory.
Execute every scenario in an isolated production-like namespace:

- PostgreSQL failover;
- RabbitMQ restart/redelivery;
- object-store outage and independently corrupted object version;
- Qdrant outage;
- scanner timeout and process crash;
- provider 429, 5xx, and timeout;
- worker/node termination separately at prescan, profiling, and analysis gates;
- a network partition affecting an external dependency.

The environment owner chooses provider-specific failover and fault-injection
commands. Keep those reviewed commands with the evidence; this repository does
not ship a universal destructive script. Before injection, resolve exact
namespace, cluster, workload, database, bucket/version, and network-policy
targets. Never run against production or a shared backup destination.

Each failure record must link the injection event and record the catalog's
expected degradation, what was observed, recovery, and explicit booleans proving:
authorization remained enforced, duplicate delivery had no duplicate effect,
durable work survived, and coverage/status exposed degradation. A dependency
error that becomes a clean result is a failed exercise.

Follow `dependency-degradation.md` during the exercise. In particular, never
purge queues, edit published flags, delete checkpoints, downgrade schema, use a
stale PostgreSQL replica, substitute another tenant's Qdrant collection, or
bypass evidence digest verification.

## Backup and isolated restore

The recovery objectives are:

| State/service | RPO | RTO |
| --- | ---: | ---: |
| PostgreSQL, LangGraph checkpoints, connector/policy/configuration | 5 min | API and scan resumption within 60 min |
| evidence objects and Qdrant vectors | 15 min | analytics and search within 4 h |
| acknowledged RabbitMQ messages | zero loss | included in scan resumption |

Measure RPO from the last transaction/object/vector acknowledged before the
failure to the newest item present after restore. Measure RTO from the declared
incident timestamp, not from when an operator began the restore.

Restore into a new network-isolated environment with separate credentials, DNS,
KMS grants, bucket prefix, Qdrant collections, and observability index. Do not
expose API ingress yet. Restore PostgreSQL and checkpoints together, exact
evidence object versions, evidence key metadata, Qdrant snapshots, connector and
policy configuration, and the bounded trace context needed for incident
correlation. Restore broker state or replay the database outbox according to the
platform backup design; acknowledged messages may not disappear.

Task 22 is the integrity authority. Run its verifier before any exposure:

```bash
docker compose exec app \
  python -m app.scripts.verify_governance_restore
```

The completed governance artifact must have schema version 1, a signed
`evidence_export_manifest` (or deletion tombstone when testing deletion), tenant
and policy scope, PostgreSQL/object/Qdrant/observability store results and their
SHA-256 values, a canonical manifest SHA-256, and a valid KMS signature. Retain
the command output under the recovery evidence reference; do not copy a success
boolean from another operation.

Before opening ingress, execute and retain all recovery probes required by the
evidence schema:

1. runtime DB role has no `BYPASSRLS`; same-tenant access succeeds and a
   cross-tenant probe is denied;
2. ciphertext and plaintext artifact digests match the signed manifest;
3. unpublished outbox rows converge to zero after dependencies recover, while
   unique side effects remain one;
4. scanner coverage remains degraded for any unavailable/corrupt source and
   becomes verified only after genuine verification;
5. each pre-failure scan resumes with the same tenant, scan, attempt, checkpoint,
   outbox, node, and gate identities; no accepted gate is requested twice;
6. connector/policy configuration, evidence versions/keys, Qdrant collections,
   and observability correlation are present and tenant scoped;
7. a canary completes deterministic scan, approval/provider, report, SSE, and
   digest-verified download paths.

## Validate and archive the release gate

Print the versioned evidence JSON Schema:

```bash
docker compose run --rm --no-deps \
  --entrypoint python \
  app \
  /app/scripts/resilience/validate_evidence.py --schema \
  > /absolute/private/resilience-evidence/resilience-evidence.schema.json
```

Validate collected evidence:

```bash
docker compose run --rm --no-deps \
  --entrypoint python \
  -v /absolute/private/resilience-evidence:/private-evidence:ro \
  app \
  /app/scripts/resilience/validate_evidence.py \
  /private-evidence/resilience-evidence.json
```

Exit `0` means the approved contract passed, `1` means measured evidence breached
one or more targets, and `2` means the document did not satisfy the schema. The
validator requires all nine deterministic runs, a budget-capped live smoke, all
failure scenarios, exact recovery checks with evidence references, and RPO/RTO
measurements. Archive the input JSON, validator output, schema, raw observations,
fixtures/manifests, immutable deployment identity, and signed Task 22 manifest
together. A later release, chart, image, production sizing, or recovery design
requires a new evidence suite.
