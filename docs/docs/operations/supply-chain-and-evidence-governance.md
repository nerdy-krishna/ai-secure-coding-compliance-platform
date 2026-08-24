# Supply-chain and evidence governance

## KMS envelopes and rotation

Production evidence storage requires `EVIDENCE_KEY_PROVIDER=aws_kms`. Set
`EVIDENCE_KMS_KEY_ID` to the current encrypt/decrypt key and
`GOVERNANCE_SIGNING_KMS_KEY_ID` to an asymmetric `SIGN_VERIFY` key. The signing key may be the same
governed key used by Rule Foundry, but its IAM policy should name both purposes explicitly.

Rotate an envelope key without downtime:

1. Create the new KMS key or move the approved alias to it. Retain decrypt and `kms:ReEncryptFrom`
   rights on the old key; grant encrypt and `kms:ReEncryptTo` on the new key.
2. Deploy the new primary key identifier. New secrets and evidence immediately use it.
3. Verified reads lazily rewrap old DEKs with KMS `ReEncrypt`; payload ciphertext and object versions
   remain immutable. Governance audit contains hashes of the previous/current key identifiers, never
   the identifiers or key material.
4. Measure old-key metadata to zero, run a full restore verification, then remove old decrypt rights.

Local KEKs are accepted only in `development`. Staging, production, and private installations
require AWS KMS. Integration principals, LLM API keys, encrypted system settings, SSO provider
configuration, and provider-billing credentials use resource-scoped envelopes. A verified read of
a legacy Fernet value or previous-key envelope durably replaces it before returning plaintext to
the caller.

## Signed images, SBOM, and provenance

`.github/workflows/supply-chain-release.yml` builds API and worker images with pinned actions. It
scans each pushed image digest with Syft and normalizes that image-specific inventory to CycloneDX
without changing Syft's supported CycloneDX 1.5/1.6 schema label. The resulting API and worker SBOMs
therefore retain their different OS packages and runtimes.
The workflow also executes the scanner binaries in the exact image with networking disabled and
binds the observed Semgrep 1.95.0, Gitleaks 8.21.2, and worker-only OSV-Scanner 2.3.5 versions and
binary hashes into the predicate.

The Semgrep evidence hash is explicitly the resolved executable entrypoint, not a claim that one
file represents the complete Python environment. Its separate file component links back to Syft's
`pkg:pypi/semgrep@1.95.0` component. Syft inventories the image packages while the signed offline
bundle manifest independently binds every multi-file scanner runtime asset by path, size, and hash.
Existing Syft component references and dependency edges are preserved, and the normalizer retains
the CycloneDX version Syft emitted rather than relabeling an older document.

The generated SLSA v1 predicate truthfully identifies this repository's pinned GitHub Actions
workflow as its builder/build type. It is not a pre-wrapped in-toto Statement: `cosign attest`
constructs that envelope and digest-qualified subject. It is not an attestation from the official
SLSA GitHub generator and does not invent build start or finish timestamps. BuildKit's native
SBOM/provenance remain attached separately. Cosign signs the immutable image digest and predicates.

- Tag releases and normal manual releases use GitHub OIDC keyless signing.
- Private manual releases choose `private_kms`. Configure repository secret
  `SUPPLY_CHAIN_AWS_ROLE_ARN`, repository variables `SUPPLY_CHAIN_AWS_REGION` and
  `SUPPLY_CHAIN_AWS_ACCOUNT_ID`, and secret `COSIGN_KMS_URI=awskms://...`. The role trust policy must
  restrict GitHub's OIDC `sub` to this repository/workflow/ref and its permissions to the one signing
  key. The workflow checks the expected account and clears inherited AWS credentials. Do not create
  static AWS access-key secrets.
- Artifacts are retained 35 days to align with the approved backup window.

Pin the digest, exact certificate identity, and issuer when admitting a public release:

```bash
cosign verify \
  --certificate-identity \
  'https://github.com/OWNER/REPOSITORY/.github/workflows/supply-chain-release.yml@refs/tags/v1.2.3' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  'ghcr.io/OWNER/REPOSITORY/sccap-worker@sha256:FULL_DIGEST'

cosign verify-attestation --type cyclonedx \
  --certificate-identity \
  'https://github.com/OWNER/REPOSITORY/.github/workflows/supply-chain-release.yml@refs/tags/v1.2.3' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  'ghcr.io/OWNER/REPOSITORY/sccap-worker@sha256:FULL_DIGEST'
```

Use the same identity/issuer pair for `--type slsaprovenance`. Admission policy must encode those
exact values (for example, Kyverno `verifyImages[].attestors[].entries[].keyless.subject` and
`.issuer`), set `required: true`, and match digest-qualified SCCAP image references. Do not use a
repository-wide wildcard identity.

For private releases, export the KMS public key during a connected ceremony, record its canonical
KMS key ARN and SHA-256 of its DER SubjectPublicKeyInfo in the change record, then distribute the
PEM and fingerprint out of band. Private-cluster admission uses that pinned public key (for example,
`cosign verify --key /etc/sccap-trust/release.pem IMAGE@sha256:...` or a read-only ConfigMap key in
the admission controller). It must not call KMS or the network to verify a deployment.

## Restricted-egress bundle

Prepare scanner binaries named `semgrep`, `gitleaks`, and `osv-scanner`; a governed rules directory
containing Semgrep YAML and the Gitleaks TOML config; and an OSV directory containing
`snapshot.json` plus the bound `osv-scanner/<ecosystem>/all.zip` databases. The snapshot manifest
must bind every database by path, size, and SHA-256. Symlinks, missing semantics, unsafe paths,
oversized metadata, and mismatched content are rejected.

```bash
docker compose exec app python -m app.scripts.manage_offline_bundle build \
  --bundle /srv/staging/sccap-offline.tar --version 2026.08.24 \
  --scanners /srv/source/scanners --rules /srv/source/rules \
  --advisory /srv/source/advisory --source-date-epoch 1787500000

docker compose exec app python -m app.scripts.manage_offline_bundle verify \
  --bundle /srv/staging/sccap-offline.tar \
  --release-public-key /etc/sccap-trust/release.pem \
  --release-public-key-sha256 "$RELEASE_PUBLIC_KEY_SHA256" \
  --release-key-id "$RELEASE_KMS_KEY_ARN"

docker compose exec app python -m app.scripts.manage_offline_bundle activate \
  --bundle /srv/staging/sccap-offline.tar --install-root /var/lib/sccap/offline \
  --release-public-key /etc/sccap-trust/release.pem \
  --release-public-key-sha256 "$RELEASE_PUBLIC_KEY_SHA256" \
  --release-key-id "$RELEASE_KMS_KEY_ARN" \
  --deployment-signing-key /etc/sccap-trust/deployment-ed25519.pem \
  --deployment-public-key-sha256 "$DEPLOYMENT_PUBLIC_KEY_SHA256"
```

`build` is the only command that uses `GOVERNANCE_SIGNING_KMS_KEY_ID`. Verification, activation,
resolution, and rollback verify the release with the out-of-band pinned public key and require no
network or KMS call. Generate a separate operator-controlled Ed25519 deployment key in the restricted
environment. It signs the canonical hash-chained `deployment-state.json` ledger; keep its private key
read-only to the deployment operator and pin/distribute its public-key fingerprint separately.
The deployment private key must be a regular, owner-only (`0600`) file owned by the activation
process; symlinks and group/other permissions are rejected.

Activation verifies the archive, streams extraction into an immutable digest directory, removes
owner write bits from every installed file and directory, verifies the installed bytes and modes
again, signs the new ledger state, and atomically switches `current`. This also satisfies the OSV
offline loader's read-only snapshot requirement. Rollback verifies
the current signed ledger and both current/target signed releases before changing state. A tampered
payload, signature, state, history chain, or pointer fails closed. If post-change smoke tests fail:

```bash
docker compose exec app python -m app.scripts.manage_offline_bundle rollback \
  --install-root /var/lib/sccap/offline \
  --release-public-key /etc/sccap-trust/release.pem \
  --release-public-key-sha256 "$RELEASE_PUBLIC_KEY_SHA256" \
  --release-key-id "$RELEASE_KMS_KEY_ARN" \
  --deployment-signing-key /etc/sccap-trust/deployment-ed25519.pem \
  --deployment-public-key-sha256 "$DEPLOYMENT_PUBLIC_KEY_SHA256"
```

To make the worker consume the activated release, set `SCCAP_OFFLINE_INSTALL_ROOT` plus
`OFFLINE_BUNDLE_RELEASE_PUBLIC_KEY`, `OFFLINE_BUNDLE_RELEASE_PUBLIC_KEY_SHA256`,
`OFFLINE_BUNDLE_RELEASE_KEY_ID`, `OFFLINE_BUNDLE_DEPLOYMENT_PUBLIC_KEY`, and
`OFFLINE_BUNDLE_DEPLOYMENT_PUBLIC_KEY_SHA256`. Worker startup then verifies signed state and every
installed byte before setting exact Semgrep/Gitleaks/OSV binary, rule/config, and advisory paths.
Any missing trust input or mismatch aborts worker startup. When `SCCAP_OFFLINE_INSTALL_ROOT` is
unset, the ordinary image scanner configuration is unchanged. The signed file ledger is the
authoritative offline deployment audit record; no database connectivity is required for it.

Use separate deployment and worker identities. The deployment identity alone receives write access
to the offline volume and the Ed25519 private key. Workers mount the activated tree and both public
keys read-only; they must never mount the deployment private key. The following Compose override is
a concrete contract (replace the images, paths, IDs, and secret delivery with deployment-owned
values):

```yaml
services:
  offline-bundle-manager:
    image: registry.example/sccap-worker@sha256:PINNED_DIGEST
    profiles: [offline-admin]
    user: "12001:12001"                 # dedicated deployment identity
    network_mode: none
    security_opt: ["no-new-privileges:true"]
    environment:
      # Deployment-owned assertion; activation also verifies only `lo` exists.
      SCCAP_OFFLINE_ACTIVATION_NETWORK_ISOLATION: compose_network_none
    volumes:
      - sccap-offline:/var/lib/sccap/offline:rw
      - /etc/sccap/release.pem:/run/sccap/release.pem:ro
      - /etc/sccap/deployment-ed25519.pem:/run/sccap/deployment.pem:ro
    # Run manage_offline_bundle activate/rollback explicitly; no long-running command.

  worker:
    volumes:
      - sccap-offline:/var/lib/sccap/offline:ro
      - /etc/sccap/release.pem:/run/sccap/release.pem:ro
      - /etc/sccap/deployment-ed25519.pub:/run/sccap/deployment.pub:ro
    environment:
      SCCAP_OFFLINE_INSTALL_ROOT: /var/lib/sccap/offline
      OFFLINE_BUNDLE_RELEASE_PUBLIC_KEY: /run/sccap/release.pem
      OFFLINE_BUNDLE_RELEASE_PUBLIC_KEY_SHA256: ${RELEASE_PUBLIC_KEY_SHA256}
      OFFLINE_BUNDLE_RELEASE_KEY_ID: ${RELEASE_KMS_KEY_ARN}
      OFFLINE_BUNDLE_DEPLOYMENT_PUBLIC_KEY: /run/sccap/deployment.pub
      OFFLINE_BUNDLE_DEPLOYMENT_PUBLIC_KEY_SHA256: ${DEPLOYMENT_PUBLIC_KEY_SHA256}

volumes:
  sccap-offline:
```

Activation performs bounded version smoke checks directly inside the manager's existing isolated
network namespace. It requires the deployment-owned
`SCCAP_OFFLINE_ACTIVATION_NETWORK_ISOLATION=compose_network_none` marker and verifies `/sys/class/net`
contains only loopback before executing any scanner. The marker is not the security boundary;
Compose `network_mode: none` is. A marker in a normally networked container is rejected. This avoids
`CAP_SYS_ADMIN` and privileged namespace creation. The worker never performs activation and requires
only read access.

## Retention, legal hold, export, and deletion

The approved default snapshot is:

| Class | Days |
|---|---:|
| Transactional and audit | 365 |
| Encrypted evidence objects | 365 |
| LLM interactions | 30 |
| Vector content | 365 |
| Loki/Langfuse logs and traces | 30 |
| Backups and release predicates | 35 |

`GovernanceService` is the only completion authority for cross-store export/deletion. It creates a
durable operation and exactly four actions (`postgres`, `object`, `qdrant`, `observability`). A legal
hold is rechecked at preparation and immediately before execution. The legacy evidence-object hold
flag is synchronized from tenant/project/scan/attempt/evidence holds so the existing object sweeper
cannot race a broader hold.

A completed export contains `artifact_kind=evidence_export_manifest`; a completed deletion contains
`artifact_kind=evidence_deletion_tombstone`. Both include the exact policy snapshot and verified
result digest for all four stores, then receive a KMS signature. An unavailable store leaves the
operation recoverable or terminally failed after bounded attempts; it never produces a signed
completion.

Prepare and execute one operation, or resume expired/failed leases after a worker crash:

```bash
docker compose exec app python -m app.scripts.run_governance_operation \
  --tenant-id TENANT_UUID prepare --kind export --scope-type tenant \
  --scope-id TENANT_UUID --actor-user-id 42 --reason 'regulated export' --execute

docker compose exec app python -m app.scripts.run_governance_operation \
  --tenant-id TENANT_UUID run-pending --limit 50
```

Tenant retention overrides are persisted and immediately rematerialize applicable evidence/LLM
expiry timestamps. Only privacy-short-lived LLM and log classes may be shorter than the approved
default; evidence, vector, and backup classes may only be lengthened. Transactional and audit
tenant overrides are rejected until durable tenant-aware sweepers exist for those classes. The
ordinary database/evidence sweepers exclude active ancestor and descendant-overlap holds. Run bounded
Qdrant, observability/log, and tenant-backup enforcement with signed evidence using:

```bash
docker compose exec app python -m app.scripts.enforce_governance_retention \
  --tenant-id TENANT_UUID --operation-id OPERATOR_GENERATED_UUID
```

Configure `GOVERNANCE_OBSERVABILITY_URL`, its bearer token, `GOVERNANCE_ARTIFACT_ROOT`, and a
tenant-partitioned `GOVERNANCE_BACKUP_ROOT`. Every destructive path holds the same per-tenant
database barrier as legal-hold placement; a hold either wins before external deletion or waits for
the bounded action and its signed evidence to commit. Reuse the same operation UUID after a crash;
the executor replays its durable pre-deletion plans and the observability idempotency key so the
signed report retains the original matched/deleted counts.

## Isolated restore verification

Before backup, create a private host directory and a named Qdrant snapshot for every collection.
Generate the signed expected inventory from the live source. Snapshot names are explicit: the
generator never guesses a latest snapshot. Preserve `expected/` alongside, but outside, the backup
being tested. The bind mount is necessary because the ordinary `app` container has no writable
`/var/lib/sccap/restore` mount.

```bash
RESTORE_EVIDENCE_HOST_DIR="$PWD/.scratch/restore-evidence"
install -d -m 0700 "$RESTORE_EVIDENCE_HOST_DIR/expected"
install -d -m 0700 "$RESTORE_EVIDENCE_HOST_DIR/restored-governance"
export RESTORE_EVIDENCE_HOST_DIR
: "${GOVERNANCE_SIGNING_KMS_KEY_ID:?set the governance KMS key ID}"
: "${GOVERNANCE_SIGNING_KMS_REGION:?set the governance KMS region}"

docker compose run --rm --no-deps \
  --user "$(id -u):$(id -g)" \
  --volume "$RESTORE_EVIDENCE_HOST_DIR/expected:/var/lib/sccap/restore-expected" \
  --env GOVERNANCE_SIGNING_KMS_KEY_ID="$GOVERNANCE_SIGNING_KMS_KEY_ID" \
  --env GOVERNANCE_SIGNING_KMS_REGION="$GOVERNANCE_SIGNING_KMS_REGION" \
  app python -m app.scripts.generate_qdrant_restore_artifact \
  --snapshot security_guidelines=PREBACKUP_SNAPSHOT_NAME \
  --snapshot cwe=PREBACKUP_SNAPSHOT_NAME \
  --output /var/lib/sccap/restore-expected/qdrant-restore.json
```

Restore PostgreSQL, object versions, those Qdrant snapshots, and observability/config backups into
an isolated network. Seed the drill before backup with a decided scan gate and pending outbox row, a
resumable production checkpoint, evidence for at least two tenants, and a completed four-store
governance operation. Generate the expected observability SHA-256 independently from the source
export, not from the restored service.

After restoring, copy the restored governance artifact tree into
`$RESTORE_EVIDENCE_HOST_DIR/restored-governance` without modifying `expected/`. This must be a copy
inside the isolated drill: convergence can append recovered-operation artifacts to it. It must not
point at production evidence or the preserved source expectations. Set every recovery input in the
operator shell. `RESTORE_CHECKPOINT_DSN` must name a non-owner PostgreSQL role with `NOSUPERUSER
NOBYPASSRLS`. The same KMS key verifies source artifacts and signs recovery receipts/reports. Shell
exports alone are not inherited by an already-running container; every variable is therefore
passed explicitly to the processes below.

```bash
RESTORE_CHECKPOINT_DSN=postgresql://restore_runtime:...@db/sccap
RESTORE_QDRANT_ARTIFACT=/var/lib/sccap/restore-expected/qdrant-restore.json
RESTORE_EXPECTED_OBSERVABILITY_SHA256=64_LOWERCASE_HEX
RESTORE_OUTBOX_RECEIPT_URL=http://127.0.0.1:8765/v1/restore/outbox-receipts
RESTORE_CHECKPOINT_RESUME_URL=http://127.0.0.1:8765/v1/restore/checkpoint-resume
RESTORE_PROBE_BEARER_TOKEN=HIGH_ENTROPY_ONE_DRILL_SECRET
RESTORE_ALLOW_LOOPBACK_HTTP=true
RESTORE_PROBE_EFFECT_TIMEOUT_SECONDS=300
RESTORE_PROBE_RESUME_TIMEOUT_SECONDS=1800
GOVERNANCE_ARTIFACT_ROOT=/var/lib/sccap/restored-governance
GOVERNANCE_OBSERVABILITY_URL=https://restored-observability.internal
GOVERNANCE_OBSERVABILITY_BEARER_TOKEN=RESTORED_SERVICE_TOKEN
GOVERNANCE_SIGNING_KMS_KEY_ID=KMS_KEY_ID
GOVERNANCE_SIGNING_KMS_REGION=us-east-1
export RESTORE_CHECKPOINT_DSN RESTORE_QDRANT_ARTIFACT RESTORE_EXPECTED_OBSERVABILITY_SHA256
export RESTORE_OUTBOX_RECEIPT_URL RESTORE_CHECKPOINT_RESUME_URL RESTORE_PROBE_BEARER_TOKEN
export RESTORE_ALLOW_LOOPBACK_HTTP RESTORE_PROBE_EFFECT_TIMEOUT_SECONDS
export RESTORE_PROBE_RESUME_TIMEOUT_SECONDS GOVERNANCE_ARTIFACT_ROOT
export GOVERNANCE_OBSERVABILITY_URL GOVERNANCE_OBSERVABILITY_BEARER_TOKEN
export GOVERNANCE_SIGNING_KMS_KEY_ID GOVERNANCE_SIGNING_KMS_REGION
```

Create one disposable operator container so the gateway and verifier share the same mounted files
and loopback namespace. The restored database, RabbitMQ, Qdrant, object store, and observability
services must already be running on the isolated Compose network. The preserved expected inventory
is mounted read-only. The isolated restored-governance copy is a separate writable mount because
recovery of incomplete operations durably appends artifacts there. The disposable processes use
the invoking operator's numeric UID/GID so the `0700` host directories remain private and writable
without broadening their modes.

```bash
docker compose run --detach --rm --no-deps \
  --name sccap-restore-operator \
  --user "$(id -u):$(id -g)" \
  --volume "$RESTORE_EVIDENCE_HOST_DIR/expected:/var/lib/sccap/restore-expected:ro" \
  --volume "$RESTORE_EVIDENCE_HOST_DIR/restored-governance:/var/lib/sccap/restored-governance:rw" \
  app sleep infinity

cleanup_restore_operator() {
  docker stop sccap-restore-operator >/dev/null 2>&1 || true
  if [ -n "${RESTORE_GATEWAY_EXEC_PID:-}" ]; then
    wait "$RESTORE_GATEWAY_EXEC_PID" 2>/dev/null || true
  fi
}
trap cleanup_restore_operator EXIT INT TERM
```

From the same operator shell, launch the gateway as a background `docker exec` process. Its output
goes to the private evidence directory. Bind it only to exact loopback; never publish this
privileged system-principal service on a container, host, or cluster interface. HTTP is accepted
only with the explicit loopback opt-in above. Use TLS for any non-loopback deployment.

```bash
docker exec \
  --env RESTORE_PROBE_BEARER_TOKEN="$RESTORE_PROBE_BEARER_TOKEN" \
  --env RESTORE_PROBE_EFFECT_TIMEOUT_SECONDS="$RESTORE_PROBE_EFFECT_TIMEOUT_SECONDS" \
  --env RESTORE_PROBE_RESUME_TIMEOUT_SECONDS="$RESTORE_PROBE_RESUME_TIMEOUT_SECONDS" \
  --env GOVERNANCE_SIGNING_KMS_KEY_ID="$GOVERNANCE_SIGNING_KMS_KEY_ID" \
  --env GOVERNANCE_SIGNING_KMS_REGION="$GOVERNANCE_SIGNING_KMS_REGION" \
  sccap-restore-operator uvicorn app.scripts.restore_recovery_gateway:app \
  --host 127.0.0.1 --port 8765 \
  >"$RESTORE_EVIDENCE_HOST_DIR/gateway.log" 2>&1 &
RESTORE_GATEWAY_EXEC_PID=$!

for attempt in 1 2 3 4 5; do
  docker exec sccap-restore-operator python -c \
    'import socket; socket.create_connection(("127.0.0.1", 8765), timeout=1).close()' \
    && break
  if [ "$attempt" -eq 5 ]; then
    cat "$RESTORE_EVIDENCE_HOST_DIR/gateway.log"
    exit 1
  fi
  sleep 1
done
```

Run the verifier with every recovery input passed explicitly. Stop and remove the disposable
container after success or failure; the trap also handles an interrupted shell and terminates the
gateway.

```bash
docker exec \
  --env RESTORE_CHECKPOINT_DSN="$RESTORE_CHECKPOINT_DSN" \
  --env RESTORE_QDRANT_ARTIFACT="$RESTORE_QDRANT_ARTIFACT" \
  --env RESTORE_EXPECTED_OBSERVABILITY_SHA256="$RESTORE_EXPECTED_OBSERVABILITY_SHA256" \
  --env RESTORE_OUTBOX_RECEIPT_URL="$RESTORE_OUTBOX_RECEIPT_URL" \
  --env RESTORE_CHECKPOINT_RESUME_URL="$RESTORE_CHECKPOINT_RESUME_URL" \
  --env RESTORE_PROBE_BEARER_TOKEN="$RESTORE_PROBE_BEARER_TOKEN" \
  --env RESTORE_ALLOW_LOOPBACK_HTTP="$RESTORE_ALLOW_LOOPBACK_HTTP" \
  --env RESTORE_PROBE_EFFECT_TIMEOUT_SECONDS="$RESTORE_PROBE_EFFECT_TIMEOUT_SECONDS" \
  --env RESTORE_PROBE_RESUME_TIMEOUT_SECONDS="$RESTORE_PROBE_RESUME_TIMEOUT_SECONDS" \
  --env GOVERNANCE_ARTIFACT_ROOT="$GOVERNANCE_ARTIFACT_ROOT" \
  --env GOVERNANCE_OBSERVABILITY_URL="$GOVERNANCE_OBSERVABILITY_URL" \
  --env GOVERNANCE_OBSERVABILITY_BEARER_TOKEN="$GOVERNANCE_OBSERVABILITY_BEARER_TOKEN" \
  --env GOVERNANCE_SIGNING_KMS_KEY_ID="$GOVERNANCE_SIGNING_KMS_KEY_ID" \
  --env GOVERNANCE_SIGNING_KMS_REGION="$GOVERNANCE_SIGNING_KMS_REGION" \
  sccap-restore-operator python -m app.scripts.verify_governance_restore

cleanup_restore_operator
trap - EXIT INT TERM
```

The command emits one canonical signed JSON report and exits `0` only when all checks pass. It
switches transaction-local principal context, proves same-tenant writes and cross-tenant write
denial, drains the complete outbox (not merely a sample), resumes through the production worker and
checkpointer, then independently re-reads durable gate/outbox/checkpoint identity. Recovery receipts
are nonce-bound and KMS-signed. It also verifies every evidence manifest/object/ciphertext byte,
strict four-store governance convergence and post-recovery signatures, the exact signed Qdrant
inventory, and the independently pinned observability digest. `--max-evidence-objects` is permitted
only for routine drills; final recovery acceptance must use the default full verification.
