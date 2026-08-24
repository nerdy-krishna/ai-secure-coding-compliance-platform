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
default; regulated evidence, audit, transactional, vector, and backup classes may only be
lengthened. The ordinary database/evidence sweepers exclude active ancestor holds. Run bounded
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

Restore PostgreSQL, object versions, Qdrant snapshots, and observability/config backups into an
isolated network. Use the non-owner, `NOSUPERUSER NOBYPASSRLS` runtime DSN, then run:

```bash
docker compose exec app python -m app.scripts.verify_governance_restore
```

The command emits one canonical signed JSON report and exits `0` only when all checks pass. It must
observe at least two restored tenants: the verifier switches transaction-local principal context to
tenant A, confirms same-tenant visibility, and confirms an explicit tenant-B query returns zero.
It dynamically verifies forced RLS on every table with a `tenant_id`, authenticates all persisted
application-secret classes, validates outbox references and meaningful checkpoint payloads,
evidence manifest chains/object bytes, strict four-store governance convergence, Qdrant snapshot
availability, observability restore digests, and every completed governance signature.
`--max-evidence-objects` is permitted only for routine drills; final recovery acceptance must use
the default full verification.
