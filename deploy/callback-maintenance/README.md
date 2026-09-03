# C11 private maintenance boundary

This base is inert: all four single-tenant workloads have zero replicas and an
invalid digest-pinned image. An approved overlay must replace the Tenant ID,
image digest, database secrets, evidence secrets, and documentation-address
object-store/KMS endpoints before enabling exactly the required workloads.

The reconciler, expiry worker, retention deleter, and independent retention
verifier use distinct service accounts and database principals. They poll the
database directly; they have no public listener, message-broker access, target
or model access, metadata-service access, or general Internet egress. The
deleter and verifier must use distinct object-store credentials. Each enabled
Tenant is rendered as a separate workload instance and credential boundary.
