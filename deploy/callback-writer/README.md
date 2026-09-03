# C11 private callback writer boundary

This base is intentionally inert: the private writer has zero replicas, a
non-routable digest placeholder, and no public Service. It must be installed in
a private namespace separately from `deploy/callback-ingress`.

An approved overlay must provide distinct edge-client and writer-server mTLS
identities, a database principal that is only a member of
`sccap_c11_ingress_writer`, mounted lookup/namespace key files, mounted evidence
credentials, literal private object-store/KMS endpoints, and the exact namespace
labels in these policies. The writer has no RabbitMQ, DNS resolver, target,
model, Kubernetes API, or general Internet egress. Never co-locate it with a
public listener or expose its Service through an Ingress or LoadBalancer.
