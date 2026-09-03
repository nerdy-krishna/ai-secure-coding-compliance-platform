# C11 callback ingress deployment boundary

This base is intentionally inert: every Deployment has zero replicas, every
Service is ClusterIP, and placeholder image/config values are non-routable. An
approved environment overlay must supply a digest-pinned image, callback zones,
literal private-writer IP, TLS Secrets, public load-balancer/source-preservation
configuration, and matching namespace/pod labels before increasing replicas.

The workloads have no database, RabbitMQ, object-store, KMS, model, Kubernetes
API, target, DNS-resolver, or general Internet egress. NetworkPolicy permits only
TCP/9443 mTLS to the separately deployed private receipt writer. There is no
plaintext local spool. Service-account tokens are disabled, filesystems are
read-only, Linux capabilities are dropped, and RuntimeDefault seccomp is used.

DNS, HTTPS, and SMTP are separate workloads and identities. Plain HTTP is not
deployed. SMTP accepts messages only after STARTTLS. A public-entry overlay must
keep ports 53 UDP/TCP, 443 TCP, and 25 TCP isolated and must preserve source IPs
for workload-local rate limiting. Do not co-locate these listeners with the API,
worker, database, RabbitMQ, or private writer.
