---
concern_area: Communication Transport & Cryptography
isvs_chapter: V4 — Communication
edition: OWASP ISVS 1.0
---

# Communication Transport & Cryptography

This concern-area covers how a device protects data while it moves
between the device, its companion applications, and its cloud
services. It maps to the communication chapter of the OWASP ISVS and
spans transport encryption, mutual authentication, certificate
validation, and the cryptography that secures device communications.

The recurring weakness is communication that is encrypted weakly, or
not at all, or encrypted without confirming who is on the other end.
Telemetry and commands travel over plaintext protocols, so anyone on
the network path can read or alter them. A device uses TLS or DTLS but
disables or ignores certificate validation — a common shortcut to make
self-signed development certificates work — so an attacker who can
intercept traffic presents any certificate and the device accepts it.
Only the server is authenticated, leaving the device itself
unverified, so a cloned or rogue device is indistinguishable from a
genuine one. Outdated protocol versions and weak cipher suites remain
enabled, so the session can be downgraded. Long-lived symmetric keys
are shared across a whole product line, so recovering one key from one
device decrypts the fleet.

Sound practice encrypts every channel that carries device data or
control with a current protocol version and strong cipher suites, and
validates the peer's certificate or public key on every connection —
no exceptions for convenience. Where the product's trust model
requires it, both ends authenticate, so the cloud can be sure it is
talking to a genuine device and vice versa. Keys are per-device and
rotatable, session keys are ephemeral, and the device rejects
downgrade attempts to obsolete protocols or ciphers.
