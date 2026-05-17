---
concern_area: Pairing & Network Exposure
isvs_chapter: V4 — Communication
edition: OWASP ISVS 1.0
---

# Pairing & Network Exposure

This concern-area covers the device's network-facing attack surface —
the services it exposes, and the pairing and bonding flows by which new
peers are admitted. It maps to the communication chapter of the OWASP
ISVS, alongside transport security.

The recurring weakness is exposing more than the product needs, and
admitting peers too readily. A device listens on debug, diagnostic, or
administrative ports that were useful in development and were never
closed for production. Network services run without authentication, so
reaching the device is the same as controlling it. Pairing accepts any
peer without a confirmation step, uses a fixed or guessable PIN, or
leaves a pairing window open indefinitely, so an attacker in range
bonds with the device and inherits a trusted relationship. Once paired,
a peer is trusted forever, with no way to review or revoke bonds.

Sound practice minimises the exposed surface: only the services the
product requires are reachable, debug and administrative interfaces are
disabled in production, and every network-facing service authenticates
its caller. Pairing requires an explicit, human-mediated confirmation —
a button press, a code shown on the device — rather than silent
acceptance, uses a per-device or sufficiently random secret, and is
time-boxed so the window closes promptly. Bonded peers are enumerable
and revocable, so a lost or compromised peer can be removed without
re-provisioning the device. The default state is closed: a freshly
booted device admits nothing until it is deliberately paired.
