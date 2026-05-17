---
concern_area: Software Platform Hardening
isvs_chapter: V3 — Software Platform
edition: OWASP ISVS 1.0
---

# Software Platform Hardening

This concern-area covers the configuration and runtime posture of the
operating system or RTOS the device runs on, once a trusted firmware
image is booting. It maps to the software-platform chapter of the OWASP
ISVS and spans OS and RTOS hardening, removal of unnecessary services,
on-device cryptography and key storage, memory protections, and process
isolation.

The recurring weakness is shipping a development configuration as the
production image. Debug shells, verbose logging, test accounts, and
diagnostic services are left enabled, each one an entry point. The
platform runs more services and listens on more interfaces than the
product needs, widening the attack surface for no functional benefit.
Cryptographic operations use keys held in ordinary application memory
or files rather than in protected storage, so a single memory-disclosure
bug exposes them. Memory protections that the hardware and OS could
provide — non-executable data regions, address-space layout
randomization, stack protection — are disabled or unavailable, so a
memory-corruption bug becomes reliable code execution. Processes run
with more privilege than they need and without isolation, so one
compromised component owns the device.

Sound practice ships a minimised production image: debug interfaces,
test accounts, and unused services are removed or disabled, and only
the interfaces the product requires are reachable. Cryptographic keys
live in a hardware-backed keystore, secure element, or trusted
execution environment, and are used through APIs that never expose the
raw key. Available memory-protection features are enabled. Each
component runs under the least privilege it needs and is isolated —
through separate accounts, namespaces, or sandboxes — so a compromise
is contained rather than total.
